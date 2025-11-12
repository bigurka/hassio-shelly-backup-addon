import os
import asyncio
import datetime
import json
import ipaddress
from typing import List, Optional
from fastapi import FastAPI, UploadFile, File, Form
from fastapi.responses import FileResponse, JSONResponse
import aiohttp

BACKUP_DIR = os.getenv("BACKUP_DIR", "/data/shelly_backups")
os.makedirs(BACKUP_DIR, exist_ok=True)

app = FastAPI(title="Shelly Backup Add-on")

CANDIDATE_PATHS = [
    "/settings",
    "/status",
    "/rpc/Shelly.GetConfig",
    "/rpc/Shelly.GetStatus",
    "/shelly",
    "/",
]


async def try_get(session: aiohttp.ClientSession, url: str, timeout=5):
    try:
        async with session.get(url, timeout=timeout) as resp:
            text = await resp.text()
            ct = resp.headers.get("content-type", "")
            if "application/json" in ct:
                return await resp.json()
            try:
                return json.loads(text)
            except Exception:
                return None
    except Exception:
        return None


def detect_device_type(data: dict) -> str:
    if isinstance(data, dict):
        keys = set(data.keys())
        if "fw" in keys or "device" in keys or "model" in keys:
            if "rpc" in json.dumps(data) or "Shelly.getconfig" in json.dumps(data) or "rpc" in keys:
                return "gen2"
            if "wifi" in keys or "mqtt" in keys or "relays" in keys:
                return "gen1"
            return "unknown"
    return "unknown"


async def probe_device(ip: str, ports: List[int] = [80, 8080, 8081]):
    async with aiohttp.ClientSession() as s:
        for port in ports:
            for path in CANDIDATE_PATHS:
                url = f"http://{ip}:{port}{path}"
                data = await try_get(s, url)
                if data:
                    dev_type = detect_device_type(data)
                    return {"ip": ip, "port": port, "path": path, "data": data, "type": dev_type}
    return None


@app.get("/scan")
async def scan(subnet: Optional[str] = None):
    subnet = subnet or os.getenv("SUBNET", "192.168.188.0/24")
    ips = [str(ip) for ip in ipaddress.IPv4Network(subnet).hosts()]
    tasks = [probe_device(ip) for ip in ips]
    results = await asyncio.gather(*tasks)
    devices = [r for r in results if r]
    return {"count": len(devices), "devices": devices}


@app.post("/backup")
async def backup_ips(ips: List[str]):
    saved = []
    for ip in ips:
        r = await probe_device(ip)
        if r:
            fname = f"{r['ip']}__{datetime.datetime.utcnow().isoformat()}.json".replace(":", "-")
            path = os.path.join(BACKUP_DIR, fname)
            meta = {"ip": r['ip'], "port": r['port'], "probe_path": r['path'], "ts": datetime.datetime.utcnow().isoformat(), "type": r.get("type")}
            with open(path, "w") as f:
                json.dump({"meta": meta, "payload": r["data"]}, f, indent=2)
            saved.append({"ip": r['ip'], "file": fname})
    return {"backed_up": saved}


@app.post("/backup_all")
async def backup_all(subnet: Optional[str] = None):
    subnet = subnet or os.getenv("SUBNET", "192.168.188.0/24")
    ips = [str(ip) for ip in ipaddress.IPv4Network(subnet).hosts()]
    tasks = [probe_device(ip) for ip in ips]
    results = await asyncio.gather(*tasks)
    saved = []
    for r in results:
        if not r:
            continue
        fname = f"{r['ip']}__{datetime.datetime.utcnow().isoformat()}.json".replace(":", "-")
        path = os.path.join(BACKUP_DIR, fname)
        meta = {"ip": r['ip'], "port": r['port'], "probe_path": r['path'], "ts": datetime.datetime.utcnow().isoformat(), "type": r.get("type")}
        with open(path, "w") as f:
            json.dump({"meta": meta, "payload": r['data']}, f, indent=2)
        saved.append({"ip": r['ip'], "file": fname})
    return {"saved": saved}


async def post_json(target_ip: str, path: str, data: dict, timeout=8):
    url = f"http://{target_ip}{path}"
    try:
        async with aiohttp.ClientSession() as s:
            async with s.post(url, json=data, timeout=timeout) as resp:
                text = await resp.text()
                return {"status": resp.status, "text": text, "url": url}
    except Exception as e:
        return {"status": None, "error": str(e), "url": url}


def build_gen1_payloads(payload: dict):
    tasks = []
    p = payload if isinstance(payload, dict) else {}
    if 'wifi' in p:
        tasks.append(('/settings/wifi', {'ssid': p['wifi'].get('ssid'), 'key': p['wifi'].get('key')}))
    if 'mqtt' in p:
        tasks.append(('/settings/mqtt', p['mqtt']))
    if 'relays' in p:
        tasks.append(('/settings/relay', {'relays': p['relays']}))
    if 'name' in p:
        tasks.append(('/settings', {'name': p['name']}))
    return tasks


def build_gen2_payloads(payload: dict):
    tasks = []
    p = payload if isinstance(payload, dict) else {}
    if 'wifi' in p:
        tasks.append(('/rpc/Wifi.SetConfig', {'ssid': p['wifi'].get('ssid'), 'password': p['wifi'].get('key')}))
    if 'mqtt' in p:
        tasks.append(('/rpc/Mqtt.SetConfig', p['mqtt']))
    if 'name' in p:
        tasks.append(('/rpc/Device.SetName', {'name': p['name']}))
    return tasks


@app.post("/restore_specific")
async def restore_specific(file: UploadFile = File(...), target_ip: str = Form(...), device_type: str = Form(...)):
    content = await file.read()
    try:
        obj = json.loads(content)
    except Exception:
        return JSONResponse({"result": "error", "reason": "invalid json"}, status_code=400)
    payload = obj.get('payload')
    if not payload:
        return JSONResponse({"result": "error", "reason": "no payload in file"}, status_code=400)

    if device_type == 'gen1':
        seq = build_gen1_payloads(payload)
    else:
        seq = build_gen2_payloads(payload)

    results = []
    for path, data in seq:
        r = await post_json(target_ip, path, data)
        results.append(r)
    return {"attempts": results}


@app.get("/backups")
async def list_backups():
    files = []
    for f in os.listdir(BACKUP_DIR):
        if f.endswith('.json'):
            files.append(f)
    return {"files": sorted(files)}


@app.get("/download/{filename}")
async def download(filename: str):
    path = os.path.join(BACKUP_DIR, filename)
    if os.path.exists(path):
        return FileResponse(path, filename=filename)
    return JSONResponse({"error": "not_found"}, status_code=404)


@app.get("/ping")
async def ping():
    return {"status": "ok"}
