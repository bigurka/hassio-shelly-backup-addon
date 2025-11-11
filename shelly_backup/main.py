\
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
async def probe_device(ip: str, ports: List[int] = [80, 8080, 8081]):
    async with aiohttp.ClientSession() as s:
        for port in ports:
            for path in CANDIDATE_PATHS:
                url = f"http://{ip}:{port}{path}"
                data = await try_get(s, url)
                if data:
                    # try to detect generation/type
                    dev_type = detect_device_type(data)
                    return {"ip": ip, "port": port, "path": path, "data": data, "type": dev_type}
    return None
def detect_device_type(data: dict) -> str:
    # heuristic detection: Gen2 often has 'fw'/'id' style and rpc endpoints; Gen1 older has different fields
    if isinstance(data, dict):
        keys = set(data.keys())
        if "fw" in keys or "device" in keys or "model" in keys:
            # could be gen2 or gen1; refine
            if "rpc" in json.dumps(data) or "Shelly.getconfig" in json.dumps(data) or "rpc" in keys:
                return "gen2"
            # check some gen1 characteristics
            if "wifi" in keys or "mqtt" in keys or "relays" in keys:
                return "gen1"
            return "unknown"
    return "unknown"
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
            json.dump({"meta": meta, "payload": r["data"]}, f, indent=2)
        saved.append({"ip": r['ip'], "file": fname})
    return {"saved": saved}
@app.post("/restore")
async def restore(file: UploadFile = File(...), target_ip: str = Form(...)):
    content = await file.read()
    try:
        obj = json.loads(content)
    except Exception:
        return JSONResponse({"result": "error", "reason": "invalid json"}, status_code=400)
    payload = obj.get("payload")
    if not payload:
        return JSONResponse({"result": "error", "reason": "no payload in file"}, status_code=400)
    async with aiohttp.ClientSession() as s:
        for path in ["/rpc/Shelly.SetConfig", "/settings", "/rpc/Shelly.SetSettings"]:
            url = f"http://{target_ip}{path}"
            try:
                async with s.post(url, json=payload, timeout=10) as resp:
                    text = await resp.text()
                    if resp.status in (200, 201):
                        return {"result": "ok", "url": url, "status": resp.status, "text": text}
            except Exception:
                continue
    return {"result": "failed", "reason": "no writable endpoint found"}
# --- advanced restore helpers ---
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
    # gen1 devices often store settings in 'wifi', 'mqtt', 'relays', 'name'
    tasks = []
    p = payload if isinstance(payload, dict) else {}
    if 'wifi' in p:
        tasks.append(('/settings/wifi', {'ssid': p['wifi'].get('ssid'), 'key': p['wifi'].get('key')}))
    if 'mqtt' in p:
        tasks.append(('/settings/mqtt', p['mqtt']))
    if 'relays' in p:
        # relays config may be complex; post as 'relays' if accepted
        tasks.append(('/settings/relay', {'relays': p['relays']}))
    if 'name' in p:
        tasks.append(('/settings', {'name': p['name']}))
    return tasks
def build_gen2_payloads(payload: dict):
    # gen2 uses RPC-style config; we try to post subsets
    tasks = []
    p = payload if isinstance(payload, dict) else {}
    # wifi
    wifi = {}
    if 'wifi' in p:
        wifi = {'ssid': p['wifi'].get('ssid'), 'password': p['wifi'].get('key')}
        tasks.append(('/rpc/Wifi.SetConfig', {'ssid': wifi['ssid'], 'password': wifi['password']}))
    # mqtt
    if 'mqtt' in p:
        tasks.append(('/rpc/Mqtt.SetConfig', p['mqtt']))
    # common name
    if 'name' in p:
        tasks.append(('/rpc/Device.SetName', {'name': p['name']}))
    return tasks
@app.post("/restore_specific")
async def restore_specific(file: UploadFile = File(...), target_ip: str = Form(...), device_type: str = Form(...)):
    \"\"\"Restore using targeted mapping for gen1 or gen2 devices.\n    device_type: 'gen1' or 'gen2'\n    \"\"\"\n    content = await file.read()\n    try:\n        obj = json.loads(content)\n    except Exception:\n        return JSONResponse({\"result\": \"error\", \"reason\": \"invalid json\"}, status_code=400)\n    payload = obj.get('payload')\n    if not payload:\n        return JSONResponse({\"result\": \"error\", \"reason\": \"no payload in file\"}, status_code=400)\n    # build sequences of small writes to avoid overwriting system fields\n    if device_type == 'gen1':\n        seq = build_gen1_payloads(payload)\n    else:\n        seq = build_gen2_payloads(payload)\n    results = []\n    for path, data in seq:\n        r = await post_json(target_ip, path, data)\n        results.append(r)\n    return {\"attempts\": results}\n@app.get(\"/backups\")\nasync def list_backups():\n    files = []\n    for f in os.listdir(BACKUP_DIR):\n        if f.endswith('.json'):\n            files.append(f)\n    return {\"files\": sorted(files)}\n@app.get(\"/download/{filename}\")\nasync def download(filename: str):\n    path = os.path.join(BACKUP_DIR, filename)\n    if os.path.exists(path):\n        return FileResponse(path, filename=filename)\n    return JSONResponse({\"error\": \"not_found\"}, status_code=404)\n@app.get(\"/ping\")\nasync def ping():\n    return {\"status\": \"ok\"}\n