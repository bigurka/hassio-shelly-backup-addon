#!/usr/bin/env bash
export PYTHONUNBUFFERED=1
HOST='0.0.0.0'
PORT=${PORT:-8080}
uvicorn main:app --host $HOST --port $PORT --loop asyncio --workers 1
