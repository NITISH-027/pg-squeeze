#!/bin/bash
cd "$(dirname "$0")/bridge"
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi
source .venv/bin/activate
echo "Installing dependencies..."
pip install -r requirements.txt
echo "Starting PG-SQUEEZE API Bridge..."
uvicorn bridge:app --host 127.0.0.1 --port 8000
