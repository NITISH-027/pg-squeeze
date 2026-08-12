# PG-SQUEEZE API Bridge

A lightweight local API bridge that tails the PG-SQUEEZE collector log at `/tmp/pg-squeeze.log` and exposes its metrics as structured JSON.

## Setup & Running

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the bridge**:
   ```bash
   uvicorn bridge:app --host 127.0.0.1 --port 8000
   ```

## Endpoints

* `GET /api/health`: Health status of the bridge and the collector.
* `GET /api/report`: Live parsed metrics of PostgreSQL connections, process forensics, hotspot intelligence, and optimization findings.
