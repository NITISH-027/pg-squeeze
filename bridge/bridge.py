import os
import re
import time
import threading
from typing import Dict, List, Optional
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="PG-SQUEEZE API Bridge")

# Enable CORS for Next.js dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for local dev
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

LOG_PATH = "/tmp/pg-squeeze.log"

# Global In-Memory State
state_lock = threading.Lock()
collector_available = False
last_event_time: Optional[float] = None

# Track connection events
active_connections: Dict[str, dict] = {}
expired_connections: List[dict] = []
process_summaries: Dict[int, dict] = {}

class HealthResponse(BaseModel):
    api_running: bool
    collector_available: bool
    last_event_timestamp: Optional[float]

@app.get("/api/health", response_model=HealthResponse)
def get_health():
    with state_lock:
        return HealthResponse(
            api_running=True,
            collector_available=collector_available,
            last_event_timestamp=last_event_time
        )

@app.get("/api/report")
def get_report():
    with state_lock:
        if not collector_available and not expired_connections and not active_connections:
            # If no real data is available, return an empty structured report indicating we are waiting/empty
            return {
                "mode": "sample" if not os.path.exists(LOG_PATH) else "live",
                "connected": collector_available,
                "summary": {
                    "total_connections": 0,
                    "short_lived": 0,
                    "idle_pattern": 0,
                    "chatter": 0,
                    "heavy": 0,
                    "normal": 0,
                    "short_lived_ratio": 0.0,
                    "processes_observed": 0,
                    "dominant_pattern": "NONE"
                },
                "processes": [],
                "patterns": {
                    "SHORT_LIVED": 0,
                    "IDLE_PATTERN": 0,
                    "CHATTER": 0,
                    "HEAVY": 0,
                    "NORMAL": 0
                },
                "events": [],
                "aggregate": {
                    "finding": "NO LIVE DATA",
                    "recommendation": "Start the PG-SQUEEZE collector to begin observation."
                },
                "hotspot": {
                    "top_contributor": "None",
                    "pid": 0,
                    "connections": 0,
                    "short_lived": 0,
                    "short_lived_ratio": 0.0,
                    "avg_lifetime": 0.0,
                    "reuse_score": 0.0,
                    "churn_contribution": 0.0,
                    "risk": "LOW",
                    "recommendation": "No recommendations available."
                }
            }

        # Calculate live report values from in-memory state
        total_connections = len(expired_connections) + len(active_connections)
        
        # Count patterns from expired and active connections
        patterns = {"SHORT_LIVED": 0, "IDLE_PATTERN": 0, "CHATTER": 0, "HEAVY": 0, "NORMAL": 0}
        for conn in expired_connections:
            cls = conn.get("classification", "NORMAL")
            patterns[cls] = patterns.get(cls, 0) + 1
        for conn in active_connections.values():
            cls = conn.get("classification", "NORMAL")
            patterns[cls] = patterns.get(cls, 0) + 1

        short_lived_ratio = (patterns["SHORT_LIVED"] / total_connections * 100.0) if total_connections > 0 else 0.0
        
        # Determine dominant pattern
        dominant_pattern = "NORMAL"
        max_count = -1
        for p, count in patterns.items():
            if count > max_count:
                max_count = count
                dominant_pattern = p
        if max_count <= 0:
            dominant_pattern = "NONE"

        # Format processes list
        processes_list = []
        for pid, p in process_summaries.items():
            short_ratio = (p["short_lived"] / p["connections"] * 100.0) if p["connections"] > 0 else 0.0
            avg_lifetime = (p["total_duration"] / p["connections"]) if p["connections"] > 0 else 0.0
            
            # Calculate reuse score (matching collector.c logic)
            # if short_ratio >= 75: 0; >= 50: 25; >= 25: 50; > 0: 75; else 100
            reuse_score = 100.0
            if p["connections"] > 0:
                if short_ratio >= 75.0:
                    reuse_score = 0.0
                elif short_ratio >= 50.0:
                    reuse_score = 25.0
                elif short_ratio >= 25.0:
                    reuse_score = 50.0
                elif short_ratio > 0.0:
                    reuse_score = 75.0

            processes_list.append({
                "process_name": p["name"],
                "pid": pid,
                "connections": p["connections"],
                "packets": p["packets"],
                "bytes": p["bytes"],
                "avg_lifetime": avg_lifetime,
                "short_lived": p["short_lived"],
                "short_lived_ratio": short_ratio,
                "reuse_score": reuse_score
            })

        # Sort processes by connection count descending
        processes_list.sort(key=lambda x: x["connections"], reverse=True)

        # Aggregate findings/recommendations
        findings = []
        recommendations = []
        if total_connections >= 5 and short_lived_ratio >= 50.0:
            findings.append(f"CONNECTION CHURN ({short_lived_ratio:.1f}% short-lived)")
            recommendations.append("Investigate PostgreSQL connection pooling and connection reuse.")
        elif total_connections >= 5 and short_lived_ratio >= 25.0:
            findings.append(f"POSSIBLE CONNECTION CHURN ({short_lived_ratio:.1f}% short-lived)")
            recommendations.append("Review connection lifecycle and consider pooling/reuse.")

        idle_ratio = (patterns["IDLE_PATTERN"] / total_connections * 100.0) if total_connections > 0 else 0.0
        if total_connections >= 3 and idle_ratio >= 50.0:
            findings.append(f"IDLE CONNECTION PATTERN ({idle_ratio:.1f}% affected)")
            recommendations.append("Review pool idle timeout and connection lifecycle settings.")

        chatter_ratio = (patterns["CHATTER"] / total_connections * 100.0) if total_connections > 0 else 0.0
        if chatter_ratio >= 50.0:
            findings.append(f"NETWORK CHATTER ({chatter_ratio:.1f}% affected)")
            recommendations.append("Investigate frequent small request/response exchanges and batching opportunities.")

        heavy_ratio = (patterns["HEAVY"] / total_connections * 100.0) if total_connections > 0 else 0.0
        if heavy_ratio >= 50.0:
            findings.append(f"HEAVY DATA TRANSFER ({heavy_ratio:.1f}% affected)")
            recommendations.append("Investigate large result sets, payload size, and query/result pagination.")

        # Hotspot (Phase 7) - Grouped by process name to avoid choosing one of many identical processes
        top_contrib = "None"
        top_conn = 0
        top_sl = 0
        top_sl_ratio = 0.0
        top_avg_lifetime = 0.0
        top_reuse_score = 100.0
        top_churn_contrib = 0.0
        top_risk = "LOW"
        top_recommendation = "No recommendations available."
        top_pids = []

        total_sl_connections = sum(p["short_lived"] for p in process_summaries.values())
        
        # Aggregate by process name
        name_groups = {}
        for pid, p in process_summaries.items():
            name = p["name"]
            if name not in name_groups:
                name_groups[name] = {
                    "name": name,
                    "connections": 0,
                    "packets": 0,
                    "bytes": 0,
                    "short_lived": 0,
                    "total_duration": 0.0,
                    "pids": []
                }
            g = name_groups[name]
            g["connections"] += p["connections"]
            g["packets"] += p["packets"]
            g["bytes"] += p["bytes"]
            g["short_lived"] += p["short_lived"]
            g["total_duration"] += p["total_duration"]
            g["pids"].append(pid)

        max_sl = -1
        top_group = None
        for name, g in name_groups.items():
            if g["short_lived"] > max_sl:
                max_sl = g["short_lived"]
                top_group = g

        if top_group and max_sl > 0:
            top_contrib = top_group["name"]
            top_conn = top_group["connections"]
            top_sl = top_group["short_lived"]
            top_sl_ratio = (top_sl / top_conn * 100.0) if top_conn > 0 else 0.0
            top_avg_lifetime = (top_group["total_duration"] / top_conn) if top_conn > 0 else 0.0
            top_pids = top_group["pids"]
            
            top_reuse_score = 100.0
            if top_sl_ratio >= 75.0:
                top_reuse_score = 0.0
            elif top_sl_ratio >= 50.0:
                top_reuse_score = 25.0
            elif top_sl_ratio >= 25.0:
                top_reuse_score = 50.0
            elif top_sl_ratio > 0.0:
                top_reuse_score = 75.0

            top_churn_contrib = (top_sl / total_sl_connections * 100.0) if total_sl_connections > 0 else 0.0
            
            if top_churn_contrib >= 75.0 and top_sl_ratio >= 75.0:
                top_risk = "HIGH"
            elif top_churn_contrib >= 50.0 or top_sl_ratio >= 50.0:
                top_risk = "MEDIUM"
            else:
                top_risk = "LOW"
            top_recommendation = f"Prioritize connection pooling/reuse investigation for process {top_contrib}."

        # Format events list (combining active and expired events for stream)
        events_stream = []
        for key, conn in active_connections.items():
            events_stream.append({
                "client": conn["client"],
                "server": conn["server"],
                "duration": conn.get("duration", 0.0),
                "packets": conn.get("packets", 0),
                "bytes": conn.get("bytes", 0),
                "process": conn.get("process", "unresolved"),
                "pid": conn.get("pid", 0),
                "classification": conn.get("classification", "NORMAL"),
                "status": "active"
            })
        for conn in expired_connections[-50:]:  # Last 50 expired connections
            events_stream.append({
                "client": conn["client"],
                "server": conn["server"],
                "duration": conn.get("duration", 0.0),
                "packets": conn.get("packets", 0),
                "bytes": conn.get("bytes", 0),
                "process": conn.get("process", "unresolved"),
                "pid": conn.get("pid", 0),
                "classification": conn.get("classification", "NORMAL"),
                "status": "expired"
            })
        # Sort by duration or just show them
        events_stream.reverse()

        return {
            "mode": "live",
            "connected": collector_available,
            "summary": {
                "total_connections": total_connections,
                "short_lived": patterns["SHORT_LIVED"],
                "idle_pattern": patterns["IDLE_PATTERN"],
                "chatter": patterns["CHATTER"],
                "heavy": patterns["HEAVY"],
                "normal": patterns["NORMAL"],
                "short_lived_ratio": short_lived_ratio,
                "processes_observed": len(process_summaries),
                "dominant_pattern": dominant_pattern
            },
            "timestamp": time.time(),
            "last_event_timestamp": last_event_time,
            "processes": processes_list,
            "patterns": patterns,
            "events": events_stream,
            "aggregate": {
                "finding": " | ".join(findings) if findings else "NO CLEAR AGGREGATE ISSUE DETECTED",
                "recommendation": " ".join(recommendations) if recommendations else "Continue monitoring aggregate connection behavior."
            },
            "hotspot": {
                "top_contributor": top_contrib,
                "pid": top_pids[0] if top_pids else 0,
                "connections": top_conn,
                "short_lived": top_sl,
                "short_lived_ratio": top_sl_ratio,
                "avg_lifetime": top_avg_lifetime,
                "reuse_score": top_reuse_score,
                "churn_contribution": top_churn_contrib,
                "risk": top_risk,
                "recommendation": top_recommendation
            }
        }

# Background Log Tailer
def log_tailer():
    global collector_available, last_event_time
    last_inode = None
    file_handle = None

    while True:
        try:
            if not os.path.exists(LOG_PATH):
                with state_lock:
                    collector_available = False
                time.sleep(1)
                continue

            # Check if file was re-created / rotated
            stat = os.stat(LOG_PATH)
            current_inode = stat.st_ino

            if current_inode != last_inode:
                if file_handle:
                    file_handle.close()
                file_handle = open(LOG_PATH, "r")
                last_inode = current_inode
                # Clear state on log rotation/restart
                with state_lock:
                    active_connections.clear()
                    expired_connections.clear()
                    process_summaries.clear()
                    collector_available = True

            # Read new lines
            lines = file_handle.readlines()
            if not lines:
                # Check if collector process is actually running/alive
                # If no new lines for > 5 seconds, let's keep collector_available=True but we can verify process list
                time.sleep(0.5)
                continue

            with state_lock:
                collector_available = True
                last_event_time = time.time()

                expired_context = None

                for line in lines:
                    line = line.strip()
                    if not line:
                        continue

                    # 1. Parse Connection Event
                    if "PG-SQUEEZE CONNECTION EVENT:" in line:
                        # Format: PG-SQUEEZE CONNECTION EVENT: 127.0.0.1:39234 <-> 127.0.0.1:5432 direction=CLIENT->SERVER packets=1 bytes=60 duration=0.000s process=python3 pid=8492
                        parts = line.split("PG-SQUEEZE CONNECTION EVENT:")[-1].strip().split()
                        if len(parts) >= 3:
                            key = f"{parts[0]} {parts[1]} {parts[2]}"  # e.g., "127.0.0.1:39234 <-> 127.0.0.1:5432"
                            
                            # Parse key/value pairs from subsequent parts
                            kv = {}
                            for part in parts[3:]:
                                if "=" in part:
                                    k, v = part.split("=", 1)
                                    kv[k] = v

                            packets = int(kv.get("packets", 0))
                            bytes_count = int(kv.get("bytes", 0))
                            duration = float(kv.get("duration", "0.0").replace("s", ""))
                            pid = int(kv.get("pid", 0))
                            process = kv.get("process", "unresolved")

                            # Simple classification logic matching collector.c
                            classification = "NORMAL"
                            if duration < 1.0:
                                classification = "SHORT_LIVED"
                            elif packets >= 50:
                                classification = "CHATTER"
                            elif bytes_count >= 1024 * 1024:
                                classification = "HEAVY"

                            active_connections[key] = {
                                "client": parts[0],
                                "server": parts[2],
                                "packets": packets,
                                "bytes": bytes_count,
                                "duration": duration,
                                "pid": pid,
                                "process": process,
                                "classification": classification
                            }

                    # 2. Parse Connection Expired Start
                    elif "PG-SQUEEZE CONNECTION EXPIRED:" in line:
                        # Format: PG-SQUEEZE CONNECTION EXPIRED: 127.0.0.1:39234 <-> 127.0.0.1:5432 duration=0.850s
                        parts = line.split("PG-SQUEEZE CONNECTION EXPIRED:")[-1].strip().split()
                        if len(parts) >= 3:
                            key = f"{parts[0]} {parts[1]} {parts[2]}"
                            duration = 0.0
                            for part in parts[3:]:
                                if "duration=" in part:
                                    duration = float(part.split("=")[1].replace("s", ""))

                            # Keep context to parse following lines of this expired event
                            expired_context = {
                                "key": key,
                                "client": parts[0],
                                "server": parts[2],
                                "duration": duration,
                                "classification": "NORMAL",
                                "pid": 0,
                                "process": "unresolved",
                                "packets": 0,
                                "bytes": 0
                            }

                    # 3. Parse Expired Details
                    elif expired_context and line.startswith("TOTAL:"):
                        # Format: TOTAL: packets=4 bytes=200 process=python3 pid=12345
                        kv = {}
                        for part in line.split("TOTAL:")[-1].strip().split():
                            if "=" in part:
                                k, v = part.split("=", 1)
                                kv[k] = v
                        
                        expired_context["packets"] = int(kv.get("packets", 0))
                        expired_context["bytes"] = int(kv.get("bytes", 0))
                        expired_context["pid"] = int(kv.get("pid", 0))
                        expired_context["process"] = kv.get("process", "unresolved")

                    elif expired_context and "Classification:" in line:
                        # Format: Classification: SHORT_LIVED
                        classification = line.split("Classification:")[-1].strip()
                        expired_context["classification"] = classification

                    elif expired_context and "Events:" in line:
                        # Last line of block
                        # Save expired connection and update process summary
                        key = expired_context["key"]
                        pid = expired_context["pid"]
                        process = expired_context["process"]

                        # Remove from active connections if present
                        active_connections.pop(key, None)

                        # Save to expired
                        expired_connections.append(expired_context)

                        # Update process summaries
                        if pid > 0:
                            if pid not in process_summaries:
                                process_summaries[pid] = {
                                    "name": process,
                                    "connections": 0,
                                    "packets": 0,
                                    "bytes": 0,
                                    "short_lived": 0,
                                    "total_duration": 0.0
                                }
                            p = process_summaries[pid]
                            p["connections"] += 1
                            p["packets"] += expired_context["packets"]
                            p["bytes"] += expired_context["bytes"]
                            p["total_duration"] += expired_context["duration"]
                            if expired_context["classification"] == "SHORT_LIVED":
                                p["short_lived"] += 1

                        expired_context = None

        except Exception as e:
            time.sleep(1)

# Start background parser thread
threading.Thread(target=log_tailer, daemon=True).start()
