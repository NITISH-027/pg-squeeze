# PG-SQUEEZE

An eBPF-powered PostgreSQL network traffic observer, connection behavior analyzer, and investigation dashboard.

---

## 1. The Problem

In high-throughput database environments, bad connection patterns—such as severe connection churn (opening and closing a new TCP socket for every individual database query)—introduce significant latency, CPU overhead on the database server, and risk of ephemeral port exhaustion. 

### Why Existing PostgreSQL Metrics Aren't Enough
Standard database telemetry (such as `pg_stat_activity` or query logs) is insufficient for diagnosing connection overhead because:
1. **No OS-level Client Attribution**: `pg_stat_activity` knows the client IP/port and backend PID, but it has no visibility into the client process's binary name or local PID running on application servers.
2. **Ephemeral/Short-Lived Connections**: ephemeral connections that connect, query, and disconnect within a few milliseconds are often missed completely by periodic sampling polling tools.
3. **No Network Context**: Traditional tools lack layer-3/layer-4 metrics like total packets, bytes, idle gaps, and duration from the OS network stack's perspective.

---

## 2. Architecture & Design

PG-SQUEEZE uses a modular, privilege-separated design:

```
                  ┌──────────────────────────────────────────────┐
                  │                 Linux Kernel                 │
                  │  ┌──────────────┐         ┌───────────────┐  │
                  │  │   tc ingress │         │   tc egress   │  │
                  │  └──────┬───────┘         └───────┬───────┘  │
                  │         │ eBPF net_observer       │          │
                  └─────────┼─────────────────────────┼──────────┘
                            │ (Events Map / Ringbuf)  │
                            ▼                         ▼
                  ┌──────────────────────────────────────────────┐
                  │          Privileged User-Space (sudo)        │
                  │  ┌────────────────────────────────────────┐  │
                  │  │ collector.c                            │  │
                  │  │  - socket/proc correlation via /proc   │  │
                  │  │  - connection classification           │  │
                  │  └───────────────┬────────────────────────┘  │
                  └──────────────────┼───────────────────────────┘
                                     │ (Line-buffered output redirection)
                                     ▼
                        /tmp/pg-squeeze.log
                                     │
                                     ▼
                  ┌──────────────────────────────────────────────┐
                  │         Non-Privileged User-Space            │
                  │  ┌────────────────────────────────────────┐  │
                  │  │ FastAPI Bridge (bridge.py)             │  │
                  │  └───────────────────┬────────────────────┘  │
                  │                      │ localhost:8000/api/report
                  │                      ▼
                  │  ┌────────────────────────────────────────┐  │
                  │  │ Next.js Dashboard (dashboard/)         │  │
                  │  └────────────────────────────────────────┘  │
                  └──────────────────────────────────────────────┘
```

1. **eBPF Filter (`net.bpf.c`)**: Attached to network interface Traffic Control (`tc`) filters. It intercepts PostgreSQL packets on port `5432` and pushes headers to a user-space ring buffer.
2. **State & Attribution Collector (`collector.c`)**: Runs with root privileges. It reads the ring buffer, maps sockets to their local OS processes (comm and PID) using `/proc/net/tcp` and `/proc/<pid>/fd`, and classifies connections.
3. **API Bridge (`bridge.py`)**: Runs as a standard, non-root user. It tails the line-buffered log `/tmp/pg-squeeze.log` in real time, maintains an in-memory aggregation of process groups (aggregating metrics across multiple PIDs of the same process name), and serves REST endpoints.
4. **Observability Dashboard (`dashboard/`)**: A dark-themed, minimal React dashboard built with Next.js and Tailwind CSS. It visualizes live patterns, process forensics, hotspot tracking, and investigation guidance.

---

## 3. Getting Started

### Prerequisites
* Linux kernel with eBPF support (`clang`, `llvm`, `libbpf-dev`, `iproute2` installed).
* Python 3.8+ (for API bridge).
* Node.js & npm (for dashboard).

### Compilation
Compile the BPF object and user-space loaders:
```bash
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c net.bpf.c -o net.bpf.o
gcc -Wall -o tc_loader tc_loader.c -lbpf
gcc -Wall -o collector collector.c -lbpf
```

### Running the System

1. **Terminal 1 (Attach TC filter)**:
   ```bash
   sudo ./tc_loader
   ```
2. **Terminal 2 (Start Collector)**:
   ```bash
   sudo stdbuf -oL ./collector > /tmp/pg-squeeze.log 2>&1
   ```
3. **Terminal 3 (Start Mock server for local testing)**:
   ```bash
   python3 tcp_test_server.py
   ```
4. **Terminal 4 (Start Python API Bridge)**:
   ```bash
   ./run_bridge.sh
   ```
5. **Terminal 5 (Start Next.js Dashboard)**:
   ```bash
   ./run_dashboard.sh
   ```

---

## 4. Workload Experimentation

We provide a built-in workload generator (`test_workloads.py`) to demonstrate contrasting connection patterns in PG-SQUEEZE.

### Workload A: Persistent Connection (Connection Reuse)
Simulates a healthy application configuration using a persistent database connection:
```bash
python3 test_workloads.py A
```
* **Behavior**: Opens a single TCP socket, sends 5 queries sequentially spaced by 2 seconds, and closes the connection.
* **PG-SQUEEZE Classification**: `NORMAL` (long duration, multiple packets over a single socket).

### Workload B: Connection Churn (Short-lived Connections)
Simulates a misconfigured application causing connection churn:
```bash
python3 test_workloads.py B
```
* **Behavior**: Connects, sends a query, disconnects immediately. Repeats 10 times.
* **PG-SQUEEZE Classification**: `SHORT_LIVED` (10 distinct connections, duration < 1.0s).

---

## 5. Investigation Guidance Matrix

PG-SQUEEZE uses a transparent three-step analytical matrix:

| Observation | Interpretation | Recommendation |
| :--- | :--- | :--- |
| **Connection Churn** (>25% short-lived connections) | The observed pattern is consistent with repeated connection establishment. | Investigate PostgreSQL connection pooling and connection reuse. |
| **Idle Pattern** (>50% idle-affected connections) | Long idle gaps observed between query packets within connections. | Review pool idle timeout and connection lifecycle settings. |
| **Network Chatter** (>50% chatter-affected connections) | High packet count with small payload exchanges. | Investigate high-frequency database interactions for batching opportunities. |
| **Heavy Data Transfer** (>50% heavy connections) | Massive byte payloads transferred over TCP. | Investigate large result sets, payload size, and query pagination. |

---

## 6. Limitations & Scope

* **IPv4 Only**: The current BPF filter monitors IPv4 traffic on port `5432`.
* **Attribution Scope**: Socket-to-process PID mapping relies on `/proc` scanning. Highly ephemeral processes running for less than a few milliseconds may exit before correlation completes, displaying as `unresolved`.
