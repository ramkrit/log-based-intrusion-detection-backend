# Log-Based Intrusion Detection Service

A Node.js backend service that monitors log files in real time, detects intrusion patterns, and surfaces alerts via an HTTP API and stdout logging. Runs entirely in Docker with zero external dependencies.

## Quick Start

### Build

```bash
docker build -t intrusion-detector .
```

### Run

```bash
docker run -p 8080:8080 -v "${PWD}/logs:/logs" intrusion-detector

```

This mounts your local `logs/` directory into the container at `/logs`. The service watches for new and modified files in that directory and processes log lines as they appear.

### Verify

```bash
curl http://localhost:8080/health
```

## API Endpoints

### GET /health

Returns service status and counters.

```bash
curl http://localhost:8080/health
```

```json
{
  "status": "healthy",
  "filesWatched": 1,
  "linesProcessed": 42,
  "alertsGenerated": 3
}
```

### GET /alerts

Returns all alerts. Supports optional query parameters:

| Parameter  | Description                              | Example                              |
|------------|------------------------------------------|--------------------------------------|
| `severity` | Filter by severity (low, medium, high, critical) | `?severity=high`            |
| `rule`     | Filter by rule name                      | `?rule=brute-force`                  |
| `since`    | Filter by timestamp (ISO 8601)           | `?since=2024-01-01T00:00:00Z`       |

```bash
# All alerts
curl http://localhost:8080/alerts

# Only high-severity alerts
curl "http://localhost:8080/alerts?severity=high"

# Only brute-force alerts
curl "http://localhost:8080/alerts?rule=brute-force"

# Alerts since a specific time
curl "http://localhost:8080/alerts?since=2024-01-01T00:00:00Z"

# Combined filters
curl "http://localhost:8080/alerts?severity=high&rule=sql-injection"
```

### GET /alerts/stats

Returns alert counts grouped by rule name and severity.

```bash
curl http://localhost:8080/alerts/stats
```

```json
{
  "byRule": { "brute-force": 2, "path-traversal": 1 },
  "bySeverity": { "high": 2, "medium": 1 }
}
```

## Triggering Detections

Create a `logs/` directory and write log lines to files inside it. The service watches for changes and processes new lines automatically.

```bash
mkdir -p logs
```

### Brute-Force Login Detection

Triggers when more than 5 HTTP 401 responses come from the same IP within 60 seconds.

```bash
cat >> logs/access.log << 'EOF'
192.168.1.100 - admin [10/Jan/2024:13:55:01 +0000] "POST /login HTTP/1.1" 401 0
192.168.1.100 - admin [10/Jan/2024:13:55:02 +0000] "POST /login HTTP/1.1" 401 0
192.168.1.100 - admin [10/Jan/2024:13:55:03 +0000] "POST /login HTTP/1.1" 401 0
192.168.1.100 - admin [10/Jan/2024:13:55:04 +0000] "POST /login HTTP/1.1" 401 0
192.168.1.100 - admin [10/Jan/2024:13:55:05 +0000] "POST /login HTTP/1.1" 401 0
192.168.1.100 - admin [10/Jan/2024:13:55:06 +0000] "POST /login HTTP/1.1" 401 0
EOF
```

### Path Traversal Detection

Triggers when a request path contains `../`, `..\\`, or URL-encoded equivalents.

```bash
cat >> logs/access.log << 'EOF'
10.0.0.50 - - [10/Jan/2024:14:00:01 +0000] "GET /static/../../../etc/passwd HTTP/1.1" 200 1024
10.0.0.51 - - [10/Jan/2024:14:00:02 +0000] "GET /files/..%2f..%2f..%2fetc/shadow HTTP/1.1" 200 512
EOF
```

### SQL Injection Detection

Triggers when a request path contains SQL injection patterns like `' OR 1=1`, `UNION SELECT`, or `; DROP`.

```bash
cat >> logs/access.log << 'EOF'
10.0.0.60 - - [10/Jan/2024:14:05:01 +0000] "GET /users?id=1'+OR+1=1-- HTTP/1.1" 200 4096
10.0.0.61 - - [10/Jan/2024:14:05:02 +0000] "GET /search?q=admin'+UNION+SELECT+*+FROM+users-- HTTP/1.1" 200 8192
10.0.0.62 - - [10/Jan/2024:14:05:03 +0000] "GET /api/data?id=1;+DROP+TABLE+users HTTP/1.1" 500 0
EOF
```

### Port Scan / Rapid Request Detection

Triggers when more than 100 requests from the same IP arrive within 10 seconds. To test, generate a burst of requests in a log file:

```bash
for i in $(seq 1 102); do
  echo "10.0.0.99 - - [10/Jan/2024:14:10:01 +0000] \"GET /page$i HTTP/1.1\" 200 512" >> logs/access.log
done
```

### Checking Results

After writing suspicious log lines, check for alerts:

```bash
# View all alerts
curl http://localhost:8080/alerts | jq .

# View alert statistics
curl http://localhost:8080/alerts/stats | jq .

# View container logs for [ALERT] lines
docker logs <container-id>
```

## Architecture

```
┌─────────────────────────────────────────────────┐
│  Docker Container                               │
│                                                 │
│  /logs (mount) ──► File Watcher                 │
│                       │                         │
│                       ▼                         │
│                   Log Parser                    │
│                       │                         │
│                       ▼                         │
│                  Rule Engine                    │
│                   │       │                     │
│                   ▼       ▼                     │
│            Alert Store   stdout ([ALERT] JSON)  │
│                   │                             │
│                   ▼                             │
│           Express HTTP :8080                    │
│           /alerts  /alerts/stats  /health       │
└─────────────────────────────────────────────────┘
```

### Components

- **File Watcher** — Monitors `/logs` using `fs.watch` with polling fallback for Docker volume mounts. Tracks byte offsets per file to avoid reprocessing. Buffers partial lines until a newline arrives.
- **Log Parser** — Parses raw lines into structured entries. Supports Common Log Format (CLF) and Combined Log Format. Unrecognized lines are preserved with `format: "unknown"`.
- **Rule Engine** — Evaluates each parsed entry against all registered detection rules. Manages sliding time windows and a 60-second cooldown to deduplicate alerts per (rule, IP) pair.
- **Alert Store** — In-memory array of alerts with filtering by severity, rule name, and timestamp. No persistence across restarts.
- **HTTP Server** — Express app exposing `/alerts`, `/alerts/stats`, and `/health` endpoints on port 8080.

### Design Reasoning

- **In-memory storage** keeps the service simple with zero external dependencies. Acceptable for a local tool where alerts don't need to survive restarts.
- **Sliding windows** (vs. fixed time buckets) prevent attack patterns from being split across bucket boundaries, reducing false negatives.
- **Safe-pattern allowlists** on path traversal and SQL injection rules reduce false positives from legitimate URLs that happen to contain matching substrings.
- **Fault isolation** — each rule evaluation is wrapped in try-catch so a failing rule doesn't block others.

## Development

### Run Tests

```bash
npm test
```

### Run Locally (without Docker)

```bash
mkdir -p /logs
npm start
```

The service expects the `/logs` directory to exist. For local development, create it or adjust the path in `src/index.js`.
