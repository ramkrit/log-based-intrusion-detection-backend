# Assumptions and Constraints

## Storage

- All alert data is stored in-memory. Alerts are lost when the container stops or restarts. This is acceptable for a local development and evaluation tool — no database or persistent volume is required for alert data.

## Deployment

- The service runs as a single Docker container with no external dependencies (no databases, message queues, or cloud services).
- The container expects a log directory mounted at `/logs`. Without this mount, the service exits with an error.
- The service listens on port 8080 inside the container.

## Log Formats

- The parser supports two standard formats:
  - **Common Log Format (CLF):** `host ident authuser [date] "method path protocol" status bytes`
  - **Combined Log Format:** CLF fields plus `"referer" "user-agent"`
- Log lines that do not match either format are stored with `format: "unknown"` and the raw line preserved. Unknown-format entries are still evaluated by detection rules where possible.

## Detection Rules

- **Brute-force login:** Triggers on more than 5 HTTP 401 responses from the same source IP within a 60-second sliding window.
- **Path traversal:** Triggers on request paths containing `../`, `..\\`, or URL-encoded equivalents. A safe-pattern allowlist can suppress known-benign matches.
- **SQL injection:** Triggers on request paths containing common SQL injection patterns (`' OR`, `UNION SELECT`, `; DROP`, etc.). A safe-pattern allowlist can suppress known-benign matches.
- **Port scan / rapid requests:** Triggers on more than 100 requests from the same source IP within a 10-second sliding window.
- Alert deduplication: the same (rule, source IP) pair will not generate more than one alert within a 60-second cooldown period.

## Performance

- The service processes log lines sequentially as they are appended. It is designed for moderate log volumes typical of local development and testing, not high-throughput production environments.
- Sliding window state is maintained per source IP using sorted arrays, pruned on each evaluation. Memory usage grows with the number of unique IPs generating events within active windows.

## Security

- The HTTP API has no authentication or authorization. It is intended for local use only and should not be exposed to untrusted networks.
