/**
 * Structured stdout logger for the intrusion detection service.
 * Alert lines are prefixed with [ALERT], operational logs with [INFO], [WARN], [ERROR].
 * All output goes through process.stdout.write() for testability.
 */

/**
 * Logs an alert to stdout as [ALERT] followed by JSON.
 * @param {{ ruleName: string, severity: string, sourceIp: string, detectedAt: string, message: string }} alert
 */
export function logAlert(alert) {
  const json = JSON.stringify({
    ruleName: alert.ruleName,
    severity: alert.severity,
    sourceIp: alert.sourceIp,
    detectedAt: alert.detectedAt,
    message: alert.message,
  });
  process.stdout.write(`[ALERT] ${json}\n`);
}

/**
 * Logs an informational message to stdout.
 * @param {string} message
 */
export function logInfo(message) {
  const json = JSON.stringify({
    level: 'info',
    message,
    timestamp: new Date().toISOString(),
  });
  process.stdout.write(`[INFO] ${json}\n`);
}

/**
 * Logs a warning message to stdout.
 * @param {string} message
 */
export function logWarn(message) {
  const json = JSON.stringify({
    level: 'warn',
    message,
    timestamp: new Date().toISOString(),
  });
  process.stdout.write(`[WARN] ${json}\n`);
}

/**
 * Logs an error message to stdout.
 * @param {string} message
 */
export function logError(message) {
  const json = JSON.stringify({
    level: 'error',
    message,
    timestamp: new Date().toISOString(),
  });
  process.stdout.write(`[ERROR] ${json}\n`);
}
