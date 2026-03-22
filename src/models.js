import { v4 as uuidv4 } from 'uuid';

/**
 * @typedef {'clf' | 'combined' | 'unknown'} LogFormat
 */

/**
 * @typedef {Object} LogEntry
 * @property {string | null} timestamp - ISO 8601 or original format string
 * @property {string | null} sourceIp - Client IP address
 * @property {string | null} method - HTTP method (GET, POST, etc.)
 * @property {string | null} path - Request path including query string
 * @property {number | null} statusCode - HTTP response status code
 * @property {number | null} size - Response size in bytes
 * @property {string | null} userAgent - User-Agent header (Combined format only)
 * @property {string | null} referer - Referer header (Combined format only)
 * @property {LogFormat} format - Detected format
 * @property {string} raw - Original unparsed line, always preserved
 */

/**
 * Creates a LogEntry object.
 * @param {Partial<LogEntry> & { raw: string }} fields
 * @returns {LogEntry}
 */
export function createLogEntry(fields) {
  return {
    timestamp: fields.timestamp ?? null,
    sourceIp: fields.sourceIp ?? null,
    method: fields.method ?? null,
    path: fields.path ?? null,
    statusCode: fields.statusCode ?? null,
    size: fields.size ?? null,
    userAgent: fields.userAgent ?? null,
    referer: fields.referer ?? null,
    format: fields.format ?? 'unknown',
    raw: fields.raw,
  };
}


/**
 * @typedef {'low' | 'medium' | 'high' | 'critical'} Severity
 */

/**
 * @typedef {Object} Alert
 * @property {string} id - UUID v4
 * @property {string} ruleName - Name of the detection rule that fired
 * @property {Severity} severity - Alert severity level
 * @property {string} detectedAt - ISO 8601 timestamp of detection
 * @property {string} sourceIp - Source IP from the triggering entry
 * @property {LogEntry} evidence - The LogEntry that triggered the alert
 * @property {string} message - Human-readable summary
 */

/**
 * Creates an Alert object.
 * @param {Omit<Alert, 'id'>} fields
 * @returns {Alert}
 */
export function createAlert(fields) {
  return {
    id: uuidv4(),
    ruleName: fields.ruleName,
    severity: fields.severity,
    detectedAt: fields.detectedAt,
    sourceIp: fields.sourceIp,
    evidence: fields.evidence,
    message: fields.message,
  };
}

/**
 * @typedef {Object} AlertFilters
 * @property {string} [severity] - Filter by severity level
 * @property {string} [rule] - Filter by rule name
 * @property {Date} [since] - Filter by detection timestamp (>=)
 */

/**
 * Creates an AlertFilters object.
 * @param {Partial<AlertFilters>} fields
 * @returns {AlertFilters}
 */
export function createAlertFilters(fields = {}) {
  return {
    severity: fields.severity ?? undefined,
    rule: fields.rule ?? undefined,
    since: fields.since ?? undefined,
  };
}

/**
 * @typedef {Object} AlertStats
 * @property {Record<string, number>} byRule - Counts grouped by rule name
 * @property {Record<string, number>} bySeverity - Counts grouped by severity
 */

/**
 * Creates an AlertStats object.
 * @param {Partial<AlertStats>} fields
 * @returns {AlertStats}
 */
export function createAlertStats(fields = {}) {
  return {
    byRule: fields.byRule ?? {},
    bySeverity: fields.bySeverity ?? {},
  };
}

/**
 * @typedef {Object} HealthResponse
 * @property {'healthy' | 'degraded'} status - Service status
 * @property {number} filesWatched - Number of files currently being watched
 * @property {number} linesProcessed - Total number of log lines processed
 * @property {number} alertsGenerated - Total number of alerts generated
 * @property {string} [error] - Error description when degraded
 */

/**
 * Creates a HealthResponse object.
 * @param {Partial<HealthResponse>} fields
 * @returns {HealthResponse}
 */
export function createHealthResponse(fields = {}) {
  return {
    status: fields.status ?? 'healthy',
    filesWatched: fields.filesWatched ?? 0,
    linesProcessed: fields.linesProcessed ?? 0,
    alertsGenerated: fields.alertsGenerated ?? 0,
    ...(fields.error != null ? { error: fields.error } : {}),
  };
}

/**
 * @typedef {Object} RuleState
 * @property {Map<string, number[]>} windows - Maps sourceIP -> sorted array of event timestamps
 * @property {Map<string, number>} cooldowns - Maps "ruleName:sourceIP" -> last alert timestamp
 */

/**
 * Creates a RuleState object.
 * @returns {RuleState}
 */
export function createRuleState() {
  return {
    windows: new Map(),
    cooldowns: new Map(),
  };
}
