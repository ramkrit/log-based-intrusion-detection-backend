import { createAlert } from '../models.js';

/**
 * SQL injection patterns to detect (case-insensitive).
 */
const SQL_PATTERNS = [
  "' or",
  "' and",
  '1=1',
  'union select',
  'union all select',
  '; drop',
  '--',
];

/**
 * Creates a SQL injection detection rule.
 * Triggers when a request path contains SQL injection patterns,
 * unless the path matches a known safe pattern.
 * @param {Set<string>} [safePatterns] - Optional set of safe path patterns to allowlist
 * @returns {{ name: string, severity: 'high', evaluate: (entry: import('../models.js').LogEntry, state: import('../models.js').RuleState) => import('../models.js').Alert | null }}
 */
export function createSqlInjectionRule(safePatterns = new Set()) {
  return {
    name: 'sql-injection',
    severity: 'high',

    /**
     * @param {import('../models.js').LogEntry} entry
     * @param {import('../models.js').RuleState} state
     * @returns {import('../models.js').Alert | null}
     */
    evaluate(entry, state) {
      const path = entry.path;
      if (!path) {
        return null;
      }

      const ip = entry.sourceIp;
      if (!ip) {
        return null;
      }

      const lowerPath = path.toLowerCase();
      const hasSqlPattern = SQL_PATTERNS.some(
        (pattern) => lowerPath.includes(pattern)
      );

      if (!hasSqlPattern) {
        return null;
      }

      // Check against safe-pattern allowlist
      for (const safe of safePatterns) {
        if (path === safe || path.includes(safe)) {
          return null;
        }
      }

      const now = entry.timestamp ? new Date(entry.timestamp).getTime() : Date.now();

      return createAlert({
        ruleName: 'sql-injection',
        severity: 'high',
        detectedAt: new Date(now).toISOString(),
        sourceIp: ip,
        evidence: entry,
        message: `SQL injection detected in request from ${ip}: ${path}`,
      });
    },
  };
}
