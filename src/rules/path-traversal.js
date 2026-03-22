import { createAlert } from '../models.js';

/**
 * Path traversal sequences to detect (case-insensitive).
 * Includes literal and URL-encoded variants.
 */
const TRAVERSAL_PATTERNS = [
  '../',
  '..\\',
  '%2e%2e%2f',
  '%2e%2e/',
  '..%2f',
  '%2e%2e%5c',
  '..%5c',
  '%2e%2e\\',
];

/**
 * Creates a path traversal detection rule.
 * Triggers when a request path contains path traversal sequences,
 * unless the path matches a known safe pattern.
 * @param {Set<string>} [safePatterns] - Optional set of safe path patterns to allowlist
 * @returns {{ name: string, severity: 'medium', evaluate: (entry: import('../models.js').LogEntry, state: import('../models.js').RuleState) => import('../models.js').Alert | null }}
 */
export function createPathTraversalRule(safePatterns = new Set()) {
  return {
    name: 'path-traversal',
    severity: 'medium',

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
      const hasTraversal = TRAVERSAL_PATTERNS.some(
        (pattern) => lowerPath.includes(pattern.toLowerCase())
      );

      if (!hasTraversal) {
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
        ruleName: 'path-traversal',
        severity: 'medium',
        detectedAt: new Date(now).toISOString(),
        sourceIp: ip,
        evidence: entry,
        message: `Path traversal detected in request from ${ip}: ${path}`,
      });
    },
  };
}
