import { createAlert } from '../models.js';

const WINDOW_MS = 60000;
const THRESHOLD = 5;

/**
 * Creates a brute-force login detection rule.
 * Triggers when more than 5 HTTP 401 responses from the same IP
 * occur within a 60-second sliding window.
 * @returns {{ name: string, severity: 'high', evaluate: (entry: import('../models.js').LogEntry, state: import('../models.js').RuleState) => import('../models.js').Alert | null }}
 */
export function createBruteForceRule() {
  return {
    name: 'brute-force',
    severity: 'high',

    /**
     * @param {import('../models.js').LogEntry} entry
     * @param {import('../models.js').RuleState} state
     * @returns {import('../models.js').Alert | null}
     */
    evaluate(entry, state) {
      if (entry.statusCode !== 401) {
        return null;
      }

      const ip = entry.sourceIp;
      if (!ip) {
        return null;
      }

      const now = entry.timestamp ? new Date(entry.timestamp).getTime() : Date.now();

      if (!state.windows.has(ip)) {
        state.windows.set(ip, []);
      }

      const timestamps = state.windows.get(ip);
      timestamps.push(now);

      // Prune entries older than 60 seconds
      const cutoff = now - WINDOW_MS;
      while (timestamps.length > 0 && timestamps[0] <= cutoff) {
        timestamps.shift();
      }

      if (timestamps.length > THRESHOLD) {
        return createAlert({
          ruleName: 'brute-force',
          severity: 'high',
          detectedAt: new Date(now).toISOString(),
          sourceIp: ip,
          evidence: entry,
          message: `Brute-force login detected: ${timestamps.length} failed attempts from ${ip} in 60s`,
        });
      }

      return null;
    },
  };
}
