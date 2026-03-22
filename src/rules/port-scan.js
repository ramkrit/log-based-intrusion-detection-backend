import { createAlert } from '../models.js';

const WINDOW_MS = 10000;
const THRESHOLD = 100;

/**
 * Creates a port scan / rapid request detection rule.
 * Triggers when more than 100 requests from the same IP
 * occur within a 10-second sliding window.
 * @returns {{ name: string, severity: 'critical', evaluate: (entry: import('../models.js').LogEntry, state: import('../models.js').RuleState) => import('../models.js').Alert | null }}
 */
export function createPortScanRule() {
  return {
    name: 'port-scan',
    severity: 'critical',

    /**
     * @param {import('../models.js').LogEntry} entry
     * @param {import('../models.js').RuleState} state
     * @returns {import('../models.js').Alert | null}
     */
    evaluate(entry, state) {
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

      // Prune entries older than 10 seconds
      const cutoff = now - WINDOW_MS;
      while (timestamps.length > 0 && timestamps[0] <= cutoff) {
        timestamps.shift();
      }

      if (timestamps.length > THRESHOLD) {
        return createAlert({
          ruleName: 'port-scan',
          severity: 'critical',
          detectedAt: new Date(now).toISOString(),
          sourceIp: ip,
          evidence: entry,
          message: `Port scan / rapid requests detected: ${timestamps.length} requests from ${ip} in 10s`,
        });
      }

      return null;
    },
  };
}
