/**
 * In-memory alert storage with filtering and stats support.
 */

/**
 * Creates a new AlertStore instance.
 * @returns {{ add: (alert: import('../models.js').Alert) => void, query: (filters: import('../models.js').AlertFilters) => import('../models.js').Alert[], stats: () => import('../models.js').AlertStats, count: () => number }}
 */
export function createAlertStore() {
  /** @type {import('../models.js').Alert[]} */
  const alerts = [];

  return {
    /**
     * Appends an alert to the store.
     * @param {import('../models.js').Alert} alert
     */
    add(alert) {
      alerts.push(alert);
    },

    /**
     * Filters alerts by severity, rule, and since with AND semantics.
     * All provided filters must match for an alert to be included.
     * @param {import('../models.js').AlertFilters} filters
     * @returns {import('../models.js').Alert[]}
     */
    query(filters = {}) {
      return alerts.filter((alert) => {
        if (filters.severity !== undefined && alert.severity !== filters.severity) {
          return false;
        }
        if (filters.rule !== undefined && alert.ruleName !== filters.rule) {
          return false;
        }
        if (filters.since !== undefined) {
          const alertTime = new Date(alert.detectedAt);
          if (alertTime < filters.since) {
            return false;
          }
        }
        return true;
      });
    },

    /**
     * Returns counts grouped by rule name and severity.
     * @returns {import('../models.js').AlertStats}
     */
    stats() {
      /** @type {Record<string, number>} */
      const byRule = {};
      /** @type {Record<string, number>} */
      const bySeverity = {};

      for (const alert of alerts) {
        byRule[alert.ruleName] = (byRule[alert.ruleName] || 0) + 1;
        bySeverity[alert.severity] = (bySeverity[alert.severity] || 0) + 1;
      }

      return { byRule, bySeverity };
    },

    /**
     * Returns total alert count.
     * @returns {number}
     */
    count() {
      return alerts.length;
    },
  };
}
