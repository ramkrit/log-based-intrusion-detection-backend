import { createRuleState } from '../models.js';

const COOLDOWN_MS = 60000;

/**
 * Creates a RuleEngine that evaluates log entries against registered detection rules.
 * @returns {object} RuleEngine instance
 */
export function createRuleEngine() {
  /** @type {Array<{rule: object, state: import('../models.js').RuleState}>} */
  const registrations = [];

  /** @type {Map<string, Set<string>>} ruleName -> set of safe patterns */
  const safePatterns = new Map();

  /**
   * Register a detection rule.
   * @param {object} rule - DetectionRule with name, severity, evaluate(entry, state)
   */
  function registerRule(rule) {
    registrations.push({
      rule,
      state: createRuleState(),
    });
  }

  /**
   * Evaluate a log entry against all registered rules.
   * Each rule evaluation is wrapped in try-catch for fault isolation.
   * Alerts are suppressed if the same (ruleName, sourceIP) fired within the cooldown period.
   * @param {import('../models.js').LogEntry} entry
   * @returns {import('../models.js').Alert[]}
   */
  function evaluate(entry) {
    const alerts = [];

    for (const { rule, state } of registrations) {
      try {
        const alert = rule.evaluate(entry, state);
        if (alert == null) continue;

        const sourceIp = alert.sourceIp;
        const cooldownKey = `${rule.name}:${sourceIp}`;
        const now = Date.now();
        const lastFired = state.cooldowns.get(cooldownKey);

        if (lastFired != null && (now - lastFired) < COOLDOWN_MS) {
          // Suppress duplicate alert within cooldown period
          continue;
        }

        state.cooldowns.set(cooldownKey, now);
        alerts.push(alert);
      } catch (err) {
        // Fault isolation: log error and skip this rule
        console.error(`[ERROR] Rule "${rule.name}" failed during evaluation:`, err.message);
      }
    }

    return alerts;
  }

  /**
   * Get all registered rules.
   * @returns {object[]}
   */
  function getRules() {
    return registrations.map(r => r.rule);
  }

  /**
   * Add a safe pattern to a rule's allowlist.
   * @param {string} ruleName
   * @param {string} pattern
   */
  function addSafePattern(ruleName, pattern) {
    if (!safePatterns.has(ruleName)) {
      safePatterns.set(ruleName, new Set());
    }
    safePatterns.get(ruleName).add(pattern);
  }

  /**
   * Get safe patterns for a rule.
   * @param {string} ruleName
   * @returns {Set<string>}
   */
  function getSafePatterns(ruleName) {
    return safePatterns.get(ruleName) ?? new Set();
  }

  return {
    registerRule,
    evaluate,
    getRules,
    addSafePattern,
    getSafePatterns,
  };
}
