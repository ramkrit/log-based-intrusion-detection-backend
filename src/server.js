import express from 'express';

const VALID_SEVERITIES = ['low', 'medium', 'high', 'critical'];

/**
 * Creates and configures the Express app (does NOT call app.listen).
 *
 * @param {ReturnType<import('./alerts/store.js').createAlertStore>} alertStore
 * @param {ReturnType<import('./health.js').createHealthController>} healthController
 * @returns {import('express').Express}
 */
export function createServer(alertStore, healthController) {
  const app = express();

  app.get('/alerts', (req, res) => {
    const { severity, rule, since } = req.query;

    if (severity !== undefined && !VALID_SEVERITIES.includes(severity)) {
      return res.status(400).json({
        error: `Invalid 'severity' parameter. Expected one of: ${VALID_SEVERITIES.join(', ')}.`,
      });
    }

    if (since !== undefined) {
      const parsed = new Date(since);
      if (isNaN(parsed.getTime())) {
        return res.status(400).json({
          error: "Invalid 'since' parameter. Expected ISO 8601 format.",
        });
      }
    }

    const filters = {};
    if (severity !== undefined) filters.severity = severity;
    if (rule !== undefined) filters.rule = rule;
    if (since !== undefined) filters.since = new Date(since);

    const alerts = alertStore.query(filters);
    res.json(alerts);
  });

  app.get('/alerts/stats', (req, res) => {
    res.json(alertStore.stats());
  });

  app.get('/health', (req, res) => {
    res.json(healthController.getHealth());
  });

  // 404 handler for unmatched routes
  app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
  });

  return app;
}
