import { createFileWatcher } from './watcher.js';
import { parse } from './parser.js';
import { createRuleEngine } from './rules/engine.js';
import { createBruteForceRule } from './rules/brute-force.js';
import { createPathTraversalRule } from './rules/path-traversal.js';
import { createSqlInjectionRule } from './rules/sql-injection.js';
import { createPortScanRule } from './rules/port-scan.js';
import { createAlertStore } from './alerts/store.js';
import { createHealthController } from './health.js';
import { createServer } from './server.js';
import { logAlert, logInfo, logError } from './logger.js';

const alertStore = createAlertStore();
const watcher = createFileWatcher();
const engine = createRuleEngine();

engine.registerRule(createBruteForceRule());
engine.registerRule(createPathTraversalRule());
engine.registerRule(createSqlInjectionRule());
engine.registerRule(createPortScanRule());

const healthController = createHealthController(watcher, alertStore);
const app = createServer(alertStore, healthController);

watcher.onLines((lines, filePath) => {
  for (const line of lines) {
    const entry = parse(line);
    const alerts = engine.evaluate(entry);
    for (const alert of alerts) {
      alertStore.add(alert);
      logAlert(alert);
    }
  }
});

try {
  watcher.start('/logs');
} catch (err) {
  logError(`Failed to start file watcher: ${err.message}`);
  process.exit(1);
}

app.listen(8080, () => {
  logInfo('Server listening on port 8080');
});

logInfo(`Loaded ${engine.getRules().length} detection rules`);
logInfo('Watching log directory: /logs');
