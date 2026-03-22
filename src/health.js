/**
 * Health controller that aggregates status from File Watcher and Alert Store.
 *
 * @param {ReturnType<import('./watcher.js').createFileWatcher>} watcher
 * @param {ReturnType<import('./alerts/store.js').createAlertStore>} alertStore
 */
export function createHealthController(watcher, alertStore) {
  return {
    /**
     * Returns the current health status of the system.
     * @returns {import('./models.js').HealthResponse}
     */
    getHealth() {
      const watcherStatus = watcher.getStatus();
      return {
        status: watcherStatus.healthy ? 'healthy' : 'degraded',
        filesWatched: watcher.getWatchedFileCount(),
        linesProcessed: watcher.getLinesProcessed(),
        alertsGenerated: alertStore.count(),
        ...(watcherStatus.error ? { error: watcherStatus.error } : {}),
      };
    },
  };
}
