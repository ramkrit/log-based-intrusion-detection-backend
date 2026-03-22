import fs from 'node:fs';
import path from 'node:path';

/**
 * Creates a FileWatcher instance that monitors a directory for log files.
 * Uses fs.watch as primary mechanism with fs.watchFile polling fallback.
 */
export function createFileWatcher() {
  /** @type {Map<string, number>} file path -> byte offset */
  const offsets = new Map();
  /** @type {Map<string, string>} file path -> buffered partial line */
  const buffers = new Map();
  /** @type {Map<string, fs.StatWatcher>} file path -> polling watcher */
  const pollingWatchers = new Map();
  /** @type {fs.FSWatcher | null} */
  let dirWatcher = null;
  /** @type {((lines: string[], filePath: string) => void) | null} */
  let linesCallback = null;
  /** @type {{ healthy: boolean; error?: string }} */
  let status = { healthy: true };
  let linesProcessed = 0;
  let logDir = '';
  let stopped = false;

  /**
   * Read new content from a file starting at the stored byte offset.
   * Splits on newlines, emits complete lines, buffers partial trailing line.
   * @param {string} filePath
   */
  function readNewContent(filePath) {
    const currentOffset = offsets.get(filePath) ?? 0;

    let stat;
    try {
      stat = fs.statSync(filePath);
    } catch (err) {
      // File may have been deleted
      removeFile(filePath);
      return;
    }

    if (stat.size <= currentOffset) {
      return;
    }

    const fd = fs.openSync(filePath, 'r');
    try {
      const bytesToRead = stat.size - currentOffset;
      const buffer = Buffer.alloc(bytesToRead);
      fs.readSync(fd, buffer, 0, bytesToRead, currentOffset);
      offsets.set(filePath, stat.size);

      const existingBuffer = buffers.get(filePath) ?? '';
      const text = existingBuffer + buffer.toString('utf-8');

      const parts = text.split('\n');

      // Last element is either empty (if text ended with \n) or a partial line
      const lastPart = parts.pop();
      buffers.set(filePath, lastPart ?? '');

      // Filter out empty strings from consecutive newlines
      const completeLines = parts.filter((line) => line.length > 0);

      if (completeLines.length > 0 && linesCallback) {
        linesProcessed += completeLines.length;
        linesCallback(completeLines, filePath);
      }
    } finally {
      fs.closeSync(fd);
    }
  }

  /**
   * Start watching a single file with fs.watchFile polling fallback.
   * @param {string} filePath
   */
  function watchFile(filePath) {
    if (pollingWatchers.has(filePath)) {
      return;
    }

    if (!offsets.has(filePath)) {
      offsets.set(filePath, 0);
      buffers.set(filePath, '');
    }

    // Read any existing content
    readNewContent(filePath);

    // Set up polling watcher as fallback (works on Docker volume mounts)
    fs.watchFile(filePath, { interval: 1000 }, () => {
      if (!stopped) {
        readNewContent(filePath);
      }
    });
    pollingWatchers.set(filePath, true);
  }

  /**
   * Remove a file from watching.
   * @param {string} filePath
   */
  function removeFile(filePath) {
    if (pollingWatchers.has(filePath)) {
      fs.unwatchFile(filePath);
      pollingWatchers.delete(filePath);
    }
    offsets.delete(filePath);
    buffers.delete(filePath);
  }

  /**
   * Scan directory for existing files and start watching them.
   * @param {string} dir
   */
  function scanExistingFiles(dir) {
    try {
      const entries = fs.readdirSync(dir);
      for (const entry of entries) {
        const fullPath = path.join(dir, entry);
        try {
          const stat = fs.statSync(fullPath);
          if (stat.isFile()) {
            watchFile(fullPath);
          }
        } catch {
          // Skip files we can't stat
        }
      }
    } catch (err) {
      status = { healthy: false, error: `Failed to scan directory: ${err.message}` };
    }
  }

  return {
    /**
     * Register a callback for complete lines.
     * @param {(lines: string[], filePath: string) => void} callback
     */
    onLines(callback) {
      linesCallback = callback;
    },

    /**
     * Start watching the given log directory.
     * Validates directory exists, scans existing files, begins monitoring.
     * @param {string} dir
     */
    start(dir) {
      logDir = dir;
      stopped = false;

      // Validate directory exists
      if (!fs.existsSync(dir)) {
        status = { healthy: false, error: `Log directory does not exist: ${dir}` };
        throw new Error(`Log directory does not exist: ${dir}`);
      }

      try {
        const stat = fs.statSync(dir);
        if (!stat.isDirectory()) {
          status = { healthy: false, error: `Path is not a directory: ${dir}` };
          throw new Error(`Path is not a directory: ${dir}`);
        }
      } catch (err) {
        if (err.message.startsWith('Log directory') || err.message.startsWith('Path is not')) {
          throw err;
        }
        status = { healthy: false, error: `Cannot access directory: ${dir}` };
        throw new Error(`Cannot access directory: ${dir}`);
      }

      // Scan existing files
      scanExistingFiles(dir);

      // Watch directory for new files
      try {
        dirWatcher = fs.watch(dir, (eventType, filename) => {
          if (stopped || !filename) return;

          const fullPath = path.join(dir, filename);

          try {
            const stat = fs.statSync(fullPath);
            if (stat.isFile() && !pollingWatchers.has(fullPath)) {
              // New file detected
              watchFile(fullPath);
            } else if (stat.isFile()) {
              // Existing file changed - read new content
              readNewContent(fullPath);
            }
          } catch {
            // File may have been deleted, ignore
          }
        });
      } catch (err) {
        status = { healthy: false, error: `Failed to watch directory: ${err.message}` };
      }
    },

    /**
     * Stop all watchers and clean up.
     */
    stop() {
      stopped = true;

      if (dirWatcher) {
        dirWatcher.close();
        dirWatcher = null;
      }

      for (const filePath of pollingWatchers.keys()) {
        fs.unwatchFile(filePath);
      }
      pollingWatchers.clear();
      offsets.clear();
      buffers.clear();
    },

    /**
     * Get the number of files currently being watched.
     * @returns {number}
     */
    getWatchedFileCount() {
      return pollingWatchers.size;
    },

    /**
     * Get the current health status.
     * @returns {{ healthy: boolean; error?: string }}
     */
    getStatus() {
      return { ...status };
    },

    /**
     * Get the total number of lines processed.
     * @returns {number}
     */
    getLinesProcessed() {
      return linesProcessed;
    },
  };
}
