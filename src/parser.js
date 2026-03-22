import { createLogEntry } from './models.js';

// CLF: host ident authuser [date] "method path protocol" status size
const CLF_REGEX = /^(\S+) (\S+) (\S+) \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d{3}) (\d+|-)$/;

// Combined: CLF + "referer" "user-agent"
const COMBINED_REGEX = /^(\S+) (\S+) (\S+) \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d{3}) (\d+|-) "([^"]*)" "([^"]*)"$/;

/**
 * Parse a CLF-style timestamp string into an ISO 8601 string.
 * Example input: "10/Oct/2000:13:55:36 -0700"
 * @param {string} raw
 * @returns {string}
 */
function parseTimestamp(raw) {
  const months = {
    Jan: '01', Feb: '02', Mar: '03', Apr: '04',
    May: '05', Jun: '06', Jul: '07', Aug: '08',
    Sep: '09', Oct: '10', Nov: '11', Dec: '12',
  };

  const m = raw.match(/^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})$/);
  if (!m) return raw;

  const [, day, monthStr, year, hour, min, sec, tz] = m;
  const month = months[monthStr];
  if (!month) return raw;

  // Format timezone as +HH:MM
  const tzFormatted = `${tz.slice(0, 3)}:${tz.slice(3)}`;
  return `${year}-${month}-${day}T${hour}:${min}:${sec}${tzFormatted}`;
}

/**
 * Parse a raw log line into a LogEntry object.
 * Attempts Combined format first (more specific), then CLF.
 * Falls back to unknown format if neither matches.
 * @param {string} rawLine
 * @returns {import('./models.js').LogEntry}
 */
export function parse(rawLine) {
  // Strip trailing carriage return (Windows line endings)
  const line = rawLine.replace(/\r$/, '');

  // Try Combined format first (it's a superset of CLF)
  const combinedMatch = line.match(COMBINED_REGEX);
  if (combinedMatch) {
    const [, ip, , , timestamp, method, path, , statusStr, sizeStr, referer, userAgent] = combinedMatch;
    return createLogEntry({
      timestamp: parseTimestamp(timestamp),
      sourceIp: ip,
      method,
      path,
      statusCode: parseInt(statusStr, 10),
      size: sizeStr === '-' ? 0 : parseInt(sizeStr, 10),
      referer: referer || null,
      userAgent: userAgent || null,
      format: 'combined',
      raw: line,
    });
  }

  // Try CLF
  const clfMatch = line.match(CLF_REGEX);
  if (clfMatch) {
    const [, ip, , , timestamp, method, path, , statusStr, sizeStr] = clfMatch;
    return createLogEntry({
      timestamp: parseTimestamp(timestamp),
      sourceIp: ip,
      method,
      path,
      statusCode: parseInt(statusStr, 10),
      size: sizeStr === '-' ? 0 : parseInt(sizeStr, 10),
      format: 'clf',
      raw: line,
    });
  }

  // Unknown format
  return createLogEntry({
    format: 'unknown',
    raw: line,
  });
}
