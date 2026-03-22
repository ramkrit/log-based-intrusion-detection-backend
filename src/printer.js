/**
 * Log Printer - formats LogEntry objects back into log line text.
 * This is the inverse of the Log Parser (src/parser.js).
 *
 * For CLF/Combined entries, reconstructs the line from structured fields.
 * For unknown format entries, returns the raw line.
 */

const MONTH_NAMES = [
  'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
  'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec',
];

/**
 * Convert an ISO 8601 timestamp back to CLF timestamp format.
 * Input:  "2000-10-10T13:55:36-07:00"
 * Output: "10/Oct/2000:13:55:36 -0700"
 * @param {string} iso
 * @returns {string}
 */
function formatTimestamp(iso) {
  // Match ISO 8601: YYYY-MM-DDThh:mm:ss+HH:MM or +HHMM
  const m = iso.match(
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})([+-]\d{2}):?(\d{2})$/
  );
  if (!m) return iso;

  const [, year, month, day, hour, min, sec, tzH, tzM] = m;
  const monthName = MONTH_NAMES[parseInt(month, 10) - 1];
  if (!monthName) return iso;

  const tz = `${tzH}${tzM}`;
  return `${day}/${monthName}/${year}:${hour}:${min}:${sec} ${tz}`;
}

/**
 * Format a LogEntry back into its original text representation.
 * @param {import('./models.js').LogEntry} entry
 * @returns {string}
 */
export function print(entry) {
  if (entry.format === 'unknown') {
    return entry.raw;
  }

  const ip = entry.sourceIp ?? '-';
  const timestamp = entry.timestamp ? formatTimestamp(entry.timestamp) : '-';
  const method = entry.method ?? '-';
  const path = entry.path ?? '/';
  const status = entry.statusCode ?? 0;
  const size = entry.size ?? 0;

  // CLF: {ip} {ident} {authuser} [{timestamp}] "{method} {path} {protocol}" {status} {size}
  // ident and authuser are not stored by the parser, default to "-"
  // protocol is not stored by the parser, default to "HTTP/1.1"
  const clf = `${ip} - - [${timestamp}] "${method} ${path} HTTP/1.1" ${status} ${size}`;

  if (entry.format === 'clf') {
    return clf;
  }

  // Combined: CLF + "{referer}" "{userAgent}"
  const referer = entry.referer ?? '';
  const userAgent = entry.userAgent ?? '';
  return `${clf} "${referer}" "${userAgent}"`;
}
