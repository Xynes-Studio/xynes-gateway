/**
 * URL sanitization helpers.
 *
 * Security note: telemetry should never persist raw query strings because they may contain secrets.
 */

/**
 * Returns the pathname portion of an absolute URL, or a sanitized path if a path is provided.
 * Always strips query string and fragment.
 */
export function getPathnameFromUrlOrPath(urlOrPath: string): string {
  if (urlOrPath.startsWith('/')) {
    return stripQueryAndHash(urlOrPath);
  }

  try {
    const url = new URL(urlOrPath);
    return url.pathname;
  } catch {
    return stripQueryAndHash(urlOrPath);
  }
}

function stripQueryAndHash(value: string): string {
  const idx = value.search(/[?#]/);
  return idx === -1 ? value : value.slice(0, idx);
}

