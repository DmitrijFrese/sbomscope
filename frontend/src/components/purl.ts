/**
 * Display helpers for package URLs.
 *
 * Findings are keyed by purl rather than by component row, so the coordinates shown in
 * the table are derived from it. The grammar is
 * `pkg:type/namespace/name@version?qualifiers`, where the namespace is optional and both
 * namespace and name may be percent-encoded — npm scopes arrive as `%40scope`.
 */
export interface PurlParts {
  /** `group:artifact` for Maven, `@scope/name` for npm, plain name otherwise. */
  coordinates: string;
  version: string;
  ecosystem: string;
}

export function describePurl(purl: string): PurlParts {
  const match = /^pkg:([^/]+)\/(.+)$/.exec(purl);
  if (!match) {
    return { coordinates: purl, version: '', ecosystem: '' };
  }

  const ecosystem = match[1] ?? '';
  const remainder = match[2] ?? '';

  // Qualifiers and subpath are display noise here.
  const withoutQualifiers = remainder.split('?')[0]?.split('#')[0] ?? '';

  const at = withoutQualifiers.lastIndexOf('@');
  const pathPart = at > 0 ? withoutQualifiers.slice(0, at) : withoutQualifiers;
  const version = at > 0 ? withoutQualifiers.slice(at + 1) : '';

  const segments = pathPart.split('/').map(decodeSegment);
  const coordinates =
    ecosystem === 'maven' ? segments.join(':') : segments.join('/');

  return { coordinates, version, ecosystem };
}

/**
 * The shortest label that still identifies a component, for places with no room for the
 * coordinates — the Inspector's tab strip, where the identity panel carries the full purl.
 *
 * <p>Maven drops the group, which is a reversed domain nobody reads to tell two artifacts
 * apart. npm keeps the whole name, because there the scope is half of it: `@angular/core`
 * and `@babel/core` are not the same library and `core` would claim they were.
 */
export function shortNameOf(purl: string): string {
  const { coordinates, ecosystem } = describePurl(purl);
  if (ecosystem !== 'maven') return coordinates;
  return coordinates.split(':').pop() || coordinates;
}

function decodeSegment(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}
