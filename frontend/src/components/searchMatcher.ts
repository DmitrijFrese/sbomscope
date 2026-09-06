/**
 * The one reading of what a search box means, for the screens that filter in the browser.
 *
 * <p>Extracted from ComponentFinder when the bump table became the second such screen. The
 * semantics below are not obvious and were arrived at by using the thing — a copy would be a
 * second place for them to drift, which is exactly what the repository's "one reading" convention
 * exists to prevent. `SearchField` owns how the controls look; this owns what they mean.
 *
 * <p>Note that the server-side filters (findings, the diff) deliberately do not use this: their
 * pattern is applied in SQL, and the same wording there is enforced by a test rather than by a
 * shared function.
 */
export interface SearchMatcher {
  test: (value: string) => boolean;
  /** Why the pattern could not be compiled, or null. A note for the user, never an error. */
  error: string | null;
}

/**
 * @param query the raw text the user typed
 * @param regex whether to read it as a regular expression rather than a literal substring
 */
export function buildMatcher(query: string, regex: boolean): SearchMatcher {
  const raw = regex ? query : query.trim().toLowerCase();
  if (!raw) {
    return { test: () => true, error: null };
  }
  if (!regex) {
    return { test: (value) => value.toLowerCase().includes(raw), error: null };
  }
  try {
    // 'i' to match the literal mode's case-insensitivity, so the toggle changes one thing.
    const compiled = new RegExp(raw, 'i');
    return { test: (value) => compiled.test(value), error: null };
  } catch (e) {
    return { test: () => false, error: e instanceof Error ? e.message : 'Invalid pattern.' };
  }
}

/**
 * Whether a row survives the filter, given every string that row is searchable by.
 *
 * <p>**Negation applies to the whole row, not to each field.** The positive form shows a row when
 * any of its fields matches, so the negative form has to hide it on the same condition; per-field
 * negation would show a row whose coordinate contains the term merely because its version does
 * not.
 *
 * <p>**A pattern that will not compile matches nothing, in both polarities.** Negating "nothing"
 * would be everything, so a half-typed exclusion would briefly show the whole list as though the
 * filter had been cleared — the most alarming possible response to a typo in a security tool.
 */
export function rowMatches(matcher: SearchMatcher, negate: boolean, fields: Array<string | null | undefined>): boolean {
  if (matcher.error) {
    return false;
  }
  const hit = fields.some((field) => matcher.test(field ?? ''));
  return negate ? !hit : hit;
}
