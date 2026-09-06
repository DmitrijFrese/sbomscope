import { describe, expect, it } from 'vitest';

import { buildMatcher, rowMatches } from './searchMatcher';

describe('searchMatcher', () => {
  it('matches a literal case-insensitively', () => {
    const matcher = buildMatcher('Tomcat', false);
    expect(matcher.error).toBeNull();
    expect(matcher.test('org.apache.tomcat.embed:tomcat-embed-core')).toBe(true);
    expect(matcher.test('log4j-api')).toBe(false);
  });

  it('compiles a regex and reports one it cannot', () => {
    expect(buildMatcher('^log4j.*api$', true).test('log4j-api')).toBe(true);
    expect(buildMatcher('[unclosed', true).error).not.toBeNull();
  });

  // The rule this whole module exists to state once: an unusable pattern is unusable in both
  // polarities. Negating "matches nothing" would show the entire list, which is the most
  // alarming possible response to a half-typed exclusion in a security tool.
  it('matches nothing in either polarity when the pattern will not compile', () => {
    const broken = buildMatcher('[unclosed', true);
    expect(rowMatches(broken, false, ['anything'])).toBe(false);
    expect(rowMatches(broken, true, ['anything'])).toBe(false);
  });

  it('negates the whole row rather than each field', () => {
    const matcher = buildMatcher('tomcat', false);
    // The row matches on its first field and not its second. Per-field negation would keep it.
    expect(rowMatches(matcher, true, ['tomcat-embed-core', '11.0.22'])).toBe(false);
    expect(rowMatches(matcher, true, ['log4j-api', '2.25.4'])).toBe(true);
  });

  it('treats a null or absent field as empty rather than throwing', () => {
    const matcher = buildMatcher('x', false);
    expect(rowMatches(matcher, false, [null, undefined, 'x'])).toBe(true);
  });
});
