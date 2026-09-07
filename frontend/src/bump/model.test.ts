import { describe, expect, it } from 'vitest';

import {
  apply,
  compareSemver,
  compareVersions,
  editsFor,
  redo,
  rowKey,
  sharedImpact,
  siteVersion,
  startSession,
  undo,
  versionDistance,
} from './model';
import type { BumpPlan, BumpRow, DeclarationSite, SiteKind } from './model';

function site(id: string, artifactId: string, kind: SiteKind = 'DIRECT'): DeclarationSite {
  return {
    id,
    file: 'module-a/pom.xml',
    module: 'module-a',
    kind,
    groupId: 'org.example',
    artifactId,
    type: '',
    classifier: '',
    currentVersion: '1.0.0',
    propertyName: kind === 'PROPERTY' ? 'shared.version' : null,
    sharedWith: [],
    exclusions: [],
    versionRange: kind === 'IMPORTED_BOM' || kind === 'UNDECLARED'
      ? null
      : { start: 1, end: 6, line: 1, column: 2 },
    insertionPoint: kind === 'IMPORTED_BOM' || kind === 'UNDECLARED'
      ? { start: 6, end: 6, line: 1, column: 7 }
      : null,
    ecosystem: 'MAVEN',
    versionLiteral: '1.0.0',
    rangeAdmitsFix: false,
  };
}

function row(id: string, artifactId: string, kind: SiteKind = 'DIRECT'): BumpRow {
  return {
    site: site(id, artifactId, kind),
    minimalTarget: '2.0.0',
    latestTarget: '3.0.0',
    minimalTargetAvailability: 'KNOWN',
    advisories: [{ osvId: 'OSV-1', cveId: null, osvUrl: null, cveUrl: null }],
    highestSeverity: 'HIGH',
    artifactUrl: null,
    currentVersionUrl: null,
    minimalTargetUrl: null,
    latestTargetUrl: null,
  };
}

function planWith(rows: BumpRow[]): BumpPlan {
  return {
    sbomId: 'b8d752d7-6d71-4a8b-8ee7-c5dc3ff7b92d',
    workspace: 'C:/work',
    files: [{ path: 'module-a/pom.xml', fingerprint: 'abc', editable: true, text: '<project />' }],
    rows,
    notes: [],
    lockfileNotes: [],
  };
}

describe('bump session command stack', () => {
  it('undos a preview text edit and then a row selection from one shared stack', () => {
    const target = row('one', 'commons-lang3');
    const key = rowKey(target.site);
    let session = startSession(planWith([target]));
    session = apply(session, { kind: 'select', row: key, version: '3.18.0', source: 'latest' });
    session = apply(session, { kind: 'editFile', path: 'module-a/pom.xml', text: '<changed />' });

    expect(session.undoLabel).toBe('Edit module-a/pom.xml');
    session = undo(session);
    expect(session.state.files).toEqual({});
    expect(session.undoLabel).toBe('Bump commons-lang3 to 3.18.0');
    session = undo(session);
    expect(session.state.selection).toEqual({});
    expect(session.canUndo).toBe(false);
  });

  it('replays an undo and exposes the matching redo label', () => {
    const target = row('one', 'commons-lang3');
    const key = rowKey(target.site);
    let session = apply(
      startSession(planWith([target])),
      { kind: 'select', row: key, version: '3.18.0', source: 'latest' },
    );

    session = undo(session);
    expect(session.redoLabel).toBe('Bump commons-lang3 to 3.18.0');
    session = redo(session);
    expect(session.state.selection[key]).toEqual({ version: '3.18.0', source: 'latest' });
  });

  it('discards redo when a new command follows an undo', () => {
    const first = row('one', 'first');
    const second = row('two', 'second');
    let session = startSession(planWith([first, second]));
    session = apply(session, { kind: 'select', row: rowKey(first.site), version: '2.0.0', source: 'minimal' });
    session = apply(session, { kind: 'select', row: rowKey(second.site), version: '2.0.0', source: 'minimal' });
    session = undo(session);
    session = apply(session, { kind: 'editFile', path: 'module-a/pom.xml', text: '<changed />' });

    expect(session.canRedo).toBe(false);
    expect(redo(session)).toStrictEqual(session);
  });

  it('does not add a stack entry for a selection it already carries', () => {
    const target = row('one', 'commons-lang3');
    const key = rowKey(target.site);
    let session = apply(
      startSession(planWith([target])),
      { kind: 'select', row: key, version: '2.0.0', source: 'minimal' },
    );
    const unchanged = apply(session, { kind: 'select', row: key, version: '2.0.0', source: 'minimal' });

    expect(unchanged.canUndo).toBe(true);
    expect(undo(unchanged).state.selection).toEqual({});
  });

  it('undos selectMany as one command', () => {
    const first = row('one', 'first');
    const second = row('two', 'second');
    let session = apply(startSession(planWith([first, second])), {
      kind: 'selectMany',
      selections: [
        { row: rowKey(first.site), version: '2.0.0', source: 'minimal' },
        { row: rowKey(second.site), version: '2.0.0', source: 'minimal' },
      ],
    });

    expect(session.undoLabel).toBe('Select 2 rows');
    session = undo(session);
    expect(session.state.selection).toEqual({});
    expect(session.canUndo).toBe(false);
  });

  it('removes a file edit when its text returns to the plan text', () => {
    let session = startSession(planWith([]));
    session = apply(session, { kind: 'editFile', path: 'module-a/pom.xml', text: '<changed />' });
    session = apply(session, { kind: 'editFile', path: 'module-a/pom.xml', text: '<project />' });

    expect(session.state.files).toEqual({});
  });
});

describe('derived bump plan data', () => {
  it('uses semver prerelease ordering for npm where Maven ordering is lexical', () => {
    expect(compareSemver('1.0.0-alpha.10', '1.0.0-alpha.2')).toBeGreaterThan(0);
    expect(compareVersions('1.0.0-alpha.10', '1.0.0-alpha.2')).toBeLessThan(0);
  });

  it('uses the higher request at one shared site and falls back when it is deselected', () => {
    const older = row('property', 'alpha', 'PROPERTY');
    const newer = row('property', 'beta', 'PROPERTY');
    const plan = planWith([older, newer]);
    let session = startSession(plan);
    session = apply(session, { kind: 'select', row: rowKey(older.site), version: '1.9', source: 'custom' });
    session = apply(session, { kind: 'select', row: rowKey(newer.site), version: '1.10', source: 'custom' });

    expect(siteVersion(session.state, 'property')).toBe('1.10');
    expect(editsFor(session.state)).toEqual([
      { siteId: 'property', newVersion: '1.10', structural: false },
    ]);
    session = apply(session, { kind: 'deselect', row: rowKey(newer.site) });
    expect(siteVersion(session.state, 'property')).toBe('1.9');
  });

  it('collapses shared-site requests and marks only insertion remedies structural', () => {
    const direct = row('direct', 'direct');
    const imported = row('imported', 'imported', 'IMPORTED_BOM');
    const undeclared = row('undeclared', 'undeclared', 'UNDECLARED');
    const session = apply(startSession(planWith([direct, imported, undeclared])), {
      kind: 'selectMany',
      selections: [
        { row: rowKey(direct.site), version: '2.0.0', source: 'minimal' },
        { row: rowKey(imported.site), version: '2.0.0', source: 'minimal' },
        { row: rowKey(undeclared.site), version: '2.0.0', source: 'minimal' },
      ],
    });

    expect(editsFor(session.state)).toEqual([
      { siteId: 'direct', newVersion: '2.0.0', structural: false },
      { siteId: 'imported', newVersion: '2.0.0', structural: true },
      { siteId: 'undeclared', newVersion: '2.0.0', structural: true },
    ]);
  });

  it('omits npm declarations that need no manifest edit from preview edits', () => {
    const target = row('package.json#dependencies#alpha', 'alpha', 'NPM_DIRECT');
    target.site.ecosystem = 'NPM';
    target.site.rangeAdmitsFix = true;
    const session = apply(startSession(planWith([target])), {
      kind: 'select', row: rowKey(target.site), version: '2.0.0', source: 'minimal',
    });

    expect(editsFor(session.state)).toEqual([]);
  });

  it('omits an undeclared npm diagnosis with no insertion point from preview edits', () => {
    const target = row('package.json#undeclared', 'transitive', 'UNDECLARED');
    target.site.ecosystem = 'NPM';
    target.site.insertionPoint = null;
    const session = apply(startSession(planWith([target])), {
      kind: 'select', row: rowKey(target.site), version: '2.0.0', source: 'minimal',
    });

    expect(editsFor(session.state)).toEqual([]);
  });

  it('reports every coordinate moved by a shared property', () => {
    const alpha = row('property', 'alpha', 'PROPERTY');
    alpha.site.sharedWith = ['org.example:beta', 'org.example:gamma'];
    const beta = row('property', 'beta', 'PROPERTY');
    beta.site.sharedWith = ['org.example:alpha', 'org.example:gamma'];
    const state = startSession(planWith([alpha, beta])).state;

    expect(sharedImpact(state, 'property')).toEqual([
      'org.example:alpha',
      'org.example:beta',
      'org.example:gamma',
    ]);
  });
});

describe('versionDistance', () => {
  it.each([
    ['3.0.1', '4.9.2', 'MAVEN', 'major'],
    ['1.6.0', '1.17.6', 'MAVEN', 'minor'],
    ['2.25.0', '2.25.5', 'MAVEN', 'patch'],
    ['1.2', '1.2.1', 'MAVEN', 'patch'],
    ['5', '6', 'MAVEN', 'major'],
    ['2.25.5', '2.25.5', 'MAVEN', 'none'],
    ['4.9.2', '3.0.1', 'MAVEN', 'none'],
    ['1.0.0-alpha', '1.0.0', 'MAVEN', 'patch'],
    ['RELEASE', '1.0.0', 'MAVEN', 'unknown'],
    ['1.0.0', 'v2.0.0', 'MAVEN', 'unknown'],
    ['', '1.0.0', 'MAVEN', 'unknown'],
    ['4.17.20', '4.17.21', 'NPM', 'patch'],
    ['4.17.20', '5.0.0', 'NPM', 'major'],
    ['1.0.0-alpha.2', '1.0.0-alpha.10', 'NPM', 'patch'],
  ] as const)('from %s to %s in %s is %s', (from, to, ecosystem, expected) => {
    expect(versionDistance(from, to, ecosystem)).toBe(expected);
  });

  it('uses the ecosystem comparator before classifying prerelease changes', () => {
    expect(versionDistance('1.0.0-alpha.2', '1.0.0-alpha.10', 'NPM')).toBe('patch');
    expect(versionDistance('1.0.0-alpha.2', '1.0.0-alpha.10', 'MAVEN')).toBe('none');
  });
});

describe('command validation', () => {
  it('refuses a command for a row key absent from the plan', () => {
    expect(() => apply(startSession(planWith([])), {
      kind: 'select',
      row: 'missing org.example:missing',
      version: '2.0.0',
      source: 'minimal',
    })).toThrow('missing org.example:missing');
  });
});
