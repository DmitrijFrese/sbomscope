import { describe, expect, it } from 'vitest';

import {
  COLUMNS,
  COMPACT_DEFAULT,
  LOCKED_COLUMNS,
  reviveColumns,
  reviveStoredColumns,
  storeColumns,
} from './columns';
import type { ColumnId } from './columns';

/**
 * Reviving a stored column preference.
 *
 * <p>The case worth pinning is the one found by verifying in the browser rather than by
 * reading: a column added to the core set later can never appear in a preference written
 * before it existed, and {@link reviveColumns} cannot tell that from a column somebody
 * deliberately unticked. Without the union below, Phase 3 shipped two columns that were on
 * nobody's screen except a first-time visitor's.
 */
describe('reviveColumns', () => {
  it('adds columns introduced since the preference was written', () => {
    // The pre-Phase-3 shape: a bare array, with no record of what was known at the time.
    const legacy: ColumnId[] = ['component', 'version', 'osvId', 'severity'];

    expect(reviveColumns(legacy)).toContain('kev');
    expect(reviveColumns(legacy)).toContain('epss');
  });

  it('respects an explicit removal once the column is known', () => {
    // The other half, and the reason the union is keyed on knownIds rather than run every
    // time: helpfully restoring a column the reader keeps unticking would be worse than
    // never showing it.
    const stored = storeColumns(['component', 'version', 'osvId', 'severity']);

    expect(reviveColumns(stored)).not.toContain('kev');
    expect(reviveColumns(stored)).not.toContain('epss');
  });

  it('stamps the revived value so the union happens exactly once', () => {
    const revived = reviveStoredColumns(['component', 'severity'] as ColumnId[]);

    expect(revived.columns).toContain('kev');
    expect(revived.knownIds).toContain('kev');
    // Written back, then revived again: the choice now sticks.
    expect(reviveColumns(storeColumns(revived.columns.filter((id) => id !== 'kev')))).not.toContain(
      'kev',
    );
  });

  it('forces the locked columns back in', () => {
    // A row without these cannot be acted on, so they are not the reader's to remove.
    const revived = reviveColumns(storeColumns(['summary']));

    LOCKED_COLUMNS.forEach((id) => expect(revived).toContain(id));
  });

  it('drops ids this build does not recognise', () => {
    // A column removed in a later version, still sitting in somebody's localStorage.
    const revived = reviveColumns(['component', 'somethingRemoved' as ColumnId]);

    expect(revived).not.toContain('somethingRemoved');
  });

  it('returns the canonical order, not the order things were ticked', () => {
    const revived = reviveColumns(storeColumns(['purl', 'component', 'severity']));
    const canonical = COLUMNS.map((c) => c.id).filter((id) => revived.includes(id));

    expect(revived).toEqual(canonical);
  });

  it('survives a corrupt or empty stored value', () => {
    // Stored state outlives the code that wrote it, and a broken preference must never be
    // worth failing a render over. An empty value carries no knownIds either, so the union
    // applies to it as well — which is right: it is indistinguishable from a preference
    // written before those columns existed.
    const expected = COLUMNS.map((c) => c.id).filter(
      (id) => LOCKED_COLUMNS.includes(id) || id === 'kev' || id === 'epss',
    );

    expect(reviveColumns([])).toEqual(expected);
    expect(reviveColumns(undefined as never)).toEqual(expected);
  });

  it('keeps the core set a subset of the columns that exist', () => {
    const known = new Set(COLUMNS.map((c) => c.id));
    COMPACT_DEFAULT.forEach((id) => expect(known.has(id)).toBe(true));
  });
});
