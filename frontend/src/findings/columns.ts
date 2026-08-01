/**
 * The findings table's columns, in one place.
 *
 * <p>The table, the column picker and the persisted preference all read this list, so a
 * column cannot exist in one and not the others.
 *
 * <p>Ordering groups each value with the source it came from. Almost everything on a row
 * describes the **OSV/GHSA advisory record**: the rating is GitHub's own qualitative label
 * from `database_specific`, and the published date is when that record appeared — neither
 * is NVD's. Only the CVE identifier points elsewhere. So the GHSA rating sits against the
 * OSV ID it belongs to, and the score leads the CVSS values that produced it, rather than
 * the whole lot being jumbled into one "severity-ish" block.
 */
import type { SortField } from '../api/client';

export type ColumnId =
  | 'component'
  | 'version'
  | 'scope'
  | 'osvId'
  | 'ghsaRating'
  | 'cveId'
  | 'severity'
  | 'cvssVersion'
  | 'cvssVector'
  | 'fixedVersion'
  | 'published'
  | 'kev'
  | 'epss'
  | 'summary'
  | 'purl';

export interface ColumnDef {
  id: ColumnId;
  label: string;
  /** Present when the column can be sorted; drives the clickable header. */
  sort?: SortField;
  /**
   * Cannot be switched off. A row without these four cannot be acted on: what the library
   * is, which version, which advisory, and how bad.
   */
  locked?: boolean;
  /** Shown under the label in the picker, for columns whose source is easy to mistake. */
  note?: string;
}

export const COLUMNS: ColumnDef[] = [
  { id: 'component', label: 'Component', sort: 'COMPONENT', locked: true },
  { id: 'version', label: 'Version', locked: true },
  { id: 'scope', label: 'Scope', sort: 'SCOPE' },
  { id: 'osvId', label: 'OSV ID', locked: true, note: 'The advisory record, usually a GHSA' },
  { id: 'ghsaRating', label: 'GHSA rating', sort: 'GHSA_RATING', note: "GitHub's own scale, not the CVSS band" },
  { id: 'cveId', label: 'CVE ID', note: 'Absent for GHSA-only and MAL-* advisories' },
  { id: 'severity', label: 'Severity', sort: 'SEVERITY', locked: true, note: 'Numeric CVSS score' },
  { id: 'cvssVersion', label: 'CVSS version', note: 'A v3 7.5 and a v4 7.5 differ' },
  { id: 'cvssVector', label: 'CVSS vector', note: 'Omitted when it cannot be attributed' },
  { id: 'fixedVersion', label: 'Fixed in', sort: 'FIXED_VERSION' },
  { id: 'published', label: 'Published', sort: 'PUBLISHED', note: 'When the advisory was published, not the CVE' },
  {
    id: 'kev',
    label: 'Known exploited',
    sort: 'KEV',
    note: 'CISA KEV. Empty means not listed, never "cleared"',
  },
  { id: 'epss', label: 'EPSS', sort: 'EPSS', note: 'Probability of exploitation in 30 days' },
  { id: 'summary', label: 'Summary' },
  { id: 'purl', label: 'Package URL' },
];

export const LOCKED_COLUMNS: ColumnId[] = COLUMNS.filter((c) => c.locked).map((c) => c.id);

/**
 * What Compact shows. Everything omitted here is available in Details or by ticking it.
 *
 * <p>Summary is the widest thing a row can carry and Package URL restates the component,
 * so both stay out by default — Compact is for scanning a list, not reading it.
 */
export const COMPACT_DEFAULT: ColumnId[] = [
  'component',
  'version',
  'scope',
  'osvId',
  'cveId',
  'severity',
  'fixedVersion',
  'published',
  // Prioritisation rather than identification, which is why they are here and not locked:
  // somebody who has never downloaded the feeds must be able to remove two columns that will
  // stay empty for them.
  'kev',
  'epss',
];

const KNOWN: ReadonlySet<string> = new Set(COLUMNS.map((c) => c.id));

/**
 * Columns added to the core set after this preference started being stored.
 *
 * <p>A stored set cannot contain a column that did not exist when it was written, and
 * {@link reviveColumns} has no way to tell that from a column somebody deliberately unticked.
 * Without this, adding a column to {@link COMPACT_DEFAULT} makes it appear only for people who
 * have never opened the page — which is to say, not for the person who asked for it. Found by
 * verifying in the browser: the two Phase 3 columns were in the default set and on nobody's
 * screen.
 *
 * <p>Each entry is unioned in exactly once, when a preference written before that entry existed
 * is first revived. Ticking a column off afterwards sticks, because the stored set is then
 * written back carrying the marker.
 */
const ADDED_SINCE: { marker: ColumnId; columns: ColumnId[] }[] = [
  // Phase 3. Keyed off `kev` being absent from the *known* set of the stored preference —
  // see the shape note below.
  { marker: 'kev', columns: ['kev', 'epss'] },
];

/**
 * What is actually persisted.
 *
 * <p>The bare array is the pre-Phase-3 shape and is still read, so nobody's choices are
 * discarded by the upgrade. `knownIds` records which columns existed when the preference was
 * written, which is the fact {@link ADDED_SINCE} needs and the one a bare array cannot carry.
 */
export interface StoredColumns {
  columns: ColumnId[];
  knownIds: ColumnId[];
}

export function storeColumns(columns: ColumnId[]): StoredColumns {
  return { columns, knownIds: COLUMNS.map((c) => c.id) };
}

/**
 * Stored preferences outlive the code that wrote them, so a saved set is repaired rather
 * than trusted: unknown ids (a column since removed) are dropped, locked ones are forced
 * back in, columns added to the core set since it was written are unioned in, and the result
 * is returned in the canonical order so the table never renders columns in whatever sequence
 * they happened to be ticked.
 */
export function reviveColumns(stored: StoredColumns | ColumnId[]): ColumnId[] {
  const legacy = Array.isArray(stored);
  const storedColumns = legacy ? stored : (stored?.columns ?? []);
  const knownWhenWritten = new Set<string>(legacy ? [] : (stored?.knownIds ?? []));

  const chosen = new Set(
    Array.isArray(storedColumns)
      ? storedColumns.filter((id): id is ColumnId => KNOWN.has(id))
      : [],
  );
  LOCKED_COLUMNS.forEach((id) => chosen.add(id));

  ADDED_SINCE.forEach((addition) => {
    if (!knownWhenWritten.has(addition.marker)) {
      addition.columns.forEach((id) => chosen.add(id));
    }
  });

  return COLUMNS.filter((c) => chosen.has(c.id)).map((c) => c.id);
}

/**
 * What the page actually persists: the revived selection, stamped with the columns this build
 * knows about.
 *
 * <p>Writing the stamp on revive rather than only on change is what makes the union above
 * happen exactly once — the very next write records that `kev` is now a known column, so
 * unticking it afterwards sticks instead of being helpfully restored on every reload.
 */
export function reviveStoredColumns(stored: StoredColumns | ColumnId[]): StoredColumns {
  return storeColumns(reviveColumns(stored));
}
