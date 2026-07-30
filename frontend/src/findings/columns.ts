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
  { id: 'ghsaRating', label: 'GHSA rating', note: "GitHub's own scale, not the CVSS band" },
  { id: 'cveId', label: 'CVE ID', note: 'Absent for GHSA-only and MAL-* advisories' },
  { id: 'severity', label: 'Severity', sort: 'SEVERITY', locked: true, note: 'Numeric CVSS score' },
  { id: 'cvssVersion', label: 'CVSS version', note: 'A v3 7.5 and a v4 7.5 differ' },
  { id: 'cvssVector', label: 'CVSS vector', note: 'Omitted when it cannot be attributed' },
  { id: 'fixedVersion', label: 'Fixed in', sort: 'FIXED_VERSION' },
  { id: 'published', label: 'Published', note: 'When the advisory was published, not the CVE' },
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
];

const KNOWN: ReadonlySet<string> = new Set(COLUMNS.map((c) => c.id));

/**
 * Stored preferences outlive the code that wrote them, so a saved set is repaired rather
 * than trusted: unknown ids (a column since removed) are dropped, locked ones are forced
 * back in, and the result is returned in the canonical order so the table never renders
 * columns in whatever sequence they happened to be ticked.
 */
export function reviveColumns(stored: ColumnId[]): ColumnId[] {
  const chosen = new Set(
    Array.isArray(stored) ? stored.filter((id): id is ColumnId => KNOWN.has(id)) : [],
  );
  LOCKED_COLUMNS.forEach((id) => chosen.add(id));
  return COLUMNS.filter((c) => chosen.has(c.id)).map((c) => c.id);
}
