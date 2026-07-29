/**
 * How a finding is rendered, shared by the findings table and the Component Inspector.
 *
 * <p>Extracted when the Inspector needed the same three states the table distinguishes: a
 * scored vulnerability, a vulnerability of unknown severity, and a component with nothing
 * known against it. Rendering those in two places is how "unscored" quietly starts reading
 * as "clean" on one screen and not the other — and the whole point of opening a component
 * from a row is that it is the same component, described the same way.
 */
import type { FindingRow } from '../api/client';

/** Standard CVSS bands, matching how the backend filters. */
export function bandOf(score: number): string {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

export const BAND_LABELS: Record<string, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};

/**
 * Three distinct states, deliberately rendered differently: a scored vulnerability, a
 * vulnerability of unknown severity, and a component with nothing known against it.
 *
 * <p>The word beside the number is the **CVSS band for that score**, derived from it. The
 * GHSA rating that used to sit here is a different scale from a different source — GitHub
 * calls 6.5 "MODERATE" where CVSS calls it "Medium" — so it has its own column now rather
 * than masquerading as this number's label.
 */
export function SeverityCell({ row }: { row: FindingRow }) {
  if (!row.osvId) {
    return <span className="text-muted">—</span>;
  }
  if (row.severityScore === null) {
    return (
      <span className="severity" data-band="none">
        <strong>?</strong>
        <span className="severity__label">unscored</span>
      </span>
    );
  }
  const band = bandOf(row.severityScore);
  return (
    <span className="severity" data-band={band}>
      <strong>{row.severityScore.toFixed(1)}</strong>
      <span className="severity__label">{BAND_LABELS[band]}</span>
    </span>
  );
}

/** Something that happened on this machine — the reader's own clock is the right one. */
export function formatTimestamp(iso: string | null): string {
  if (!iso) return 'never';
  const date = new Date(iso);
  return Number.isNaN(date.getTime())
    ? iso
    : date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

/**
 * An advisory's publication date: UTC, and a date rather than a timestamp.
 *
 * Not the same kind of value as the one above, and formatting it as one was wrong in a way
 * that only showed up off-centre. OSV publishes real times — GHSA-5gvw-p9qm-jgwh is
 * 2026-07-21T22:00:43Z — so the local zone moved the date across midnight for anyone east of
 * UTC: in Berlin it read "22.07.2026, 00:00", a day after the record it links to on osv.dev,
 * and the 00:00 made it look as though no time had been recorded at all.
 *
 * The time of day an advisory was filed says nothing for triage either, where the question
 * is how old it is. Dropping it costs nothing and removes the whole class of off-by-one-day
 * disagreement with the source. The export writes the same value, in the same zone.
 */
export function formatAdvisoryDate(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime())
    ? iso
    : date.toLocaleDateString(undefined, { dateStyle: 'medium', timeZone: 'UTC' });
}
