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

/**
 * CISA's Known Exploited Vulnerabilities mark.
 *
 * <p>Three empty states, and the cell distinguishes the two that vary per row. A clean
 * component or a finding with no CVE cannot be looked up at all — CISA's catalogue is keyed by
 * CVE, and 3% of Maven advisories and 97.5% of npm ones carry none — so those read as "no CVE
 * to check", which is the question being unaskable rather than answered. A finding with a CVE
 * that is simply not in the catalogue reads as "not listed".
 *
 * <p><b>Neither is a clearance, and the wording is doing that work.</b> Absence from KEV means
 * CISA has not confirmed exploitation, not that the flaw cannot be exploited — a column of "No"
 * would claim the second. The third state, a catalogue nobody has downloaded, is identical on
 * every row at once and is stated once above the table instead.
 */
export function KevCell({ row }: { row: FindingRow }) {
  if (!row.cveId) {
    return (
      <span className="text-muted" title="No CVE — CISA's catalogue is keyed by CVE, so this cannot be looked up">
        —
      </span>
    );
  }
  if (!row.kevListedOn) {
    return (
      <span
        className="text-muted kev--unlisted"
        title="Not in CISA's catalogue. That means exploitation has not been confirmed, not that it cannot be exploited."
      >
        not listed
      </span>
    );
  }

  // Risk colour, because this is a risk statement — the rule the scope badges were repointed to
  // keep true. It is also rare enough (4 of 212 CVEs on a real SBOM) not to compete with the
  // severity column for attention.
  const mark = (
    <span className="kev" data-listed="true">
      <span className="kev__mark">
        <strong>Exploited</strong>
        {row.kevRansomware && (
          <span
            className="kev__ransomware"
            title="CISA has confirmed use in a ransomware campaign"
          >
            ransomware
          </span>
        )}
      </span>
      <span className="kev__since">since {row.kevListedOn}</span>
    </span>
  );

  return row.kevUrl ? (
    <a href={row.kevUrl} target="_blank" rel="noreferrer" className="kev__link">
      {mark}
    </a>
  ) : (
    mark
  );
}

/**
 * The EPSS probability, with the percentile that makes it readable.
 *
 * <p>Both numbers, because either alone says less than the file does: 0.033 reads as negligible
 * where "87th percentile" says it is worse than most of what you own.
 *
 * <p>Deliberately uncoloured. It is a likelihood, not a severity, and a third risk-coloured
 * scale on one row would compete with the two that already disagree with each other. There is
 * also no threshold to colour it against — FIRST states plainly that 0.10 is commonly cited and
 * carries no special authority, so any band we drew would be our invention presented as theirs.
 */
export function EpssCell({ row }: { row: FindingRow; detailed?: boolean }) {
  if (!row.cveId) {
    return (
      <span className="text-muted" title="No CVE — EPSS scores CVEs, so this cannot be looked up">
        —
      </span>
    );
  }
  if (row.epssScore === null) {
    return (
      <span className="text-muted" title="EPSS does not score this CVE">
        unscored
      </span>
    );
  }
  return (
    <span
      className="epss"
      title={`EPSS ${row.epssScore} — the probability this vulnerability is exploited in the next 30 days`}
    >
      <strong>{formatEpssProbability(row.epssScore)}</strong>
      {row.epssPercentile !== null && (
        // The word is spelled out rather than abbreviated to "87th". Two bare numbers stacked
        // in one cell both read as probabilities, and a reader has no way to tell that the
        // second one is a rank among all scored CVEs rather than a second likelihood.
        <span
          className="epss__percentile"
          title={
            `Higher than ${Math.round(row.epssPercentile * 100)}% of every CVE EPSS scores` +
            ' worldwide. A global rank, not a rank within this SBOM — it would be the same' +
            ' number on an empty one.'
          }
        >
          {/* Keep the visible label compact. The tooltip states that this is a global rank
              among CVEs scored by EPSS, rather than a rank within the current SBOM. */}
          {formatPercentile(row.epssPercentile)} percentile
        </span>
      )}
    </span>
  );
}

/**
 * As a percentage, with precision that follows the magnitude.
 *
 * <p>Fixed precision fails at both ends: two decimals renders 0.99999 as "100.00%", which
 * overstates a probability that is not 1, and zero decimals renders most of the set as "0%",
 * which is the one reading this column must not produce. Anything below a tenth of a percent
 * says so rather than rounding to nothing.
 */
export function formatEpssProbability(score: number): string {
  const percent = score * 100;
  // Nothing may round up to 100%. Caught by verifying rather than by reading: 0.99945 went
  // through toFixed(0) and rendered as "100%", which states certainty about a probability that
  // is not 1 — the exact overstatement this branch was written to prevent, defeated by the one
  // below it. Anything above 99% therefore keeps a decimal, and the very top says ">99.9%"
  // rather than naming a number it would have to round to reach.
  if (percent > 99.9) return '>99.9%';
  if (percent >= 99) return `${Math.floor(percent * 10) / 10}%`;
  if (percent >= 10) return `${percent.toFixed(0)}%`;
  if (percent >= 0.1) return `${percent.toFixed(1)}%`;
  // And nothing may round down to zero either: "0%" would read as "will not happen".
  return '<0.1%';
}

/** "87th" — the ordinal reads as a rank, which is what a percentile is. */
export function formatPercentile(percentile: number): string {
  const rank = Math.round(percentile * 100);
  // Same rule as the probability above: a percentile below 1 must not be rendered as the top
  // of the scale. EPSS does publish an exact 1.0, and that one is genuinely "100th".
  if (rank >= 100 && percentile < 1) return '>99th';
  const remainderTen = rank % 10;
  const remainderHundred = rank % 100;
  let suffix = 'th';
  if (remainderTen === 1 && remainderHundred !== 11) suffix = 'st';
  else if (remainderTen === 2 && remainderHundred !== 12) suffix = 'nd';
  else if (remainderTen === 3 && remainderHundred !== 13) suffix = 'rd';
  return `${rank}${suffix}`;
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
