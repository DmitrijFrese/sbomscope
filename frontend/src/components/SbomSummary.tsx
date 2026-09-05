import { SEVERITY_LABELS } from '../api/client';
import type { Sbom, SeverityBand } from '../api/client';
import { CARD_BANDS } from '../sboms/severityRollup';

/**
 * What a document says about itself, wherever it is shown.
 *
 * <p>Lifted out of `SidebarTree` when the diff page needed the same card. The two were about
 * to be near-copies, and a near-copy of a card carrying <em>counts</em> is worse than most:
 * the sidebar and the diff would each be free to decide what "not scanned" looks like, and a
 * reader comparing the two panels would have no way to tell a real difference between two
 * documents from a difference between two renderers.
 *
 * <p>Deliberately presentational. The sidebar's card is a button that selects a document and
 * carries drag handles, badges and a row menu; none of that belongs here, so this holds only
 * the parts that answer "which document is this, and what is in it".
 */

export function formatUploadedAt(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime())
    ? iso
    : date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

/** A set of severity counts as small chips, worst first. */
export function SeverityChips({ counts }: { counts: Partial<Record<SeverityBand, number>> }) {
  const total = CARD_BANDS.reduce((sum, band) => sum + (counts[band] ?? 0), 0);
  if (total === 0) return null;
  return (
    <span className="sbom-card__risk">
      {CARD_BANDS.map((band) => {
        const count = counts[band] ?? 0;
        return (
          <span key={band} className="risk-count" data-band={band.toLowerCase()} data-empty={count === 0}>
            <strong>{count}</strong> {SEVERITY_LABELS[band].toLowerCase()}
          </span>
        );
      })}
    </span>
  );
}

/**
 * Scanning, never scanned, or the counts — three states, and the middle one matters.
 *
 * <p>"Not scanned" is not "no vulnerabilities": a document nobody has looked at must not read
 * as a clean one, which is the same distinction the Clean band draws one level in.
 */
export function SbomRisk({ sbom }: { sbom: Sbom }) {
  if (sbom.scanning) return <span className="sbom-card__meta">Scanning…</span>;
  if (sbom.scannedComponents === 0) return <span className="sbom-card__meta">Not scanned</span>;
  return <SeverityChips counts={sbom.severityCounts} />;
}

/** The document's own lines: name, when it arrived, how big it is, and what is in it. */
export function SbomSummary({ sbom }: { sbom: Sbom }) {
  return (
    <>
      <span className="sbom-card__name">{sbom.filename}</span>
      <span className="sbom-card__meta">
        {formatUploadedAt(sbom.uploadedAt)} · {sbom.componentCount} components
      </span>
      <span className="sbom-card__meta">CycloneDX {sbom.specVersion}</span>
      <SbomRisk sbom={sbom} />
    </>
  );
}
