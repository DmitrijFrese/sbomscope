import { useState } from 'react';

import { SEVERITY_LABELS, sbomDocumentUrl } from '../api/client';
import type { Sbom, SeverityBand } from '../api/client';
import { useSboms } from '../sboms/SbomProvider';
import { SbomUploadForm } from './SbomUploadForm';
import { ChevronLeftIcon, ChevronRightIcon, DownloadIcon } from './icons';

function formatUploadedAt(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime())
    ? iso
    : date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

/**
 * The four scored CVSS bands worth triaging on. Unscored remains on the findings page: it is
 * a qualitatively different state rather than another rung on the CVSS scale.
 */
const CARD_BANDS: SeverityBand[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

/**
 * What is known about this SBOM's risk, or that nothing is.
 *
 * <p>Never-scanned is stated rather than rendered as zeros. An unexamined document has no
 * critical vulnerabilities in exactly the same way an unexamined one has none, and a card
 * that cannot tell the two apart is the same conflation the schema, the bands and the scan
 * table all exist to prevent.
 */
function SbomRisk({ sbom }: { sbom: Sbom }) {
  // Said before the counts rather than beside them: while a scan is running the numbers are
  // whatever was known beforehand, and "0 critical" from a document still being read is the
  // same false reassurance "Not scanned" exists to prevent.
  if (sbom.scanning) {
    return <span className="sbom-card__meta">Scanning…</span>;
  }
  if (sbom.scannedComponents === 0) {
    return <span className="sbom-card__meta">Not scanned</span>;
  }

  return (
    <span className="sbom-card__risk">
      {CARD_BANDS.map((band) => {
        const count = sbom.severityCounts[band] ?? 0;
        return (
          // Empty bands are dimmed rather than dropped, so "none found" stays visibly
          // different from "not measured" — the rule the severity chips already follow.
          <span
            key={band}
            className="risk-count"
            data-band={band.toLowerCase()}
            data-empty={count === 0}
          >
            <strong>{count}</strong> {SEVERITY_LABELS[band].toLowerCase()}
          </span>
        );
      })}
    </span>
  );
}

interface SbomSidebarProps {
  collapsed: boolean;
  onToggleCollapsed: () => void;
}

/** Lists uploaded SBOMs. Selection drives both main views. */
export function SbomSidebar({ collapsed, onToggleCollapsed }: SbomSidebarProps) {
  const { sboms, selected, loading, error, select, remove } = useSboms();
  const [uploading, setUploading] = useState(false);
  const [removeError, setRemoveError] = useState<string | null>(null);

  // Collapsed leaves a rail rather than nothing at all: a sidebar that vanishes entirely
  // gives no clue how to bring it back, and the count is worth keeping in view.
  if (collapsed) {
    return (
      <aside className="sidebar sidebar--rail" aria-label="Uploaded SBOMs">
        <button
          type="button"
          className="icon-button"
          onClick={onToggleCollapsed}
          aria-expanded={false}
          aria-label="Expand the SBOM list"
          title="Expand the SBOM list"
        >
          <ChevronRightIcon className="navitem__icon" />
        </button>
        <span className="sidebar__rail-label" aria-hidden="true">
          SBOMs
        </span>
        <span className="sidebar__rail-count">{sboms.length}</span>
      </aside>
    );
  }

  async function onRemove(id: string, filename: string) {
    if (!window.confirm(`Delete ${filename}? Its components and analysis are removed too.`)) {
      return;
    }
    setRemoveError(null);
    try {
      await remove(id);
    } catch (e) {
      setRemoveError(e instanceof Error ? e.message : 'Could not delete that SBOM.');
    }
  }

  return (
    <aside className="sidebar" aria-label="Uploaded SBOMs">
      <div className="sidebar__header">
        <h2 className="sidebar__title">SBOMs</h2>
        <div className="sidebar__header-actions">
          <button
            type="button"
            className="button button--small"
            onClick={() => setUploading((open) => !open)}
            aria-expanded={uploading}
          >
            {uploading ? 'Close' : 'Upload'}
          </button>
          <button
            type="button"
            className="icon-button"
            onClick={onToggleCollapsed}
            aria-expanded={true}
            aria-label="Collapse the SBOM list"
            title="Collapse the SBOM list"
          >
            <ChevronLeftIcon className="navitem__icon" />
          </button>
        </div>
      </div>

      {uploading && <SbomUploadForm onDone={() => setUploading(false)} />}

      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      {removeError && (
        <p className="form-error" role="alert">
          {removeError}
        </p>
      )}

      {loading && sboms.length === 0 && <p className="sidebar__note">Loading…</p>}

      {!loading && sboms.length === 0 && !uploading && (
        <div className="sidebar__empty">
          <div className="empty-state">
            <p style={{ margin: 0 }}>No SBOMs uploaded yet.</p>
          </div>
        </div>
      )}

      {sboms.length > 0 && (
        <ul className="sidebar__list">
          {sboms.map((sbom) => {
            const isSelected = selected?.id === sbom.id;
            return (
              <li key={sbom.id} className="sbom-row">
                <button
                  type="button"
                  className="sbom-card"
                  aria-current={isSelected ? 'true' : undefined}
                  data-selected={isSelected}
                  onClick={() => select(sbom.id)}
                >
                  <span className="sbom-card__name">{sbom.filename}</span>
                  <span className="sbom-card__meta">
                    {formatUploadedAt(sbom.uploadedAt)} · {sbom.componentCount} components
                  </span>
                  <span className="sbom-card__meta">CycloneDX {sbom.specVersion}</span>
                  <SbomRisk sbom={sbom} />
                  {sbom.workspacePath && (
                    <span className="sbom-card__meta sbom-card__path" title={sbom.workspacePath}>
                      {sbom.workspacePath}
                    </span>
                  )}
                </button>

                <div className="sbom-row__actions">
                  {/* A plain link, not a fetch: the browser does the download and takes the
                      filename from the response, which is the name it was uploaded under. */}
                  <a
                    className="icon-button sbom-row__action"
                    href={sbomDocumentUrl(sbom.id)}
                    download
                    aria-label={`Download ${sbom.filename}`}
                    title="Download the uploaded document"
                  >
                    <DownloadIcon />
                  </a>

                  <button
                    type="button"
                    className="icon-button sbom-row__action"
                    onClick={() => onRemove(sbom.id, sbom.filename)}
                    aria-label={`Delete ${sbom.filename}`}
                    title="Delete"
                  >
                    ×
                  </button>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </aside>
  );
}
