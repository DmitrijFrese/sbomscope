import { useCallback, useEffect, useState } from 'react';

import {
  SCOPE_LABELS,
  SEVERITY_BANDS,
  SEVERITY_LABELS,
  VULNERABLE_BANDS,
  fetchFindings,
  runScan,
} from '../api/client';
import type { FindingQuery, FindingRow, ScanStatus, SeverityBand, SortField } from '../api/client';
import { ExportMenu } from '../components/ExportMenu';
import { Pagination } from '../components/Pagination';
import { ScanProgress } from '../components/ScanProgress';
import { ScanReadinessHint } from '../components/ScanReadinessHint';
import { ViewOptionsMenu } from '../components/ViewOptionsMenu';
import { COLUMNS, COMPACT_DEFAULT, reviveColumns } from '../findings/columns';
import type { ColumnId } from '../findings/columns';
import { useSboms } from '../sboms/SbomProvider';
import { usePersistentState } from '../state/persisted';

const PAGE_SIZES = [20, 50, 100, 200];

const DEFAULT_QUERY: FindingQuery = {
  sort: 'SEVERITY',
  ascending: false,
  filter: '',
  // Opens on what needs attention; tick "No vulnerabilities" to bring the rest of the
  // inventory into the same table.
  severities: VULNERABLE_BANDS,
  pageSize: 20,
  page: 0,
};

/**
 * How the table is being looked at is a preference and persists. Which page you were on
 * is not: restoring page 7 against whichever SBOM happens to be selected now lands
 * somewhere arbitrary, and the rows there have nothing to do with where you left off.
 */
function reviveQuery(stored: FindingQuery): FindingQuery {
  return {
    ...DEFAULT_QUERY,
    ...stored,
    // Written by an older build, or edited by hand — an empty selection would render an
    // empty table that reads as a broken screen.
    severities:
      Array.isArray(stored.severities) && stored.severities.length > 0
        ? stored.severities
        : VULNERABLE_BANDS,
    pageSize: PAGE_SIZES.includes(stored.pageSize) ? stored.pageSize : DEFAULT_QUERY.pageSize,
    page: 0,
  };
}

/** Something that happened on this machine — the reader's own clock is the right one. */
function formatDate(iso: string | null): string {
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
function formatAdvisoryDate(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime())
    ? iso
    : date.toLocaleDateString(undefined, { dateStyle: 'medium', timeZone: 'UTC' });
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : 'Something went wrong.';
}

/** Standard CVSS bands, matching how the backend filters. */
function bandOf(score: number): string {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

const BAND_LABELS: Record<string, string> = {
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
function SeverityCell({ row }: { row: FindingRow }) {
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

/** Long free text: clamped so one verbose advisory cannot set the height of every row. */
function TruncatedCell({ value, className }: { value: string | null; className?: string }) {
  if (!value) {
    return <span className="text-muted">—</span>;
  }
  return (
    <span className={`truncate ${className ?? ''}`} title={value}>
      {value}
    </span>
  );
}

/** One cell, chosen by column id. Kept beside the column list it switches over. */
function renderCell(column: ColumnId, row: FindingRow) {
  switch (column) {
    case 'component':
      return (
        <>
          {row.registryUrl ? (
            <a className="mono" href={row.registryUrl} target="_blank" rel="noreferrer">
              {row.coordinates}
            </a>
          ) : (
            <span className="mono">{row.coordinates}</span>
          )}
        </>
      );
    case 'version':
      return <span className="mono">{row.version ?? '—'}</span>;
    // "root" for the component the document describes; it is an application component, but
    // saying so distinguishes the project itself from its sibling modules.
    case 'scope':
      return row.root ? (
        <span className="badge badge--root">root</span>
      ) : (
        <span className={`badge badge--scope-${row.scope.toLowerCase()}`}>
          {SCOPE_LABELS[row.scope]}
        </span>
      );
    case 'osvId':
      return row.osvUrl ? (
        <a href={row.osvUrl} target="_blank" rel="noreferrer">
          {row.osvId}
        </a>
      ) : (
        <span className="text-muted">no known vulnerabilities</span>
      );
    case 'ghsaRating':
      return row.severityRating ? (
        <span className="badge">{row.severityRating}</span>
      ) : (
        <span className="text-muted">—</span>
      );
    case 'cveId':
      if (row.cveUrl) {
        return (
          <a href={row.cveUrl} target="_blank" rel="noreferrer">
            {row.cveId}
          </a>
        );
      }
      // A finding with no CVE is a real state, not missing data: 3% of the Maven set are
      // GHSA-only or MAL-* entries. Distinguished from a clean component's empty cell.
      return row.osvId ? (
        <span className="badge">no CVE</span>
      ) : (
        <span className="text-muted">—</span>
      );
    case 'severity':
      return <SeverityCell row={row} />;
    case 'cvssVersion':
      return row.cvssVersion ? (
        <span className="mono">{row.cvssVersion.replace('CVSS_', 'CVSS ')}</span>
      ) : (
        <span className="text-muted">—</span>
      );
    case 'cvssVector':
      return <TruncatedCell value={row.cvssVector} className="mono cell-vector" />;
    case 'fixedVersion':
      return (
        <span className="mono">{row.osvId ? (row.fixedVersion ?? 'no fix') : '—'}</span>
      );
    case 'published':
      return <>{row.publishedAt ? formatAdvisoryDate(row.publishedAt) : '—'}</>;
    case 'summary':
      return <TruncatedCell value={row.summary} className="cell-summary" />;
    case 'purl':
      return <TruncatedCell value={row.purl} className="mono cell-purl" />;
  }
}

/** Clickable column header that also announces the sort state to assistive technology. */
function SortableHeader({
  label,
  field,
  query,
  onSort,
}: {
  label: string;
  field: SortField;
  query: FindingQuery;
  onSort: (field: SortField) => void;
}) {
  const active = query.sort === field;
  const direction = active ? (query.ascending ? 'ascending' : 'descending') : 'none';

  return (
    <th scope="col" aria-sort={direction}>
      <button type="button" className="sort-header" onClick={() => onSort(field)}>
        {label}
        <span className="sort-header__arrow" aria-hidden="true">
          {active ? (query.ascending ? '▲' : '▼') : '↕'}
        </span>
      </button>
    </th>
  );
}


export function VulnerabilitiesPage() {
  const { selected, reload } = useSboms();
  const [status, setStatus] = useState<ScanStatus | null>(null);
  const [query, setQuery] = usePersistentState<FindingQuery>(
    'findings.query',
    DEFAULT_QUERY,
    reviveQuery,
  );
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [details, setDetails] = usePersistentState<boolean>('findings.details', false);
  const [compactColumns, setCompactColumns] = usePersistentState<ColumnId[]>(
    'findings.compactColumns',
    COMPACT_DEFAULT,
    reviveColumns,
  );

  // Details is every column; Compact is the chosen subset, always in canonical order.
  const visibleColumns = details
    ? COLUMNS
    : COLUMNS.filter((column) => compactColumns.includes(column.id));

  const load = useCallback(async (sbomId: string, current: FindingQuery) => {
    setLoading(true);
    setError(null);
    try {
      setStatus(await fetchFindings(sbomId, current));
    } catch (e) {
      setError(messageOf(e));
    } finally {
      setLoading(false);
    }
  }, []);

  // Keyed on the id rather than the object: reloading the SBOM list hands back a new
  // object for the same document, and depending on that would refetch the whole table
  // every time the sidebar refreshed.
  const selectedId = selected?.id ?? null;

  useEffect(() => {
    if (!selectedId) {
      setStatus(null);
      return;
    }
    void load(selectedId, query);
  }, [selectedId, query, load]);

  /** Any change other than paging returns to the first page. */
  function update(patch: Partial<FindingQuery>) {
    setQuery((current) => ({ ...current, page: 0, ...patch }));
  }

  function toggleSort(field: SortField) {
    setQuery((current) => ({
      ...current,
      page: 0,
      sort: field,
      ascending: current.sort === field ? !current.ascending : field === 'COMPONENT',
    }));
  }

  function toggleSeverity(band: SeverityBand) {
    setQuery((current) => {
      const next = current.severities.includes(band)
        ? current.severities.filter((b) => b !== band)
        : [...current.severities, band];
      // Clearing every band would show nothing at all, which reads as a broken screen.
      return { ...current, page: 0, severities: next.length === 0 ? VULNERABLE_BANDS : next };
    });
  }

  async function scan() {
    if (!selected) return;
    setScanning(true);
    setError(null);
    try {
      await runScan(selected.id);
      await load(selected.id, query);
      // The sidebar cards carry the same counts from the SBOM list, so a scan that did not
      // refresh it would leave two views of one document disagreeing on screen at once.
      await reload();
    } catch (e) {
      setError(messageOf(e));
    } finally {
      setScanning(false);
    }
  }

  if (!selected) {
    return (
      <>
        <div className="page-header">
          <h1>Vulnerabilities</h1>
          <p>Known vulnerabilities for the selected SBOM.</p>
        </div>
        <div className="empty-state">
          <p style={{ margin: 0 }}>Upload an SBOM, or select one from the sidebar.</p>
        </div>
      </>
    );
  }

  const rows = status?.rows ?? [];
  const filtered = status?.filteredCount ?? 0;
  const neverScanned = status !== null && status.scannedComponents === 0;
  const pageCount = Math.max(1, Math.ceil(filtered / query.pageSize));
  const firstOnPage = filtered === 0 ? 0 : query.page * query.pageSize + 1;
  const lastOnPage = Math.min(filtered, (query.page + 1) * query.pageSize);

  const ready = status?.readiness.ready ?? false;

  return (
    <>
      {/* The scan action sits with the title rather than on its own row: it is the one
          thing you do to this SBOM, and it was previously costing a full band of vertical
          space above the table it acts on. */}
      <div className="page-header page-header--split">
        <div className="page-header__identity">
          <h1>{selected.filename}</h1>
          {/* Everything describing the document, on one line. The headline count and the
              scan date used to be two further paragraphs below the table's summary block,
              which spent three bands of vertical space saying what fits in one. */}
          <p>
            {selected.componentCount} components · CycloneDX {selected.specVersion}
            {status && !neverScanned && (
              <>
                {' · '}
                <strong>{status.findingCount}</strong> known{' '}
                {status.findingCount === 1 ? 'vulnerability' : 'vulnerabilities'}
                {' · scanned '}
                {formatDate(status.lastScannedAt)}
              </>
            )}
            {status && neverScanned && ' · never scanned'}
            {selected.workspacePath ? ` · ${selected.workspacePath}` : ''}
          </p>
        </div>

        <div className="page-header__actions">
          {status && <ScanReadinessHint readiness={status.readiness} />}
          <button
            type="button"
            className="button button--primary"
            onClick={scan}
            disabled={scanning || !ready}
          >
            {scanning ? 'Scanning…' : neverScanned ? 'Scan for vulnerabilities' : 'Re-scan'}
          </button>
        </div>
      </div>

      {scanning && <ScanProgress componentCount={selected.componentCount} />}

      {status && !status.scanningEnabled && (
        <div className="notice">
          Scanning is switched off, so nothing has been checked. Turn on{' '}
          <strong>Use OSV-Scanner</strong> in Settings to analyse this SBOM.
        </div>
      )}

      {status?.scanningEnabled && neverScanned && (
        <div className="notice">
          This SBOM has not been scanned yet. An empty list below means “not checked”, not
          “no vulnerabilities”.
        </div>
      )}

      {status?.scanningEnabled && !neverScanned && status.stale && (
        <div className="notice notice--warn">
          These results are more than {status.staleAfterDays} days old. New advisories are
          published constantly — re-scan for an up-to-date answer.
        </div>
      )}

      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}

      <div className="controls">
        <input
          type="search"
          className="toolbar__search"
          placeholder="Filter by component, advisory or CVE…"
          value={query.filter}
          onChange={(event) => update({ filter: event.target.value })}
          aria-label="Filter rows"
        />

        {/* The chips and the severity counts described the same six bands, so showing both
            was saying everything twice — and the counts had to live somewhere, which cost a
            band of vertical space wherever they went. Merged: each chip carries its own
            total, which also makes the numbers clickable.

            The count is what selecting that band puts on screen, and it does not move with
            the filter — it describes the SBOM, so the chips stay comparable however the view
            is narrowed. */}
        <div className="chips" role="group" aria-label="Severity">
          {SEVERITY_BANDS.map((band) => {
            const count = status?.severityCounts?.[band];
            return (
              <button
                key={band}
                type="button"
                className="chip"
                data-band={band.toLowerCase()}
                aria-pressed={query.severities.includes(band)}
                onClick={() => toggleSeverity(band)}
              >
                {SEVERITY_LABELS[band]}
                {count !== undefined && <span className="chip__count">{count}</span>}
              </button>
            );
          })}
        </div>

        {/* Display and export live together on the right; the left of this row is
            filtering. */}
        <span className="controls__end">
          <ViewOptionsMenu
            details={details}
            onDetailsChange={setDetails}
            compact={compactColumns}
            onColumnsChange={setCompactColumns}
          />
          <ExportMenu
            sbomId={selected.id}
            query={query}
            visibleCount={rows.length}
            totalCount={filtered}
            visibleColumns={visibleColumns.map((column) => column.id)}
          />
        </span>
      </div>

      {loading && <p>Loading…</p>}

      {!loading && filtered === 0 && (
        <div className="empty-state">
          <p style={{ margin: 0 }}>
            {neverScanned
              ? 'Nothing has been scanned yet.'
              : 'Nothing matches the current filter.'}
          </p>
        </div>
      )}

      {filtered > 0 && (
        <>
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  {/* Not a column: absent from the picker, from Details, and from the
                      export, where Excel supplies its own numbering. It exists to give a
                      row a name you can say out loud. */}
                  <th scope="col" className="rownum" aria-label="Row number">
                    #
                  </th>
                  {visibleColumns.map((column) =>
                    column.sort ? (
                      <SortableHeader
                        key={column.id}
                        label={column.label}
                        field={column.sort}
                        query={query}
                        onSort={toggleSort}
                      />
                    ) : (
                      <th key={column.id} scope="col">
                        {column.label}
                      </th>
                    ),
                  )}
                </tr>
              </thead>
              <tbody>
                {rows.map((row, index) => (
                  <tr key={`${row.purl}-${row.osvId ?? 'clean'}`}>
                    {/* Numbered across the whole result, not per page, so "row 437" still
                        means something on page 22. */}
                    <td className="rownum">{firstOnPage + index}</td>
                    {visibleColumns.map((column) => (
                      <td key={column.id}>{renderCell(column.id, row)}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Rows-per-page belongs with the pages it sizes, below the table, which is
              also where a reader ends up after scrolling through one. */}
          <div className="pagination">
            <label className="pagesize">
              Rows
              <select
                value={query.pageSize}
                onChange={(event) => update({ pageSize: Number(event.target.value) })}
              >
                {PAGE_SIZES.map((size) => (
                  <option key={size} value={size}>
                    {size}
                  </option>
                ))}
              </select>
            </label>

            <span className="toolbar__count">
              {firstOnPage}–{lastOnPage} of {filtered}
            </span>

            <Pagination
              page={query.page}
              pageCount={pageCount}
              onPage={(page) => setQuery((c) => ({ ...c, page }))}
            />
          </div>
        </>
      )}
    </>
  );
}
