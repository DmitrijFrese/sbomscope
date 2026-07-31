import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

import {
  SCOPES,
  SCOPE_LABELS,
  SEVERITY_BANDS,
  SEVERITY_LABELS,
  VULNERABLE_BANDS,
  fetchFindings,
  runScan,
} from '../api/client';
import type {
  DependencyScope,
  FindingQuery,
  FindingRow,
  ScanStatus,
  SeverityBand,
  SortField,
} from '../api/client';
import { ExportMenu } from '../components/ExportMenu';
import { Pagination } from '../components/Pagination';
import { ScanProgress } from '../components/ScanProgress';
import { ScanReadinessHint } from '../components/ScanReadinessHint';
import { SearchField } from '../components/SearchField';
import { ViewOptionsMenu } from '../components/ViewOptionsMenu';
import { ComponentIcon } from '../components/icons';
import { COLUMNS, COMPACT_DEFAULT, reviveColumns } from '../findings/columns';
import type { ColumnId } from '../findings/columns';
import {
  SeverityCell,
  formatAdvisoryDate,
  formatTimestamp,
} from '../findings/presentation';
import { useSboms } from '../sboms/SbomProvider';
import { usePersistentState } from '../state/persisted';

const PAGE_SIZES = [20, 50, 100, 200];

/**
 * How long the table waits after the last keystroke before asking the backend.
 *
 * <p>Long enough that typing a pattern is one request rather than fifteen, short enough that
 * it still reads as live. Applied to every change, not only the filter, so the field does not
 * behave differently depending on the regex toggle.
 */
const FILTER_DEBOUNCE_MS = 250;

const DEFAULT_QUERY: FindingQuery = {
  sort: 'SEVERITY',
  ascending: false,
  filter: '',
  // Off by default, deliberately: a purl is mostly dots, so always-on would silently widen
  // every filter anyone already types and start erroring on literals containing ( or [.
  regex: false,
  // Same reasoning: exclusion is a mode the reader turns on, never a guess.
  negate: false,
  // Opens on what needs attention; tick "No vulnerabilities" to bring the rest of the
  // inventory into the same table.
  severities: VULNERABLE_BANDS,
  // All three by default. Severity opens narrowed because most rows are not worth reading;
  // there is no scope that is normally not worth reading.
  scopes: SCOPES,
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
    // Written by a build before B9 existed, so absent rather than wrong — and an empty
    // selection would render an empty table for the same reason severities cannot be empty.
    scopes:
      Array.isArray(stored.scopes) && stored.scopes.length > 0 ? stored.scopes : SCOPES,
    // Absent in anything stored before B15. Defaulting to false rather than to the stored
    // value's truthiness matters: `undefined` would send the filter as a literal anyway, but
    // the toggle would render indeterminate and disagree with what the table is showing.
    regex: stored.regex === true,
    negate: stored.negate === true,
    pageSize: PAGE_SIZES.includes(stored.pageSize) ? stored.pageSize : DEFAULT_QUERY.pageSize,
    page: 0,
  };
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : 'Something went wrong.';
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
    // The two cells link to different depths on purpose: the artifact page resolves
    // whenever the artifact exists, the version page may not exist at all for a
    // vendor-patched build. A reader who lands on the artifact page can find their
    // version; one who lands on a 404 cannot.
    case 'component':
      return (
        <>
          {row.registryArtifactUrl ? (
            <a className="mono" href={row.registryArtifactUrl} target="_blank" rel="noreferrer">
              {row.coordinates}
            </a>
          ) : (
            <span className="mono">{row.coordinates}</span>
          )}
        </>
      );
    case 'version':
      if (!row.version) {
        return <span className="mono">—</span>;
      }
      return row.registryVersionUrl ? (
        <a className="mono" href={row.registryVersionUrl} target="_blank" rel="noreferrer">
          {row.version}
        </a>
      ) : (
        <span className="mono">{row.version}</span>
      );
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
  /**
   * A failure, and whether it was the filter pattern's fault.
   *
   * The two belong in different places on screen. A rejected regex is a note on the field
   * that produced it — the reader is looking at the input, mid-word — where a scan or network
   * failure is about the page. Carrying the distinction in the state rather than guessing it
   * from the message text keeps it out of the business of parsing prose.
   */
  const [error, setError] = useState<{ message: string; fromPattern: boolean } | null>(null);

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
    try {
      setStatus(await fetchFindings(sbomId, current));
      setError(null);
    } catch (e) {
      // The rows already on screen are left in place. A pattern is typed one character at a
      // time, so `^(org\.spring` exists on the way to every pattern that starts that way —
      // blanking the table at each of those would make the whole field flicker. The message
      // appears beside the input; the last answer that meant something stays visible.
      setError({
        message: messageOf(e),
        fromPattern: current.regex && current.filter.length > 0,
      });
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
    // Debounced, in both modes. It was undebounced before B15, which a LIKE could carry and
    // a regular expression cannot — and the delay is deliberately not conditional on the
    // mode, or the field would feel different depending on a toggle that is meant to change
    // only what matches. Everything else on this object (sort, bands, paging) is a click
    // rather than a keystroke, so waiting on those costs one interaction its 250ms.
    const timer = window.setTimeout(() => void load(selectedId, query), FILTER_DEBOUNCE_MS);
    return () => window.clearTimeout(timer);
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

  function toggleScope(scope: DependencyScope) {
    setQuery((current) => {
      const next = current.scopes.includes(scope)
        ? current.scopes.filter((s) => s !== scope)
        : [...current.scopes, scope];
      // Same rule as severity: unticking the last one empties the table, which reads as a
      // broken screen rather than as a filter.
      return { ...current, page: 0, scopes: next.length === 0 ? SCOPES : next };
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
      setError({ message: messageOf(e), fromPattern: false });
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
                {formatTimestamp(status.lastScannedAt)}
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

      {/* Two different statements, deliberately not merged. "A newer archive is on disk" is a
          fact about this machine that the reader can act on now; the day count is a guess that
          the world has moved on. Showing the second for the first case would point them at a
          seven-day clock that has nothing to do with why the results are behind. */}
      {status?.scanningEnabled && !neverScanned && status.stale && (
        <div className="notice notice--warn">
          {status.staleReason === 'ARCHIVE_REFRESHED' ? (
            <>
              A newer vulnerability database has been downloaded since these results were
              produced. Re-scan to check this SBOM against it.
            </>
          ) : (
            <>
              These results are more than {status.staleAfterDays} days old. New advisories are
              published constantly — re-scan for an up-to-date answer.
            </>
          )}
        </div>
      )}

      {/* A rejected pattern is reported on the field instead — see below. */}
      {error && !error.fromPattern && (
        <p className="form-error" role="alert">
          {error.message}
        </p>
      )}

      <div className="controls">
        <SearchField
          value={query.filter}
          onValueChange={(filter) => update({ filter })}
          regex={query.regex}
          onRegexChange={(regex) => update({ regex })}
          negate={query.negate}
          onNegateChange={(negate) => update({ negate })}
          placeholder="Filter by component, advisory or CVE…"
          ariaLabel="Filter rows"
          note={error?.fromPattern ? error.message : null}
          inputClassName="toolbar__search"
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
            scopes={query.scopes}
            onScopeToggle={toggleScope}
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
                  {/* Like the row number, not a column: absent from the picker, from
                      Details and from the export. Leading rather than trailing so it
                      stays reachable when a wide column set scrolls the table sideways. */}
                  <th scope="col" className="rowaction">
                    <span className="visually-hidden">Inspect</span>
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
                    <td className="rowaction">
                      <Link
                        className="icon-button"
                        to={`/component-inspector?purl=${encodeURIComponent(row.purl)}`}
                        aria-label={`Inspect ${row.coordinates}`}
                        title={`Inspect ${row.coordinates}`}
                      >
                        <ComponentIcon className="navitem__icon" />
                      </Link>
                    </td>
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
