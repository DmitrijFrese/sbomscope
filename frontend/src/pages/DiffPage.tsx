import { useEffect, useState } from 'react';
import type { DragEvent, ReactNode } from 'react';
import { Link } from 'react-router-dom';

import { diffExportUrl, fetchDiff, SEVERITY_LABELS, VULNERABLE_BANDS } from '../api/client';
import type { DiffFilter, DiffResult, DiffRow, DiffSide, DiffChange, DiffSort, Sbom } from '../api/client';
import { ExportLinksMenu } from '../components/ExportMenu';
import { SbomSummary } from '../components/SbomSummary';
import { SearchField } from '../components/SearchField';
import { dragTypeFor } from '../components/useSidebarDrag';
import { useSboms } from '../sboms/SbomProvider';

const CHANGE_LABELS: Record<DiffChange, string> = {
  ADDED: 'Added',
  REMOVED: 'Removed',
  VERSION_CHANGED: 'Changed',
  UNCHANGED: 'Unchanged',
};

const CHANGE_MARKS: Record<DiffChange, string> = {
  ADDED: '+',
  REMOVED: '−',
  VERSION_CHANGED: '↔',
  UNCHANGED: '=',
};

const DEFAULT_FILTER: DiffFilter = {
  sort: 'COORDINATES',
  ascending: true,
  filter: '',
  regex: false,
  negate: false,
};

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : 'Something went wrong.';
}

const SBOM_DRAG_TYPE = dragTypeFor('sbom');

/**
 * One side of the comparison, and a drop target for it.
 *
 * <p>The body is the sidebar's own card — see `SbomSummary`. Two panels describing the same
 * documents in two different vocabularies would leave a reader working out whether a
 * difference between them was real, and the counts are exactly what someone choosing a
 * baseline wants to see before pressing Compare.
 *
 * <p>Dropping is additive: the row menu's "Compare as left/right" stays, because HTML5
 * drag-and-drop has no keyboard equivalent at all — the same rule that kept "Move to…" beside
 * dragging in the sidebar.
 */
function SelectionCard({
  side,
  sbom,
  onDropSbom,
}: {
  side: 'left' | 'right';
  sbom: Sbom | null;
  onDropSbom: (sbomId: string) => void;
}) {
  const [over, setOver] = useState(false);

  // `getData` is blocked during dragover, so the *type* is what identifies the payload while
  // the pointer is still moving. A folder being dragged carries a different type and is
  // therefore refused by the cursor rather than after the drop.
  const carriesSbom = (event: DragEvent) => event.dataTransfer.types.includes(SBOM_DRAG_TYPE);

  return (
    <div
      className="diff-selection__card"
      data-missing={!sbom}
      data-drop-target={over}
      onDragOver={(event) => {
        if (!carriesSbom(event)) return;
        event.preventDefault();
        // Must match the source's `effectAllowed`, which the sidebar sets to 'move'. A
        // mismatched effect makes the browser refuse the drop with no visible reason.
        event.dataTransfer.dropEffect = 'move';
        setOver(true);
      }}
      onDragLeave={() => setOver(false)}
      onDrop={(event) => {
        setOver(false);
        if (!carriesSbom(event)) return;
        event.preventDefault();
        const id = event.dataTransfer.getData(SBOM_DRAG_TYPE);
        if (id) onDropSbom(id);
      }}
    >
      <span className="diff-selection__side">
        {side === 'left' ? 'Left · baseline' : 'Right · new state'}
      </span>
      {sbom ? (
        <SbomSummary sbom={sbom} />
      ) : (
        <span className="diff-selection__missing">Not chosen — drop a document here</span>
      )}
    </div>
  );
}

function ChangeBadge({ change }: { change: DiffChange }) {
  return (
    <span className="diff-change" data-change={change.toLowerCase()}>
      <span aria-hidden="true">{CHANGE_MARKS[change]}</span>
      {CHANGE_LABELS[change]}
    </span>
  );
}

function idsOf(side: DiffSide | null): Set<string> {
  return new Set(side?.cveIds ?? []);
}

export function findingDelta(row: Pick<DiffRow, 'left' | 'right'>): {
  gained: string[];
  lost: string[];
} {
  const left = idsOf(row.left);
  const right = idsOf(row.right);
  return {
    gained: [...right].filter((id) => !left.has(id)),
    lost: [...left].filter((id) => !right.has(id)),
  };
}

/**
 * The advisory ids of one delta, each linked to its own record.
 *
 * <p>The destination comes from the side that carries the identifier — `advisoryUrls` is built
 * by the backend, so a CVE reaches NVD and an OSV-only advisory reaches osv.dev, exactly as the
 * findings table's own cells do. An identifier with no link is still shown, as plain text: a
 * missing URL is a reason to render less, never to drop the finding.
 */
function AdvisoryList({ ids, from }: { ids: string[]; from: DiffSide | null }) {
  if (ids.length === 0) return <span className="mono">None</span>;
  return (
    <span className="mono diff-delta__ids">
      {ids.map((id) => {
        const url = from?.advisoryUrls?.[id];
        return url ? (
          <a key={id} href={url} target="_blank" rel="noreferrer noopener">
            {id}
          </a>
        ) : (
          <span key={id}>{id}</span>
        );
      })}
    </span>
  );
}

export function FindingDeltaCell({ row }: { row: Pick<DiffRow, 'left' | 'right'> }) {
  const { gained, lost } = findingDelta(row);
  const hasFindings = (row.left?.cveIds.length ?? 0) > 0 || (row.right?.cveIds.length ?? 0) > 0;

  if (!hasFindings) {
    return <span className="text-muted">No findings on either side</span>;
  }
  if (gained.length === 0 && lost.length === 0) {
    return <span className="text-muted">Same CVEs on both sides</span>;
  }

  return (
    <span className="diff-delta">
      <span className="diff-delta__line" data-kind="gained">
        <strong>Gained</strong>
        {/* Gained ids exist on the right, lost ids on the left — each list asks the side that
            actually holds it where its advisories point. */}
        <AdvisoryList ids={gained} from={row.right} />
      </span>
      <span className="diff-delta__line" data-kind="lost">
        <strong>Lost</strong>
        <AdvisoryList ids={lost} from={row.left} />
      </span>
    </span>
  );
}

/**
 * A version, and a way into the Component Inspector for the component behind it.
 *
 * <p>The Inspector reads the *selected* document, and the two sides of a diff are usually not
 * the selected one — so the link selects the document it belongs to on the way through. Without
 * that, clicking the left version would open the Inspector against whatever happened to be
 * selected and show a different component's story with the right heading over it.
 *
 * <p>Plain text where the side has no purl: a component the document did not identify has
 * nothing to inspect, and a link that lands on an empty panel is worse than no link.
 */
function Version({ side, sbomId }: { side: DiffSide | null; sbomId: string }) {
  const { select } = useSboms();
  if (!side) return <span className="text-muted">—</span>;
  if (!side.purl) return <span className="mono">{side.version ?? '—'}</span>;
  return (
    <Link
      className="mono"
      to={`/component-inspector?purl=${encodeURIComponent(side.purl)}`}
      onClick={() => select(sbomId)}
      title="Inspect this component"
    >
      {side.version ?? '—'}
    </Link>
  );
}

/**
 * Split columns, and only split.
 *
 * <p>An inline/split toggle shipped with the first version because that is what code-diff
 * tools offer. It does not earn its place here: a code diff puts two versions of a *line*
 * side by side, where this table's two versions are two short strings that fit in two columns
 * with room to spare — so "inline" only stacked the same two values into one cell and made
 * the rows taller. Removed rather than kept as a preference nobody would revisit.
 */
/** Clickable diff-table header that also announces the sort state to assistive technology. */
function SortableHeader({
  label,
  field,
  query,
  onSort,
}: {
  label: string;
  field: DiffSort;
  query: DiffFilter;
  onSort: (field: DiffSort) => void;
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

function ResultsTable({
  rows,
  leftId,
  rightId,
  query,
  onSort,
}: {
  rows: DiffRow[];
  leftId: string;
  rightId: string;
  query: DiffFilter;
  onSort: (field: DiffSort) => void;
}) {
  return (
    <div className="table-scroll">
      <table className="data-table diff-table" data-view="split">
        <thead>
          <tr>
            <SortableHeader label="Change" field="CHANGE" query={query} onSort={onSort} />
            <SortableHeader label="Coordinates" field="COORDINATES" query={query} onSort={onSort} />
            <th scope="col">Left version</th>
            <th scope="col">Right version</th>
            <th scope="col">Finding delta</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr
              key={`${row.coordinates}-${row.left?.version ?? ''}-${row.right?.version ?? ''}-${index}`}
              data-change={row.change.toLowerCase()}
            >
              <td><ChangeBadge change={row.change} /></td>
              <td className="mono">{row.coordinates}</td>
              <td><Version side={row.left} sbomId={leftId} /></td>
              <td><Version side={row.right} sbomId={rightId} /></td>
              <td><FindingDeltaCell row={row} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/**
 * One document's vulnerability total, or null when nobody has scanned it.
 *
 * <p>Null rather than zero, and the caller must render it as such: an unscanned document
 * reporting "0 vulnerabilities" beside a scanned one is the single ambiguity this application
 * is most careful about, and a subtraction would launder it into a confident delta.
 */
function vulnerabilityTotal(sbom: Sbom): number | null {
  if (sbom.scannedComponents === 0) return null;
  return VULNERABLE_BANDS.reduce((sum, band) => sum + (sbom.severityCounts[band] ?? 0), 0);
}

function signed(delta: number): string {
  return delta > 0 ? `+${delta}` : `${delta}`;
}

/**
 * The same left → right for each vulnerable band.
 *
 * <p>Every band, including the ones at zero on both sides, so the parts visibly add up to the
 * total above them — the rule the findings page's own chips follow. Unscored is among them:
 * an advisory with no CVSS score is a vulnerability, and dropping it here would leave a
 * breakdown that does not sum to its own headline.
 */
function SeverityBreakdown({ left, right }: { left: Sbom; right: Sbom }) {
  if (left.scannedComponents === 0 || right.scannedComponents === 0) return null;
  return (
    <span className="diff-stat__bands">
      {VULNERABLE_BANDS.map((band) => {
        const before = left.severityCounts[band] ?? 0;
        const after = right.severityCounts[band] ?? 0;
        const delta = after - before;
        return (
          <span key={band} className="diff-stat__band" data-band={band.toLowerCase()}>
            <span className="diff-stat__band-name">{SEVERITY_LABELS[band]}</span>
            <span className="diff-stat__pair">
              {before} <span aria-hidden="true">→</span> {after}
            </span>
            <span
              className="diff-stat__delta"
              data-tone="risk"
              data-direction={delta === 0 ? 'flat' : delta > 0 ? 'up' : 'down'}
            >
              {delta === 0 ? '±0' : signed(delta)}
            </span>
          </span>
        );
      })}
    </span>
  );
}

/** Left → right for one measurement, with the delta only where both sides have a number. */
function DeltaStat({
  label,
  left,
  right,
  tone,
  breakdown,
}: {
  label: string;
  left: number | null;
  right: number | null;
  /** `risk` colours the direction; `count` does not — growth is not a regression. */
  tone: 'risk' | 'count';
  /** Rendered below the pair, where one number is not the whole answer. */
  breakdown?: ReactNode;
}) {
  const known = left !== null && right !== null;
  const delta = known ? right - left : 0;
  return (
    <div>
      <dt>{label}</dt>
      <dd>
        <span className="diff-stat__pair">
          {left ?? '—'} <span aria-hidden="true">→</span> {right ?? '—'}
        </span>
        {known && delta !== 0 && (
          <span
            className="diff-stat__delta"
            data-tone={tone}
            data-direction={delta > 0 ? 'up' : 'down'}
          >
            {signed(delta)}
          </span>
        )}
        {known && delta === 0 && <span className="diff-stat__delta" data-direction="flat">±0</span>}
        {!known && <span className="diff-stat__delta" data-direction="unknown">not scanned</span>}
        {breakdown}
      </dd>
    </div>
  );
}

function Summary({ result, left, right }: { result: DiffResult; left: Sbom; right: Sbom }) {
  return (
    <section className="diff-summary" aria-labelledby="diff-summary-title">
      <div>
        <h2 id="diff-summary-title">Whole comparison</h2>
        <p>These totals cover both documents and do not change with the row filter.</p>
      </div>
      {/* The two headline numbers a reader wants before reading any row: did the inventory
          grow, and did the vulnerability count fall. Taken from the documents themselves
          rather than from the diff rows, so they agree with the sidebar's own cards.

          The vulnerability total carries its own breakdown, because the total on its own can
          hide the answer: trading two criticals for three lows is a good day and reads as
          "+1" without it. The parts are every vulnerable band, so they always add up to the
          headline beside them. */}
      <dl className="diff-summary__counts diff-summary__stats">
        <DeltaStat
          label="Components"
          left={left.componentCount}
          right={right.componentCount}
          tone="count"
        />
        <DeltaStat
          label="Vulnerabilities"
          left={vulnerabilityTotal(left)}
          right={vulnerabilityTotal(right)}
          tone="risk"
          breakdown={<SeverityBreakdown left={left} right={right} />}
        />
      </dl>
      <dl className="diff-summary__counts">
        {(Object.keys(CHANGE_LABELS) as DiffChange[]).map((change) => (
          <div key={change}>
            <dt>{CHANGE_LABELS[change]}</dt>
            <dd>{result.summary.changes[change]}</dd>
          </div>
        ))}
        <div>
          <dt>CVEs gained</dt>
          <dd>{result.summary.cveIdsGained}</dd>
        </div>
        <div>
          <dt>CVEs lost</dt>
          <dd>{result.summary.cveIdsLost}</dd>
        </div>
      </dl>
    </section>
  );
}

export function DiffPage() {
  const { diffSelection, selectForDiff, swapDiffSides, diffRun, rememberDiffRun } = useSboms();
  const { left, right } = diffSelection;

  // The comparison itself lives above the router, so leaving this page and coming back does
  // not discard an answer that took a real query to produce. The filter travels with it for
  // the same reason: re-typing a pattern to see the result you already had is the same loss
  // one step earlier.
  const held = diffRun && diffRun.leftId === left?.id && diffRun.rightId === right?.id
    ? diffRun
    : null;
  const result = held?.result ?? null;

  const [query, setQuery] = useState<DiffFilter>(held?.filter ?? DEFAULT_FILTER);
  const [loading, setLoading] = useState(false);
  const [showUnchanged, setShowUnchanged] = useState(false);
  const [error, setError] = useState<{ message: string; fromPattern: boolean } | null>(null);

  /**
   * Once a comparison exists, the filter re-runs it by itself.
   *
   * <p>It did not, and the result was a filter that looked broken: typing narrowed nothing,
   * because the rows are filtered in SQL and only `Compare` asked for them again. Nothing on
   * screen said so. Every other filter in this product applies as you type, so this one being
   * a two-step act was a surprise with no reason behind it.
   *
   * <p>**`Compare` still exists and still guards the expensive half.** Choosing two documents
   * runs nothing until it is pressed — B24's rule, and this does not touch it. What changed is
   * that narrowing an answer already on screen no longer counts as asking a new question.
   *
   * <p>Debounced, because the filter is a text field and a request per keystroke would put a
   * comparison of two whole documents behind every character.
   */
  const hasRun = held !== null;
  // True while the rows on screen were produced by exactly this filter. Without it, arriving
  // back on the page would immediately re-run a comparison already in hand — which is the
  // thing holding the result in the session was for.
  const rowsMatchFilter = held !== null
    && held.filter.filter === query.filter
    && held.filter.regex === query.regex
    && held.filter.negate === query.negate
    && held.filter.sort === query.sort
    && held.filter.ascending === query.ascending;

  useEffect(() => {
    if (!hasRun || rowsMatchFilter || !left || !right) return undefined;
    const timer = window.setTimeout(() => void compare(), 350);
    return () => window.clearTimeout(timer);
    // `compare` closes over the current query and sides; re-running it is exactly the intent.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query.filter, query.regex, query.negate, query.sort, query.ascending,
    hasRun, rowsMatchFilter, left?.id, right?.id]);
  const missing = [left ? null : 'left', right ? null : 'right'].filter(Boolean) as string[];
  const unchangedCount = result?.rows.filter((row) => row.change === 'UNCHANGED').length ?? 0;
  const exportVisibleCount = result?.rows.filter((row) => row.change !== 'UNCHANGED').length ?? 0;
  const exportAllCount = result
    ? Object.values(result.summary.changes).reduce((total, count) => total + count, 0)
    : 0;
  const visibleRows = result?.rows.filter((row) => showUnchanged || row.change !== 'UNCHANGED') ?? [];

  async function compare() {
    if (!left || !right) return;
    setLoading(true);
    setError(null);
    try {
      rememberDiffRun({
        leftId: left.id,
        rightId: right.id,
        filter: query,
        result: await fetchDiff(left.id, right.id, query),
      });
    } catch (e) {
      // As on the findings page, a half-typed rejected pattern leaves the last good answer
      // visible and puts the message on the field that produced it.
      setError({
        message: messageOf(e),
        fromPattern: query.regex && query.filter.length > 0,
      });
    } finally {
      setLoading(false);
    }
  }

  function toggleSort(sort: DiffSort) {
    setQuery((current) => ({
      ...current,
      sort,
      ascending: current.sort === sort ? !current.ascending : true,
    }));
  }

  const header = (
    <div className="page-header">
      <h1>SBOM Diff</h1>
      <p>Left is the baseline; right is the new state. Added and removed are relative to left.</p>
    </div>
  );

  const selection = (
    <section className="diff-selection" aria-label="SBOMs to compare">
      <SelectionCard side="left" sbom={left} onDropSbom={(id) => selectForDiff('left', id)} />
      <button
        type="button"
        className="button button--small diff-selection__swap"
        onClick={swapDiffSides}
        disabled={!left && !right}
        title="Exchange the baseline and the new state"
      >
        {/* Double-headed: this control exchanges the two sides, where a single head would
            claim a direction it does not have. The single arrows elsewhere on this page —
            `73 → 61` in the summary, `1.2.3 → 1.5.34` in a row — are the opposite case, a
            left-to-right transition, and stay as they are. */}
        <span aria-hidden="true">↔</span>
        <span className="visually-hidden">Swap sides</span>
      </button>
      <SelectionCard side="right" sbom={right} onDropSbom={(id) => selectForDiff('right', id)} />
      <button
        type="button"
        className="button button--primary"
        disabled={!left || !right || loading}
        onClick={() => void compare()}
      >
        {loading ? 'Comparing…' : 'Compare'}
      </button>
    </section>
  );

  // Every hook is above this branch, and must stay there: a hook added below it would change
  // the hook count as soon as the second document is chosen, and React would blank the route
  // with nothing in the console to say why.
  if (!left || !right) {
    return (
      <>
        {header}
        {selection}
        <div className="empty-state diff-empty">
          <p>
            Drag a document from the sidebar onto the missing {missing.join(' and ')}{' '}
            {missing.length === 1 ? 'side' : 'sides'}, or use{' '}
            <strong>Compare as left</strong> and <strong>Compare as right</strong> in its{' '}
            <strong>⋯</strong> menu.
          </p>
          <p>
            Left is what you had; right is what you have now. The same document may sit on both
            sides — that comparison is legal and answers all-unchanged.
          </p>
        </div>
      </>
    );
  }

  return (
    <>
      {header}
      {selection}

      {error && !error.fromPattern && (
        <p className="form-error" role="alert">{error.message}</p>
      )}

      {result && <Summary result={result} left={left} right={right} />}

      {/* Below the summary and directly above the table, because that is what it narrows.
          Sitting at the top of the page it read as part of choosing the documents, which is
          the wrong claim: the summary above it deliberately does *not* move with this. */}
      <div className="controls diff-controls">
        <SearchField
          value={query.filter}
          onValueChange={(filter) => setQuery((current) => ({ ...current, filter }))}
          regex={query.regex}
          onRegexChange={(regex) => setQuery((current) => ({ ...current, regex }))}
          negate={query.negate}
          onNegateChange={(negate) => setQuery((current) => ({ ...current, negate }))}
          placeholder="Filter by coordinates, version or CVE…"
          ariaLabel="Filter diff rows"
          note={error?.fromPattern ? error.message : null}
          inputClassName="toolbar__search"
        />

        <span className="controls__end diff-controls__view">
          <label className="diff-unchanged-toggle">
            <input
              type="checkbox"
              checked={showUnchanged}
              onChange={(event) => setShowUnchanged(event.target.checked)}
            />
            Show unchanged
          </label>
          {result && !showUnchanged && (
            <span className="toolbar__count">
              {unchangedCount} unchanged {unchangedCount === 1 ? 'row' : 'rows'} hidden
            </span>
          )}
          {result && (
            <ExportLinksMenu
              visibleUrl={diffExportUrl(left.id, right.id, query, 'visible')}
              allUrl={diffExportUrl(left.id, right.id, query, 'all')}
              visibleCount={exportVisibleCount}
              totalCount={exportAllCount}
              visibleHint="current filter, unchanged excluded"
              allHint="every comparison row, unchanged included"
            />
          )}
        </span>
      </div>

      {!result && !loading && (
        <div className="empty-state diff-empty">
          <p style={{ margin: 0 }}>Select Compare to run this comparison.</p>
        </div>
      )}

      {result && result.rows.length === 0 && (
        <div className="empty-state diff-empty">
          <p style={{ margin: 0 }}>Nothing matches the current filter.</p>
        </div>
      )}

      {result && result.rows.length > 0 && visibleRows.length === 0 && (
        <div className="empty-state diff-empty">
          <p style={{ margin: 0 }}>
            All {unchangedCount} {unchangedCount === 1 ? 'row is' : 'rows are'} unchanged and hidden.
          </p>
        </div>
      )}

      {visibleRows.length > 0 && (
        <ResultsTable rows={visibleRows} leftId={left.id} rightId={right.id}
          query={query} onSort={toggleSort} />
      )}
    </>
  );
}
