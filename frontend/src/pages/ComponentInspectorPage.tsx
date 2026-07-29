import { useCallback, useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';

import { SCOPE_LABELS, fetchComponentDetail } from '../api/client';
import type { ComponentDetail, FindingRow } from '../api/client';
import { ComponentFinder } from '../components/ComponentFinder';
import { DependencyGraphPanel } from '../components/DependencyGraphPanel';
import { SeverityCell, formatAdvisoryDate, formatTimestamp } from '../findings/presentation';
import { useSboms } from '../sboms/SbomProvider';
import { usePersistentState } from '../state/persisted';

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : 'Something went wrong.';
}

/** One advisory against this component, in the same terms the findings table uses. */
function Advisory({ row }: { row: FindingRow }) {
  return (
    <li className="advisory">
      <div className="advisory__head">
        <SeverityCell row={row} />
        <span className="advisory__ids">
          {row.osvUrl ? (
            <a href={row.osvUrl} target="_blank" rel="noreferrer">
              {row.osvId}
            </a>
          ) : (
            <span className="mono">{row.osvId}</span>
          )}
          {row.cveUrl ? (
            <a href={row.cveUrl} target="_blank" rel="noreferrer">
              {row.cveId}
            </a>
          ) : (
            /* A finding with no CVE is a real state, not missing data — roughly 3% of the
               Maven set are GHSA-only or MAL-* entries. */
            <span className="badge">no CVE</span>
          )}
          {row.severityRating && <span className="badge">{row.severityRating}</span>}
        </span>
      </div>

      {row.summary && <p className="advisory__summary">{row.summary}</p>}

      <dl className="advisory__facts">
        <div>
          <dt>Fixed in</dt>
          <dd className="mono">{row.fixedVersion ?? 'no fix'}</dd>
        </div>
        <div>
          <dt>Published</dt>
          <dd>{row.publishedAt ? formatAdvisoryDate(row.publishedAt) : '—'}</dd>
        </div>
        <div>
          <dt>CVSS</dt>
          <dd className="mono">
            {row.cvssVector ?? (row.cvssVersion ? row.cvssVersion.replace('CVSS_', 'CVSS ') : '—')}
          </dd>
        </div>
      </dl>
    </li>
  );
}

/**
 * What is known against this component, and — just as important — whether anything looked.
 *
 * <p>Three states, not two. An unscanned component and a clean one both have no advisories,
 * and rendering them the same way would let "nobody checked" read as "nothing wrong". That
 * is the distinction the scan table exists to preserve, and it has to survive all the way
 * out to here.
 */
function Findings({ detail }: { detail: ComponentDetail }) {
  const advisories = detail.findings.filter((row) => row.osvId);

  if (!detail.scannedAt) {
    return (
      <div className="notice notice--warn">
        This component has never been scanned, so nothing is known about it either way. Run a
        scan from the Vulnerabilities view.
      </div>
    );
  }

  if (advisories.length === 0) {
    return (
      <p className="panel__hint">
        Checked {formatTimestamp(detail.scannedAt)} — no known vulnerabilities.
      </p>
    );
  }

  return (
    <>
      <p className="panel__hint">
        {advisories.length} known {advisories.length === 1 ? 'vulnerability' : 'vulnerabilities'} ·
        checked {formatTimestamp(detail.scannedAt)}
      </p>
      <ul className="advisory-list">
        {advisories.map((row) => (
          <Advisory key={row.osvId} row={row} />
        ))}
      </ul>
    </>
  );
}

/** Not built yet, said plainly rather than shown as an empty result. */
function Planned({ children }: { children: React.ReactNode }) {
  return <p className="panel__hint panel__hint--planned">{children}</p>;
}

/**
 * The panels, as tabs.
 *
 * <p>Stacked, four panels made the page a scroll where only one of them is ever the reason
 * you came. Tabs keep the component's identity and the finder fixed while the answer
 * changes, which is what makes the finder worth its column: pick the next library and the
 * same question is already on screen for it.
 *
 * <p>"Advisories" rather than "Vulnerabilities" — the top-level view already owns that word,
 * and two different things under one name in one application is how a reader stops trusting
 * either. It is also the more accurate label: what the panel lists is advisory records, and
 * a component can have none.
 */
const TABS = [
  { id: 'advisories', label: 'Advisories' },
  { id: 'graph', label: 'Dependency graph' },
  { id: 'upgrades', label: 'Upgrade paths' },
  { id: 'workspace', label: 'Workspace usage' },
] as const;

type TabId = (typeof TABS)[number]['id'];

const TAB_IDS: readonly string[] = TABS.map((tab) => tab.id);

/**
 * The component-centred view: one library in depth, where the vulnerability table is a list
 * of many.
 *
 * <p>The selected component lives in the query string rather than in component state, so a
 * refresh keeps it and the per-row action in the findings table is an ordinary link. Keyed
 * by purl to match the table's own unit — its query collapses a library listed twice into
 * one row, so a row identifies a purl, not a component record.
 */
export function ComponentInspectorPage() {
  const { selected } = useSboms();
  const [params, setParams] = useSearchParams();
  const purl = params.get('purl');

  const [detail, setDetail] = useState<ComponentDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Persisted, and deliberately not reset when the component changes: comparing the same
  // panel across several libraries is the workflow the finder exists for.
  const [tab, setTab] = usePersistentState<TabId>('inspector.tab', 'advisories', (stored) =>
    TAB_IDS.includes(stored) ? stored : 'advisories',
  );

  const advisoryCount = detail?.findings.filter((row) => row.osvId).length ?? 0;

  const select = useCallback(
    (chosen: string) => {
      // replace: false so the browser's back button walks the components you looked at,
      // which is how you got here from a row in the first place.
      setParams({ purl: chosen });
    },
    [setParams],
  );

  const sbomId = selected?.id ?? null;

  useEffect(() => {
    if (!sbomId || !purl) {
      setDetail(null);
      setError(null);
      return;
    }

    let cancelled = false;
    setLoading(true);
    setError(null);

    fetchComponentDetail(sbomId, purl)
      .then((result) => {
        if (!cancelled) setDetail(result);
      })
      .catch((e: unknown) => {
        if (!cancelled) {
          setDetail(null);
          setError(messageOf(e));
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [sbomId, purl]);

  if (!selected) {
    return (
      <>
        <div className="page-header">
          <h1>Component Inspector</h1>
        </div>
        <div className="empty-state">
          <p style={{ margin: 0 }}>Upload an SBOM, or select one from the sidebar.</p>
        </div>
      </>
    );
  }

  const component = detail?.component;

  return (
    <>
      <div className="page-header">
        <h1>Component Inspector</h1>
        <p>
          One library in depth: which version to move to, where it comes from, and whether
          your own code touches it.
        </p>
      </div>

      <div className="inspector">
        {/* Identity above the finder, both fixed while the panel beside them changes. What
            you are looking at and how to change it belong together, and moving them out of
            the main column gives the panel back the height it needs — a dependency tree is
            long, and it was starting below a header every time. */}
        <div className="inspector__side">
          {component ? (
            <section className="panel component-identity">
              <h2 className="panel__title">
                {component.registryUrl ? (
                  <a
                    className="mono"
                    href={component.registryUrl}
                    target="_blank"
                    rel="noreferrer"
                  >
                    {component.coordinates}
                  </a>
                ) : (
                  <span className="mono">{component.coordinates}</span>
                )}
              </h2>

              <div className="component-identity__facts">
                <span className="mono">{component.version ?? 'no version'}</span>
                {component.root ? (
                  <span className="badge badge--root">root</span>
                ) : (
                  <span className={`badge badge--scope-${component.scope.toLowerCase()}`}>
                    {SCOPE_LABELS[component.scope]}
                  </span>
                )}
                {advisoryCount > 0 && (
                  <span className="badge badge--warn">
                    {advisoryCount} {advisoryCount === 1 ? 'advisory' : 'advisories'}
                  </span>
                )}
              </div>

              <p className="panel__hint mono component-identity__purl">{component.purl}</p>
            </section>
          ) : (
            /* A placeholder rather than a shimmering skeleton: nothing is loading, nothing
               is selected, and animating it would promise something is on its way. It holds
               the same height so choosing a component does not shift the finder under the
               cursor that is about to click it. */
            <section className="panel component-identity component-identity--empty">
              <p className="component-identity__none">No component selected</p>
            </section>
          )}

          <ComponentFinder sbomId={selected.id} selectedPurl={purl} onSelect={select} />
        </div>

        <div className="inspector__main">
          {error && (
            <p className="form-error" role="alert">
              {error}
            </p>
          )}

          {!purl && !error && (
            <div className="empty-state">
              <p style={{ margin: 0 }}>
                Find a library on the left, or open one from a row in the Vulnerabilities
                view.
              </p>
            </div>
          )}

          {loading && <p>Loading…</p>}

          {component && detail && (
            <>
              <div className="tabs" role="tablist" aria-label="Component panels">
                {TABS.map(({ id, label }) => (
                  <button
                    key={id}
                    type="button"
                    role="tab"
                    id={`tab-${id}`}
                    className="tab"
                    aria-selected={tab === id}
                    aria-controls={`panel-${id}`}
                    onClick={() => setTab(id)}
                  >
                    {label}
                  </button>
                ))}
              </div>

              <section
                className="panel tabpanel"
                role="tabpanel"
                id={`panel-${tab}`}
                aria-labelledby={`tab-${tab}`}
              >
                {tab === 'advisories' && <Findings detail={detail} />}

                {tab === 'graph' && purl && (
                  <DependencyGraphPanel sbomId={selected.id} purl={purl} />
                )}

                {tab === 'upgrades' && (
                  <Planned>
                    Not built yet. Will offer the latest patch on this line, the latest within
                    this major, the latest overall, and the earliest version clearing every
                    known critical and high — each with the vulnerabilities it would still
                    carry.
                  </Planned>
                )}

                {tab === 'workspace' && (
                  <Planned>
                    {selected.workspacePath
                      ? 'Not built yet. Will show where this library is referenced in your source tree.'
                      : `Not built yet — and ${selected.filename} was imported without a workspace path, so there would be nothing to scan. The other panels do not need one.`}
                  </Planned>
                )}
              </section>
            </>
          )}
        </div>
      </div>
    </>
  );
}
