import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';

import { ApiError, SCOPE_LABELS, fetchComponentDetail } from '../api/client';
import type { ComponentDetail, FindingRow } from '../api/client';
import { ComponentFinder } from '../components/ComponentFinder';
import { DependencyGraphPanel } from '../components/DependencyGraphPanel';
import { UpgradePathsPanel } from '../components/UpgradePathsPanel';
import { describePurl, shortNameOf } from '../components/purl';
import { SeverityCell, formatAdvisoryDate, formatTimestamp } from '../findings/presentation';
import { neighbourAfterClosing, useSboms } from '../sboms/SbomProvider';
import type { InspectorTabs } from '../sboms/SbomProvider';
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
 * The components open in this session, browser-style.
 *
 * <p>Deliberately not a `tablist`, though it looks like one. ARIA reserves that pattern for
 * a set of panels one of which is shown, and the panels below it are already that — nesting
 * a second tablist whose "panel" is the whole page, with a close button inside each tab,
 * would be a worse description of this than a list of links to the same page.
 */
function OpenComponents({
  tabs,
  current,
  contentLoading,
  onSelect,
  onClose,
}: {
  tabs: InspectorTabs;
  current: string | null;
  /**
   * Whether the panel below is still fetching. Not used to render anything — it is the one
   * reflow this strip can be told about directly rather than having to observe, and the
   * observer that would otherwise catch it cannot be relied on alone. See the effect below.
   */
  contentLoading: boolean;
  onSelect: (purl: string) => void;
  onClose: (purl: string) => void;
}) {
  // The strip is one non-wrapping row, so an activation driven from anywhere but a click on
  // the tab itself — a row's Inspect link, a close activating its neighbour, restoring the
  // active tab after a route change — can land on a tab that is scrolled out of sight.
  //
  // Deliberately not scrollIntoView: it scrolls every scrollable ancestor, so on a long
  // dependency tree it can yank the page as well as the strip. Adjusting the strip's own
  // scroll by the overshoot touches nothing else.
  //
  // useLayoutEffect, and not a requestAnimationFrame inside a plain effect, which was the
  // first attempt. rAF does not fire while the page is hidden — measured, `visibilityState`
  // 'hidden' and the callback never ran — so a tab opened in a background browser tab stayed
  // scrolled out of view until something else moved it. useLayoutEffect runs synchronously
  // after the DOM is updated whatever the page's visibility, and reading a rect inside it
  // flushes layout, so the measurement is of the arrangement being corrected.
  const activeRef = useRef<HTMLLIElement>(null);
  useLayoutEffect(() => {
    const tab = activeRef.current;
    const strip = tab?.parentElement;
    if (!tab || !strip) return;

    const reveal = () => {
      const tabBox = tab.getBoundingClientRect();
      const stripBox = strip.getBoundingClientRect();
      if (tabBox.left < stripBox.left) {
        strip.scrollLeft -= stripBox.left - tabBox.left;
      } else if (tabBox.right > stripBox.right) {
        strip.scrollLeft += tabBox.right - stripBox.right;
      }
    };

    reveal();

    // Once is not enough, and the case that proves it is not window resizing. Arriving back
    // on this page renders the strip before the panel below has loaded, so the page has no
    // vertical scrollbar yet; when the panel arrives the scrollbar takes ~15px off this
    // column, and the tab that was flush against the right edge is clipped by exactly that.
    // Measured. `contentLoading` in the deps is that specific reflow, told rather than
    // observed; the observer covers the ones nothing can announce — the window resizing, the
    // SBOM sidebar collapsing — without either of them needing to know this exists.
    const observer = new ResizeObserver(reveal);
    observer.observe(strip);
    return () => observer.disconnect();
    // `tabs.open` and not `current` alone: a tab that is not already open is appended only
    // once its component has loaded, so at the moment the active purl changes there is no
    // element to reveal yet — the list changing is the event that matters, and it is also
    // what shifts every other tab's position when one is evicted.
  }, [current, tabs.open, contentLoading]);

  if (tabs.open.length === 0) return null;

  return (
    <ul className="component-tabs" aria-label="Open components">
      {tabs.open.map((purl) => {
        const name = shortNameOf(purl);
        const { version } = describePurl(purl);
        return (
          <li
            key={purl}
            ref={purl === current ? activeRef : undefined}
            className="component-tab"
            data-active={purl === current}
          >
            <button
              type="button"
              className="component-tab__label"
              /* The full purl on hover: the label drops the group, and two artifacts can
                 share a name across groups. */
              title={purl}
              aria-current={purl === current ? 'true' : undefined}
              onClick={() => onSelect(purl)}
            >
              <span className="component-tab__name">{name}</span>
              {/* The version is not decoration here. An SBOM routinely carries the same
                  library at two versions across modules — that is precisely the case the
                  Inspector is for — and two tabs both reading "jackson-databind" would be
                  indistinguishable. Muted and second, as the finder already renders it. */}
              {version && <span className="component-tab__version mono">{version}</span>}
            </button>
            <button
              type="button"
              className="component-tab__close"
              aria-label={`Close ${name} ${version}`.trim()}
              onClick={() => onClose(purl)}
            >
              ×
            </button>
          </li>
        );
      })}
    </ul>
  );
}

/** Stable, so an SBOM with nothing open does not re-render the page on every pass. */
const NO_TABS: InspectorTabs = { open: [], active: null, recent: [] };

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
  const { selected, inspectorTabs, openInspectorTab, closeInspectorTab } = useSboms();
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
  const tabs = (sbomId ? inspectorTabs[sbomId] : null) ?? NO_TABS;

  // The patch this design supersedes kept a last-purl-per-SBOM map in localStorage. Nothing
  // reads it now, and leaving it behind would strand state in every browser that ran that
  // build — the kind of orphan that costs someone an hour when they next go looking.
  useEffect(() => {
    try {
      window.localStorage.removeItem('sbomscope.inspector.lastPurl');
    } catch {
      // Private browsing. Not being able to tidy up is not a reason to fail a render.
    }
  }, []);

  // The URL names the active tab, so a refresh and every plain "Inspect" link elsewhere in
  // the app keep working unchanged. Reaching this page without one — the top-nav item, which
  // carries no purl — restores whatever this SBOM had active instead of landing on a blank
  // panel, which is the bug this whole item exists for.
  useEffect(() => {
    if (!sbomId || purl || !tabs.active) return;
    setParams({ purl: tabs.active }, { replace: true });
  }, [sbomId, purl, tabs.active, setParams]);

  const closeTab = useCallback(
    (closing: string) => {
      if (!sbomId) return;
      closeInspectorTab(sbomId, closing);
      // Only the active tab moves the URL; closing any other one leaves you where you are.
      if (closing !== purl) return;
      const neighbour = neighbourAfterClosing(tabs.open, closing);
      setParams(neighbour ? { purl: neighbour } : {}, { replace: true });
    },
    [sbomId, purl, tabs.open, closeInspectorTab, setParams],
  );

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
        if (cancelled) return;
        setDetail(result);
        // Opened only once the component is known to be in this document, so a stale purl
        // in the URL can never put a tab there that cannot be opened.
        openInspectorTab(sbomId, purl);
      })
      .catch((e: unknown) => {
        if (cancelled) return;
        setDetail(null);

        // A component that is not in this SBOM is a different document, not a failure —
        // the normal way to hit it is switching SBOMs with a purl still in the URL. Drop
        // it and fall back to this SBOM's own tabs, rather than showing the raw 404.
        if (e instanceof ApiError && e.status === 404) {
          closeInspectorTab(sbomId, purl);
          setParams({}, { replace: true });
          return;
        }

        setError(messageOf(e));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [sbomId, purl, openInspectorTab, closeInspectorTab, setParams]);

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
          {/* Above the panel tabs rather than beside the finder: a strip of browser-style
              tabs needs the width, and the 280px side column has none to give. It also
              sits directly above the content it switches, which is what makes it read as
              tabs at all. Only the active tab's panel is mounted — the bump probe runs
              server-side and hydrates from the backend's cached progress when its tab
              comes back, so rendering the others would only multiply the polling. */}
          <OpenComponents
            tabs={tabs}
            current={purl}
            contentLoading={loading}
            onSelect={select}
            onClose={closeTab}
          />

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

                {tab === 'upgrades' && purl && (
                  <UpgradePathsPanel sbomId={selected.id} purl={purl} />
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
