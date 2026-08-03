import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

import { fetchComponentGraph, fetchComponentRoutePage } from '../api/client';
import type { ComponentGraph, GraphNode, GraphTreeNode, ModuleRoutes } from '../api/client';

/** How deep the descendants tree stands open before you have to ask. */
const OPEN_TO_DEPTH = 2;
const MAX_DISPLAYED_ROUTES = 10_000;

function inspectHref(node: GraphNode): string | null {
  return node.purl ? `/component-inspector?purl=${encodeURIComponent(node.purl)}` : null;
}

/**
 * One step of a route, or one node of the tree.
 *
 * <p>Every node is a link to itself, because the question that follows "who pulls this in"
 * is almost always about one of the answers.
 */
function Node({
  node,
  current,
}: {
  node: GraphNode;
  current?: boolean;
}) {
  const href = inspectHref(node);
  const label = (
    <>
      <span className="mono">{node.coordinates}</span>
      {node.version && <span className="graph-node__version mono">{node.version}</span>}
    </>
  );

  return (
    <span
      className="graph-node"
      data-vulnerable={node.vulnerable}
      data-current={!!current}
    >
      {href && !current ? <Link to={href}>{label}</Link> : label}
      {node.vulnerable && (
        <span className="graph-node__flag" title="Has known vulnerabilities">
          !
        </span>
      )}
    </span>
  );
}

/**
 * One route from a module down to the component, read left to right.
 *
 * <p><b>The module itself is dropped.</b> The backend sends each route module → … →
 * component inclusive, and the heading directly above already names the module — repeating it
 * as step 1 of every route spends the widest column on the word the reader has just read.
 *
 * <p>The card header names the immediate predecessor of the inspected component. That is the
 * declaration point represented by this SBOM route; the displayed target version remains the
 * resolved version and is not claimed to be a literal version written in that component's POM.
 */
export function routeDeclaration(route: GraphNode[]): GraphNode | null {
  return route.at(-2) ?? null;
}

export function totalRouteCount(modules: ModuleRoutes[]): number {
  return modules.reduce((total, module) => total + module.totalRoutes, 0);
}

function Route({ route, targetPurl, number }: { route: GraphNode[]; targetPurl: string; number: number }) {
  const steps = route.slice(1);
  const declaration = routeDeclaration(route);

  // Defensive: a route consisting only of the module would leave nothing to draw. Reachable
  // in principle if a module ever reached itself; targetIsOwnCode covers the real case.
  if (steps.length === 0) {
    return null;
  }

  return (
    <li className="route-card">
      <div className="route-card__header">
        <span className="route-card__number">Route {number}</span>
        {declaration && (
          <span className="route-card__declaration">
            {declaration.scope === 'APPLICATION'
              ? 'Declared by your module'
              : 'Declared by intermediate component'}:{' '}
            <span className="mono">{declaration.coordinates}</span>
            {declaration.version && <span className="mono"> {declaration.version}</span>}
          </span>
        )}
      </div>
      <div className="route-card__path">
        {steps.map((step, index) => (
          <span key={`${step.bomRef}-${index}`} className="route__step">
            {index > 0 && (
              <span className="route__arrow" aria-hidden="true">
                →
              </span>
            )}
            <Node node={step} current={step.purl === targetPurl && index === steps.length - 1} />
          </span>
        ))}
      </div>
    </li>
  );
}

function ModulePanel({
  module: entry,
  targetPurl,
  loadMore,
}: {
  module: ModuleRoutes;
  targetPurl: string;
  loadMore: (entry: ModuleRoutes) => Promise<void>;
}) {
  const shown = entry.routes.length;
  const [loadingMore, setLoadingMore] = useState(false);
  const [moreError, setMoreError] = useState<string | null>(null);
  const remaining = entry.totalRoutes - shown;

  async function handleLoadMore() {
    setLoadingMore(true);
    setMoreError(null);
    try {
      await loadMore(entry);
    } catch (error) {
      setMoreError(error instanceof Error ? error.message : 'Could not load more routes.');
    } finally {
      setLoadingMore(false);
    }
  }

  return (
    <section className="module-routes">
      <h3 className="module-routes__name">
        <Node node={entry.module} />
        {entry.module.root && <span className="badge badge--root">root</span>}
      </h3>

      {shown === 0 ? (
        /* Defensive mismatch: reachability found the module but complete route enumeration
           produced none. The module still appears because which modules are affected is the
           more important claim. */
        <p className="panel__hint">
          Reached from here, but no route could be materialised.
        </p>
      ) : (
        <ul className="route-list">
          {entry.routes.map((route, index) => (
            <Route key={index} route={route} targetPurl={targetPurl} number={index + 1} />
          ))}
        </ul>
      )}

      {entry.totalRoutes > shown && shown < MAX_DISPLAYED_ROUTES && (
        <div className="module-routes__more">
          <span>
            Showing the {shown} shortest of {entry.truncated ? `${entry.totalRoutes}+` : entry.totalRoutes} routes.
          </span>
          <button className="button" type="button" disabled={loadingMore} onClick={handleLoadMore}>
            {loadingMore ? 'Loading…' : `Show next ${Math.min(100, remaining)}`}
          </button>
        </div>
      )}
      {entry.totalRoutes > shown && shown >= MAX_DISPLAYED_ROUTES && (
        <p className="module-routes__more">
          Showing the first {shown} routes. Further route bodies are omitted by the display safety limit;
          the total above remains exact.
        </p>
      )}
      {moreError && <p className="form-error" role="alert">{moreError}</p>}
    </section>
  );
}

function Tree({ node, depth }: { node: GraphTreeNode; depth: number }) {
  const hasChildren = node.children.length > 0;

  // No scope badge here. Everything below the component is something it brought with it,
  // and the depth already says how directly — a word repeated on every row of a tree is
  // noise competing with the two markers that do carry information.
  const label = (
    <>
      <Node node={node.node} />
      {node.repeated && (
        <span className="badge" title="Expanded elsewhere in this tree">
          also above
        </span>
      )}
      {node.cyclic && (
        <span className="badge badge--warn" title="This component is already on the path above">
          cycle
        </span>
      )}
    </>
  );

  if (!hasChildren) {
    return <li className="deptree__leaf">{label}</li>;
  }

  return (
    <li>
      <details open={depth < OPEN_TO_DEPTH}>
        <summary>
          {label}
          <span className="deptree__count">{node.children.length}</span>
        </summary>
        <ul className="deptree">
          {node.children.map((child) => (
            <Tree key={child.node.bomRef} node={child} depth={depth + 1} />
          ))}
        </ul>
      </details>
    </li>
  );
}

/**
 * Where a component comes from, and what it drags in.
 *
 * <p>Two shapes, because they are two questions. Upward is a route — the chain from one of
 * your modules down to here — and every module that reaches the component is listed, since
 * the set of your modules affected is the scope of the problem. Downward is a tree, because
 * what a library pulls in is a set to browse rather than a route to trace.
 */
export function DependencyGraphPanel({ sbomId, purl }: { sbomId: string; purl: string }) {
  const [graph, setGraph] = useState<ComponentGraph | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    fetchComponentGraph(sbomId, purl)
      .then((result) => {
        if (!cancelled) setGraph(result);
      })
      .catch((e: unknown) => {
        if (!cancelled) {
          setGraph(null);
          setError(e instanceof Error ? e.message : 'Could not build the dependency graph.');
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [sbomId, purl]);

  if (loading) return <p>Loading…</p>;
  if (error) {
    return (
      <p className="form-error" role="alert">
        {error}
      </p>
    );
  }
  if (!graph) return null;

  const modules = graph.reachedFrom;
  const totalPaths = totalRouteCount(modules);

  async function loadMore(entry: ModuleRoutes) {
    const page = await fetchComponentRoutePage(sbomId, purl, entry.module.bomRef, entry.routes.length);
    setGraph((current) => current && ({
      ...current,
      reachedFrom: current.reachedFrom.map((candidate) => candidate.module.bomRef === page.moduleBomRef
        ? { ...candidate, routes: [...candidate.routes, ...page.routes], totalRoutes: page.totalRoutes }
        : candidate),
    }));
  }

  return (
    <>
      <section>
        <h2 className="panel__title">Reached from</h2>

        {graph.targetIsOwnCode ? (
          <p className="panel__hint">
            This is your own code, not a dependency — there is nothing above it in the graph
            and no version to upgrade to.
          </p>
        ) : modules.length === 0 ? (
          /* A component nothing reaches is a real state of a real document, not an error. */
          <p className="panel__hint">
            Nothing in this SBOM depends on this component. It is present in the document
            without being reachable from any of your own code.
          </p>
        ) : (
          <>
            {/* The headline, before any route is read: how much of your own code carries
                this. That is what decides whether a finding is a morning's work or a
                quarter's. */}
            <p className="panel__hint">
              {graph.ownModuleCount > 1 ? (
                <>
                  Pulled in by{' '}
                  <strong>
                    {modules.length} of your {graph.ownModuleCount}
                  </strong>{' '}
                  modules.
                </>
              ) : (
                <>Pulled in by your own code.</>
              )}{' '}
              Total paths: <strong>{totalPaths}</strong>.
            </p>
            {modules.map((entry) => (
              <ModulePanel
                key={entry.module.bomRef}
                module={entry}
                targetPurl={purl}
                loadMore={loadMore}
              />
            ))}
          </>
        )}
      </section>

      <section className="deptree-section">
        <h2 className="panel__title">Pulls in</h2>
        {!graph.tree || graph.tree.children.length === 0 ? (
          <p className="panel__hint">This component has no dependencies of its own.</p>
        ) : (
          <ul className="deptree deptree--root">
            {graph.tree.children.map((child) => (
              <Tree key={child.node.bomRef} node={child} depth={1} />
            ))}
          </ul>
        )}
      </section>
    </>
  );
}
