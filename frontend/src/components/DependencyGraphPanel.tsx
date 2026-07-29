import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

import { fetchComponentGraph } from '../api/client';
import type { ComponentGraph, GraphNode, GraphTreeNode, ModuleRoutes } from '../api/client';

/** How deep the descendants tree stands open before you have to ask. */
const OPEN_TO_DEPTH = 2;

function inspectHref(node: GraphNode): string | null {
  return node.purl ? `/component-inspector?purl=${encodeURIComponent(node.purl)}` : null;
}

/**
 * One step of a route, or one node of the tree.
 *
 * <p>Every node is a link to itself, because the question that follows "who pulls this in"
 * is almost always about one of the answers.
 */
function Node({ node, current }: { node: GraphNode; current?: boolean }) {
  const href = inspectHref(node);
  const label = (
    <>
      <span className="mono">{node.coordinates}</span>
      {node.version && <span className="graph-node__version mono">{node.version}</span>}
    </>
  );

  return (
    <span className="graph-node" data-vulnerable={node.vulnerable} data-current={!!current}>
      {href && !current ? <Link to={href}>{label}</Link> : label}
      {node.vulnerable && (
        <span className="graph-node__flag" title="Has known vulnerabilities">
          !
        </span>
      )}
    </span>
  );
}

/** module → … → component, read left to right. */
function Route({ route, targetPurl }: { route: GraphNode[]; targetPurl: string }) {
  return (
    <li className="route">
      {route.map((step, index) => (
        <span key={`${step.bomRef}-${index}`} className="route__step">
          {index > 0 && (
            <span className="route__arrow" aria-hidden="true">
              →
            </span>
          )}
          <Node node={step} current={step.purl === targetPurl && index === route.length - 1} />
        </span>
      ))}
    </li>
  );
}

function ModulePanel({ module: entry, targetPurl }: { module: ModuleRoutes; targetPurl: string }) {
  const shown = entry.routes.length;
  return (
    <section className="module-routes">
      <h3 className="module-routes__name">
        <Node node={entry.module} />
        {entry.module.root && <span className="badge badge--root">root</span>}
      </h3>

      {shown === 0 ? (
        /* Reachability found the module but enumeration could not produce a route within
           its budget. The module still appears — which of your modules are affected is the
           answer; by which hop is the detail. */
        <p className="panel__hint">
          Reached from here, but this graph has too many routes to enumerate.
        </p>
      ) : (
        <ul className="route-list">
          {entry.routes.map((route, index) => (
            <Route key={index} route={route} targetPurl={targetPurl} />
          ))}
        </ul>
      )}

      {entry.totalRoutes > shown && (
        <p className="module-routes__more">
          Showing the {shown} shortest of {entry.truncated ? `${entry.totalRoutes}+` : entry.totalRoutes} routes.
        </p>
      )}
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
              )}
            </p>
            {modules.map((entry) => (
              <ModulePanel key={entry.module.bomRef} module={entry} targetPurl={purl} />
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
