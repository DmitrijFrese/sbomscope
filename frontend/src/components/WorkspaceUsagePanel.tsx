import { useEffect, useState } from 'react';

import { fetchWorkspaceComponentAnalysis } from '../api/client';
import type { WorkspaceComponentAnalysis, WorkspaceEvidenceStatus } from '../api/client';

const POLL_INTERVAL_MS = 1500;

const LABELS: Record<WorkspaceEvidenceStatus, string> = {
  REACHABLE: 'Reachable',
  NO_CALL_PATH: 'No bytecode call path',
  NEEDS_REVIEW: 'Needs review',
  UNAVAILABLE: 'Unavailable',
};

function inFlight(state: WorkspaceComponentAnalysis['state']): boolean {
  return state === 'QUEUED' || state === 'RUNNING';
}

/**
 * A direct call crosses from workspace bytecode straight into the component. Anything with an
 * intervening method is still useful evidence, but says that the component is reached
 * transitively rather than implying the application called it directly.
 */
export function pathKind(path: string[]): string {
  if (path.length <= 2) return 'Direct call';
  const intermediates = path.length - 2;
  return `Transitive call (${intermediates} intermediate ${intermediates === 1 ? 'method' : 'methods'})`;
}

/** The Inspector's user-visible trigger for an offline analysis of already-built bytecode. */
export function WorkspaceUsagePanel({ sbomId, purl }: { sbomId: string; purl: string }) {
  const [analysis, setAnalysis] = useState<WorkspaceComponentAnalysis | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    let timer: number | undefined;
    const load = async () => {
      try {
        const next = await fetchWorkspaceComponentAnalysis(sbomId, purl);
        if (!active) return;
        setAnalysis(next);
        setError(null);
        if (inFlight(next.state)) timer = window.setTimeout(load, POLL_INTERVAL_MS);
      } catch (reason) {
        if (active) setError(reason instanceof Error ? reason.message : 'Could not load workspace evidence.');
      }
    };
    void load();
    return () => {
      active = false;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [sbomId, purl]);

  if (error) return <p className="form-error" role="alert">{error}</p>;
  if (!analysis) return <p className="panel__hint">Checking the built workspace...</p>;

  return (
    <div className="workspace-usage">
      <p className="panel__hint">{analysis.message}</p>
      {(analysis.state === 'QUEUED' || analysis.state === 'RUNNING') && (
        <p className="panel__hint">
          SBOMscope reads existing <span className="mono">target/classes</span> and the configured read-only Maven
          cache. It does not run your workspace build.
        </p>
      )}
      {analysis.state === 'NOT_CONFIGURED' && (
        <p className="panel__hint">Attach a workspace path when uploading the SBOM to enable this view.</p>
      )}
      {analysis.evidence.map((item, index) => (
        <section className="workspace-usage__module" key={`${item.modulePath ?? 'workspace'}-${index}`}>
          <div className="workspace-usage__heading">
            <strong>{item.modulePath ?? 'Workspace inputs'}</strong>
            <span className={`badge workspace-usage__status workspace-usage__status--${item.status.toLowerCase()}`}>
              {LABELS[item.status]}
            </span>
          </div>
          <p className="panel__hint">{item.detail}</p>
          {item.methodPaths.map((path, pathIndex) => (
            <div key={pathIndex}>
              <span className="badge workspace-usage__path-kind">{pathKind(path)}</span>
              <ol className="workspace-usage__path" aria-label="Observed bytecode call path">
                {path.map((method) => <li className="mono" key={method}>{method}</li>)}
              </ol>
            </div>
          ))}
        </section>
      ))}
      {analysis.state === 'COMPLETED' && (
        <p className="panel__hint">
          A reachable path is library-use evidence, not proof that an advisory's vulnerable method was called.
          A negative answer becomes <em>Needs review</em> when Spring/AOP, proxies, reflection, or a missing input
          makes a WALA-only negative result incomplete.
        </p>
      )}
    </div>
  );
}
