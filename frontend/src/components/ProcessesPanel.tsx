import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { PROBE_FINISHED, cancelProbe, fetchProbeQueue } from '../api/client';
import type { ProbeTask } from '../api/client';
import { useSboms } from '../sboms/SbomProvider';

const POLL_INTERVAL_MS = 2000;

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : 'Something went wrong.';
}

/**
 * Elapsed time, from the instant the backend reported rather than a duration it computed —
 * a number of seconds sent over the wire is stale the moment it arrives, and this panel is
 * watched while it ticks.
 */
function duration(fromIso: string, toMillis: number): string {
  const from = new Date(fromIso).getTime();
  if (Number.isNaN(from)) return '—';
  const seconds = Math.max(0, Math.floor((toMillis - from) / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${String(seconds % 60).padStart(2, '0')}s`;
}

/**
 * How long it has been going, or how long it took.
 *
 * <p>A queued probe times from submission and a running one from the moment it actually
 * started: reporting a wait as run time would overstate what Maven has been asked to do, which
 * is the same distinction QUEUED exists to make.
 */
function elapsedFor(task: ProbeTask, now: number): string {
  const from = task.startedAt ?? task.submittedAt;
  const to = task.finishedAt ? new Date(task.finishedAt).getTime() : now;
  return duration(from, to);
}

const STATE_LABELS: Record<ProbeTask['state'], string> = {
  RUNNING: 'running',
  QUEUED: 'queued',
  COMPLETED: 'finished',
  STOPPED: 'stopped',
  FAILED: 'failed',
};

/**
 * What the Maven probe is doing right now, and how to stop it.
 *
 * <p>This exists because a probe deliberately outlives the Component Inspector tab it was
 * started from — the tab is a view of backend state, not its owner — and a tab can be closed
 * by the reader or evicted by the tab cap. Until now the only way to reach a running probe was
 * to already know which component it belonged to, which is exactly what somebody who has lost
 * track of it does not.
 *
 * <p>Probes are serialised on one background thread, so at most one row is ever RUNNING and the
 * rest are waiting behind it. That is a property of the design, not a coincidence: the isolated
 * probe repository cannot safely take concurrent writes.
 */
export function ProcessesPanel() {
  const [tasks, setTasks] = useState<ProbeTask[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [stopping, setStopping] = useState<string | null>(null);
  const [now, setNow] = useState(() => Date.now());

  const { select } = useSboms();
  const navigate = useNavigate();
  const pollTimer = useRef<number | null>(null);

  useEffect(() => {
    let cancelled = false;

    function poll() {
      fetchProbeQueue()
        .then((result) => {
          if (cancelled) return;
          setTasks(result);
          setError(null);
          setNow(Date.now());
        })
        .catch((e: unknown) => {
          if (!cancelled) setError(messageOf(e));
        })
        .finally(() => {
          if (!cancelled) pollTimer.current = window.setTimeout(poll, POLL_INTERVAL_MS);
        });
    }

    poll();
    return () => {
      cancelled = true;
      if (pollTimer.current !== null) window.clearTimeout(pollTimer.current);
    };
  }, []);

  // A second, faster clock so the elapsed column moves between polls. Cheap, and it stops the
  // panel reading as frozen while a probe sits inside a 60-second Maven invocation.
  useEffect(() => {
    const ticker = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(ticker);
  }, []);

  const stop = useCallback(async (id: string) => {
    setStopping(id);
    try {
      await cancelProbe(id);
      // Not removed from the list — the next poll returns it as STOPPED, which is the point.
    } catch (e) {
      setError(messageOf(e));
    } finally {
      setStopping(null);
    }
  }, []);

  return (
    <section className="panel" aria-labelledby="monitoring-processes">
      <h2 className="panel__title" id="monitoring-processes">
        Maven probes
      </h2>
      <p className="panel__hint">
        Probes run one at a time on a single background thread — the isolated probe repository
        cannot safely take concurrent writes — so one row runs and the rest wait behind it.
        Stopping a run keeps every candidate it had already settled; <em>Continue</em> on the
        component picks the search up from where it stopped, with a fresh budget. Finished runs
        stay listed for this session — select one to open the component it was answering for.
      </p>

      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}

      {tasks.length === 0 ? (
        <p className="panel__hint">No probe has run this session.</p>
      ) : (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col">State</th>
                <th scope="col">Component</th>
                <th scope="col">Module</th>
                <th scope="col">Elapsed</th>
                <th scope="col">
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {tasks.map((task) => (
                <tr key={task.id} data-finished={PROBE_FINISHED.includes(task.state)}>
                  <td>
                    <span
                      className={
                        task.state === 'RUNNING' || task.state === 'FAILED'
                          ? 'badge badge--warn'
                          : 'badge'
                      }
                    >
                      {STATE_LABELS[task.state]}
                    </span>
                  </td>
                  <td className="mono">
                    {/* The way back to the component whose name the reader has forgotten —
                        which is the whole reason this panel exists. Not a plain link: the
                        Inspector reads the purl from the URL but the SBOM from the selection,
                        so a link alone would open this component against whichever document
                        happened to be selected and then quietly clear itself. */}
                    {task.purl ? (
                      <button
                        type="button"
                        className="linklike"
                        title="Open this component in the Inspector"
                        onClick={() => {
                          select(task.sbomId);
                          navigate(`/component-inspector?purl=${encodeURIComponent(task.purl ?? '')}`);
                        }}
                      >
                        {task.component}
                      </button>
                    ) : (
                      task.component
                    )}
                  </td>
                  <td className="mono">{task.module ?? '—'}</td>
                  <td className="mono">{elapsedFor(task, now)}</td>
                  <td>
                    {/* Nothing to stop once it has ended — the row stays as history, and an
                        offered control that can only fail is worse than none. */}
                    {!PROBE_FINISHED.includes(task.state) && (
                      <button
                        type="button"
                        className="button button--small"
                        onClick={() => void stop(task.id)}
                        disabled={stopping === task.id}
                      >
                        {stopping === task.id ? 'Stopping…' : 'Stop'}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
