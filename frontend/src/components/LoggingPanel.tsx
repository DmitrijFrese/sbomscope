import { useEffect, useRef, useState } from 'react';

import { fetchActivity, fetchLogStatus, openLogFolder } from '../api/client';
import type { ActivityEvent, LogStatus } from '../api/client';

const POLL_INTERVAL_MS = 3000;

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : 'Something went wrong.';
}

function formatTime(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime())
    ? iso
    : date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'medium' });
}

/**
 * Everything SBOMscope writes to disk about its own notable actions: network calls,
 * external processes, and changes to stored data.
 *
 * <p>The path is always shown as copyable text — a browser cannot open a native folder from
 * an {@code http://} page. The "Open folder" button is a separate thing: it triggers a
 * backend action, and the backend runs on the user's own machine, which is what makes it
 * possible at all. Hidden rather than shown-and-failing when the backend reports no
 * {@code Desktop} support (headless environments).
 */
export function LoggingPanel() {
  const [status, setStatus] = useState<LogStatus | null>(null);
  const [events, setEvents] = useState<ActivityEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [opening, setOpening] = useState(false);
  const [openError, setOpenError] = useState<string | null>(null);

  const pollTimer = useRef<number | null>(null);

  useEffect(() => {
    fetchLogStatus().then(setStatus).catch((e: unknown) => setError(messageOf(e)));
  }, []);

  useEffect(() => {
    let cancelled = false;

    function poll() {
      fetchActivity(200)
        .then((result) => {
          if (!cancelled) setEvents(result);
        })
        .catch((e: unknown) => {
          if (!cancelled) setError(messageOf(e));
        })
        .finally(() => {
          if (!cancelled) {
            pollTimer.current = window.setTimeout(poll, POLL_INTERVAL_MS);
          }
        });
    }

    poll();
    return () => {
      cancelled = true;
      if (pollTimer.current !== null) window.clearTimeout(pollTimer.current);
    };
  }, []);

  async function openFolder() {
    setOpening(true);
    setOpenError(null);
    try {
      setStatus(await openLogFolder());
    } catch (e) {
      setOpenError(messageOf(e));
    } finally {
      setOpening(false);
    }
  }

  return (
    <section className="panel" aria-labelledby="settings-logging">
      <h2 className="panel__title" id="settings-logging">
        Logging
      </h2>
      <p className="panel__hint">
        <span className="mono">sbomscope.log</span> is the full verbose record, for
        diagnosing after the fact. <span className="mono">activity.jsonl</span> holds only
        notable events — anything touching the network, running an external process, or
        changing stored data — shown below as it is written.
      </p>

      {status && (
        <div className="upload-form__actions" style={{ alignItems: 'center' }}>
          <span className="mono path-cell" title={status.path}>
            {status.path}
          </span>
          {status.canOpenFolder && (
            <button type="button" className="button button--small" onClick={openFolder} disabled={opening}>
              {opening ? 'Opening…' : 'Open folder'}
            </button>
          )}
        </div>
      )}

      {openError && (
        <p className="form-error" role="alert">
          {openError}
        </p>
      )}
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}

      <div className="table-scroll" style={{ marginTop: 'var(--space-4)' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th scope="col">Time</th>
              <th scope="col">Category</th>
              <th scope="col">Event</th>
              <th scope="col">Outcome</th>
              <th scope="col">Detail</th>
            </tr>
          </thead>
          <tbody>
            {events.length === 0 && (
              <tr>
                <td colSpan={5}>Nothing logged yet.</td>
              </tr>
            )}
            {events.map((event, index) => (
              // No stable id in the log line itself; position is fine for a read-only tail
              // that re-fetches wholesale on every poll.
              <tr key={index}>
                <td className="mono">{formatTime(event.timestamp)}</td>
                <td>
                  <span className="badge">{event.category}</span>
                </td>
                <td className="mono">{event.event}</td>
                <td>
                  {event.outcome === 'FAILURE' ? (
                    <span className="badge badge--warn">{event.outcome}</span>
                  ) : (
                    event.outcome
                  )}
                </td>
                <td>{event.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
