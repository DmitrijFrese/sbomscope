import { useEffect, useLayoutEffect, useRef, useState } from 'react';

import { fetchLogText } from '../api/client';
import { usePersistentToggle } from '../state/persisted';
import { SearchField } from './SearchField';

const POLL_INTERVAL_MS = 3000;
const LINES = 1000;
const FILTER_DEBOUNCE_MS = 250;

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : 'Something went wrong.';
}

/**
 * The verbose record — every `mvn` command and everything Maven said back.
 *
 * <p>Separate from the activity tail beside it, and not a nicer rendering of the same thing.
 * The activity log answers "what has SBOMscope done"; this answers "what exactly did it say",
 * which is the only question that helps when a probe fails on a machine with no route to a
 * repository. Until now the only way to read it was the Open folder button, which is no way at
 * all on a machine where the browser and the file manager are not both to hand.
 *
 * <p>Rendered as plain preformatted text rather than parsed into columns: it is a transcript,
 * with stack traces and Maven's own formatting in it, and any structure imposed here would be
 * invented rather than read.
 */
export function FullLogPanel() {
  const [lines, setLines] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState('');
  const [regex, setRegex] = useState(false);
  const [negate, setNegate] = useState(false);
  const [follow, toggleFollow] = usePersistentToggle('monitoring.followLog', true);

  const pollTimer = useRef<number | null>(null);
  const scroller = useRef<HTMLPreElement>(null);

  useEffect(() => {
    let cancelled = false;

    function poll() {
      fetchLogText(LINES, filter, regex, negate)
        .then((result) => {
          if (cancelled) return;
          setLines(result);
          setError(null);
        })
        .catch((e: unknown) => {
          // The lines already on screen stay. A half-written pattern must not clear the
          // transcript somebody is reading.
          if (!cancelled) setError(messageOf(e));
        })
        .finally(() => {
          if (!cancelled) pollTimer.current = window.setTimeout(poll, POLL_INTERVAL_MS);
        });
    }

    // Debounced on the filter for the same reason the findings table is: this is a request
    // per keystroke otherwise, and the backend now scans megabytes to answer it.
    const debounce = window.setTimeout(poll, filter ? FILTER_DEBOUNCE_MS : 0);
    return () => {
      cancelled = true;
      window.clearTimeout(debounce);
      if (pollTimer.current !== null) window.clearTimeout(pollTimer.current);
    };
  }, [filter, regex, negate]);

  // Layout, not passive: the scroll has to move in the same frame the new lines are painted,
  // or following a live log flickers back to the old position first.
  useLayoutEffect(() => {
    if (!follow || !scroller.current) return;
    scroller.current.scrollTop = scroller.current.scrollHeight;
  }, [lines, follow]);

  return (
    <section className="panel" aria-labelledby="monitoring-full-log">
      <h2 className="panel__title" id="monitoring-full-log">
        sbomscope.log
      </h2>
      <p className="panel__hint">
        The last {LINES} lines. Every <span className="mono">mvn</span> command the probe runs
        is written here verbatim, so it can be copied into a terminal and reproduced, along with
        everything Maven printed back.
      </p>

      {/* Filtered on the backend, not here: it can look much further back than the {LINES}
          lines this panel holds, so searching for something that scrolled past still finds it.
          Filtering what already arrived would only ever search the visible tail. */}
      <SearchField
        value={filter}
        onValueChange={setFilter}
        regex={regex}
        onRegexChange={setRegex}
        negate={negate}
        onNegateChange={setNegate}
        placeholder="Find in the log…"
        ariaLabel="Find in the log"
        note={error}
        inputClassName="toolbar__search"
      />

      <label className="setting-option" style={{ maxWidth: '100%' }}>
        <input type="checkbox" checked={follow} onChange={toggleFollow} />
        <span>
          <span className="setting-option__label">Follow new lines</span>
          <span className="setting-option__hint">
            Keeps the view pinned to the end as lines arrive. Turn it off to read back through
            a failure without being pulled forward every three seconds.
          </span>
        </span>
      </label>

      {lines.length === 0 && !error ? (
        <p className="panel__hint">
          {filter ? 'No lines match that.' : 'Nothing written yet.'}
        </p>
      ) : (
        <pre className="log-text" ref={scroller} tabIndex={0} aria-label="Full log">
          {lines.join('\n')}
        </pre>
      )}
    </section>
  );
}
