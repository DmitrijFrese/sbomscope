import { useEffect, useState } from 'react';

/**
 * Shown while a scan runs.
 *
 * <p>Deliberately indeterminate. osv-scanner emits no progress we can read — it reports
 * once, at the end — so a percentage bar would be inventing a number, and a bar that
 * advances on nothing is worse than no bar at all: it tells the user how long is left, which
 * we do not know.
 *
 * <p>What can be stated truthfully is how many components are being checked and how long it
 * has been going, which is enough to tell "working" apart from "hung" — the actual question
 * someone has thirty seconds in.
 */
export function ScanProgress({ componentCount }: { componentCount: number }) {
  const [seconds, setSeconds] = useState(0);

  useEffect(() => {
    const timer = window.setInterval(() => setSeconds((current) => current + 1), 1000);
    return () => window.clearInterval(timer);
  }, []);

  return (
    <div className="scan-progress" role="status" aria-live="polite">
      <span className="spinner" aria-hidden="true" />
      <span>
        Scanning <strong>{componentCount}</strong>{' '}
        {componentCount === 1 ? 'component' : 'components'} against the offline database…
      </span>
      {/* Only once it has been long enough for the wait to be worth acknowledging. */}
      {seconds >= 3 && <span className="scan-progress__elapsed">{seconds}s</span>}
    </div>
  );
}
