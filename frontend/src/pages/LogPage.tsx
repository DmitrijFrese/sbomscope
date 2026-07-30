import { LoggingPanel } from '../components/LoggingPanel';

/**
 * Its own tab rather than a Settings panel — it is watched during and after an action
 * (a scan, a probe), not configured once and left alone the way scanner or Maven settings are.
 */
export function LogPage() {
  return (
    <>
      <div className="page-header">
        <h1>Activity log</h1>
        <p>
          Every notable action SBOMscope has taken: anything touching the network, running an
          external process, or changing stored data.
        </p>
      </div>

      <LoggingPanel />
    </>
  );
}
