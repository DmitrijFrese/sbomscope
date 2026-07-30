import { FullLogPanel } from '../components/FullLogPanel';
import { LoggingPanel } from '../components/LoggingPanel';
import { ProcessesPanel } from '../components/ProcessesPanel';
import { usePersistentState } from '../state/persisted';

/**
 * Three views of the same question — what is this application doing, and what has it done.
 *
 * <p>Ordered by urgency rather than by history. **Processes** is what is happening right now
 * and the only one with a control on it; the two logs are the record, at two levels of detail.
 * A reader arrives here either because something is taking a long time (the first tab) or
 * because something went wrong and they need to know exactly what Maven said (the third).
 */
const TABS = [
  { id: 'processes', label: 'Processes' },
  { id: 'activity', label: 'Activity log' },
  { id: 'full', label: 'Full log' },
] as const;

type TabId = (typeof TABS)[number]['id'];

const TAB_IDS: readonly string[] = TABS.map((tab) => tab.id);

export function MonitoringPage() {
  const [tab, setTab] = usePersistentState<TabId>('monitoring.tab', 'processes', (stored) =>
    TAB_IDS.includes(stored) ? stored : 'processes',
  );

  return (
    <>
      <div className="page-header">
        <h1>Monitoring</h1>
        <p>
          What SBOMscope is doing right now, and everything notable it has done: anything
          touching the network, running an external process, or changing stored data.
        </p>
      </div>

      <div className="tabs" role="tablist" aria-label="Monitoring views">
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

      <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
        {tab === 'processes' && <ProcessesPanel />}
        {tab === 'activity' && <LoggingPanel />}
        {tab === 'full' && <FullLogPanel />}
      </div>
    </>
  );
}
