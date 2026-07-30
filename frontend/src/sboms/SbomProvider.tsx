import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';

import { deleteSbom, fetchSboms, uploadSbom } from '../api/client';
import type { Sbom } from '../api/client';
import { usePersistentState } from '../state/persisted';

/**
 * The Component Inspector's open tabs for one SBOM.
 *
 * <p>Per SBOM because a tab strip listing components that are not in the current document
 * is meaningless. That shape also answers "what happens when you switch to an SBOM without
 * the selected component" without a special case: you see that SBOM's own tabs, and none
 * for one never opened this session.
 */
export interface InspectorTabs {
  /** Open purls, in the order they were opened — which is the order they are shown in. */
  open: string[];
  /** Which one the Inspector shows when it is reached without a purl in the URL. */
  active: string | null;
  /** The same purls, most recently activated first. Only eviction reads this. */
  recent: string[];
}

/** Shared so an SBOM with no tabs does not hand out a new object on every render. */
const NO_TABS: InspectorTabs = { open: [], active: null, recent: [] };

/**
 * How many components stay open per SBOM before the least recently used one is dropped.
 *
 * <p>The same answer IntelliJ and VS Code arrived at, and for the same reason: past about a
 * dozen, a tab strip has stopped being navigation and become a second thing to search. Ten
 * also keeps the strip near one row's worth of width, so it does not start taking height
 * from the panel — which is the whole reason the identity block was moved out of the main
 * column in the first place.
 *
 * <p>**Eviction is silent, and that is safe here specifically because a tab holds nothing.**
 * The panel's state all lives elsewhere: advisories and the graph are re-fetched per (sbom,
 * purl), and a bump probe's progress is cached on the backend keyed by module and target, so
 * closing a tab does not stop a probe or discard its result — reopening the component
 * rehydrates it. A dropped tab costs two keystrokes in the finder and nothing else, which is
 * why this does not need the "report it, never disguise it" treatment that budget exhaustion
 * in the probe does. There, something was genuinely not done.
 */
const MAX_OPEN_TABS = 10;

/**
 * Which tab a close activates: the one to its right, or failing that the one to its left —
 * what a browser does, and null when the last tab is closed.
 *
 * <p>Exported because the Inspector has to put the answer in the URL while the provider
 * puts it in the tab list, and two statements of the rule would eventually disagree.
 */
export function neighbourAfterClosing(open: string[], closing: string): string | null {
  const index = open.indexOf(closing);
  if (index < 0) return null;
  const remaining = open.filter((purl) => purl !== closing);
  return remaining[index] ?? remaining[index - 1] ?? null;
}

/**
 * Holds the uploaded SBOMs and which one is selected.
 *
 * <p>Both main views operate on the same selection, so it lives above them rather than
 * in either one. The backend remains the source of truth: every mutation is followed by
 * a reload rather than patching local state, which keeps the list honest even when an
 * import partly fails.
 *
 * <p>It also holds the Component Inspector's open tabs, for one reason: this is above the
 * router. The bug every version of that item was chasing is that navigating to another
 * page and back threw the Inspector away, and state inside the page cannot survive its own
 * unmount. Deliberately **not** persisted — which components you had open is where you were
 * in a session, not a preference, and it has no business outliving the application.
 */
interface SbomContextValue {
  sboms: Sbom[];
  selected: Sbom | null;
  loading: boolean;
  error: string | null;
  select: (id: string | null) => void;
  reload: () => Promise<void>;
  upload: (file: File, workspacePath?: string) => Promise<void>;
  remove: (id: string) => Promise<void>;
  /** Open Inspector tabs per SBOM id. Absent means none open this session. */
  inspectorTabs: Record<string, InspectorTabs>;
  /** Appends the purl if it is not already open, and makes it active either way. */
  openInspectorTab: (sbomId: string, purl: string) => void;
  closeInspectorTab: (sbomId: string, purl: string) => void;
}

const SbomContext = createContext<SbomContextValue | undefined>(undefined);

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : 'Something went wrong.';
}

export function SbomProvider({ children }: { children: ReactNode }) {
  const [sboms, setSboms] = useState<Sbom[]>([]);

  // Persisted, because the Component Inspector puts the component in the URL and the SBOM
  // it belongs to is not in there with it — without this, a refresh restored the component
  // against whichever SBOM happened to be newest. It also fixes the older annoyance that
  // reloading the findings view silently switched you to a different document.
  //
  // Never trusted: a stored id can name an SBOM since deleted, and reload() replaces it
  // with the most recent upload when it no longer matches anything.
  const [selectedId, setSelectedId] = usePersistentState<string | null>(
    'sboms.selected',
    null,
    (stored) => (typeof stored === 'string' ? stored : null),
  );
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // In-memory on purpose: see the note on SbomContextValue. Plain useState is enough
  // precisely because this must not survive a restart.
  const [inspectorTabs, setInspectorTabs] = useState<Record<string, InspectorTabs>>({});

  const openInspectorTab = useCallback((sbomId: string, purl: string) => {
    setInspectorTabs((current) => {
      const tabs = current[sbomId] ?? NO_TABS;
      // Reopening the tab you are already on must not produce new state, or the effect
      // that calls this on every successful load would re-render forever. Already active
      // also means already at the front of `recent`, so nothing else needs checking.
      if (tabs.active === purl && tabs.open.includes(purl)) return current;

      const recent = [purl, ...tabs.recent.filter((seen) => seen !== purl)];
      let open = tabs.open;

      if (!open.includes(purl)) {
        open = [...open, purl];
        if (open.length > MAX_OPEN_TABS) {
          // Least recently activated goes, never the one being opened. Display order stays
          // the order things were opened in, as a browser does — only the victim is chosen
          // by recency, because dropping "the oldest opened" would discard the tab you have
          // been coming back to all session.
          const victim = recent[recent.length - 1];
          if (victim && victim !== purl) {
            open = open.filter((tab) => tab !== victim);
            recent.pop();
          }
        }
      }

      return { ...current, [sbomId]: { open, active: purl, recent } };
    });
  }, []);

  const closeInspectorTab = useCallback((sbomId: string, purl: string) => {
    setInspectorTabs((current) => {
      const tabs = current[sbomId];
      if (!tabs || !tabs.open.includes(purl)) return current;
      const neighbour = neighbourAfterClosing(tabs.open, purl);
      return {
        ...current,
        [sbomId]: {
          open: tabs.open.filter((tab) => tab !== purl),
          active: tabs.active === purl ? neighbour : tabs.active,
          recent: tabs.recent.filter((seen) => seen !== purl),
        },
      };
    });
  }, []);

  const reload = useCallback(async () => {
    setLoading(true);
    try {
      const result = await fetchSboms();
      setSboms(result);
      setError(null);

      // Keep the selection valid: if the selected SBOM is gone, fall back to the
      // most recent upload rather than leaving the views pointing at nothing.
      setSelectedId((current) => {
        if (current && result.some((sbom) => sbom.id === current)) {
          return current;
        }
        return result[0]?.id ?? null;
      });
    } catch (e) {
      setError(messageOf(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  const upload = useCallback(
    async (file: File, workspacePath?: string) => {
      const created = await uploadSbom(file, workspacePath);
      await reload();
      setSelectedId(created.id);
    },
    [reload],
  );

  const remove = useCallback(
    async (id: string) => {
      await deleteSbom(id);
      // Tabs are scoped to a document that no longer exists, so they go with it rather
      // than sitting there keyed to an id nothing can resolve.
      setInspectorTabs((current) => {
        if (!(id in current)) return current;
        const next = { ...current };
        delete next[id];
        return next;
      });
      await reload();
    },
    [reload],
  );

  const selected = useMemo(
    () => sboms.find((sbom) => sbom.id === selectedId) ?? null,
    [sboms, selectedId],
  );

  const value = useMemo(
    () => ({
      sboms,
      selected,
      loading,
      error,
      select: setSelectedId,
      reload,
      upload,
      remove,
      inspectorTabs,
      openInspectorTab,
      closeInspectorTab,
    }),
    [
      sboms,
      selected,
      loading,
      error,
      reload,
      upload,
      remove,
      inspectorTabs,
      openInspectorTab,
      closeInspectorTab,
    ],
  );

  return <SbomContext.Provider value={value}>{children}</SbomContext.Provider>;
}

export function useSboms(): SbomContextValue {
  const context = useContext(SbomContext);
  if (!context) {
    throw new Error('useSboms must be used inside an SbomProvider');
  }
  return context;
}
