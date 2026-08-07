import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';

import {
  attachWorkspace as attachWorkspaceRequest,
  createFolder as createFolderRequest,
  deleteFolder as deleteFolderRequest,
  deleteSbom,
  fetchFolders,
  fetchSboms,
  moveFolder as moveFolderRequest,
  moveSbomToFolder as moveSbomToFolderRequest,
  renameFolder as renameFolderRequest,
  reorderLevel as reorderLevelRequest,
  sortLevelByName as sortLevelByNameRequest,
  uploadSbom,
} from '../api/client';
import type { Folder, Sbom } from '../api/client';
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

/**
 * What became of one file in an upload.
 *
 * <p>Per file rather than per batch, because one malformed document among five is the normal
 * case — a single "upload failed" would hide the four that worked, and a single "uploaded"
 * would hide the one that did not.
 */
export interface UploadOutcome {
  filename: string;
  /** Set when the import succeeded. */
  sbomId?: string;
  /** Set when it did not, carrying the backend's own message. */
  error?: string;
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
  /**
   * Imports one or more documents, sequentially, and reports what happened to each. Never
   * rejects for a failed file: a partial failure is a result, not an error, and throwing
   * would discard the outcomes of the files that did import.
   */
  upload: (files: File[], workspacePath?: string) => Promise<UploadOutcome[]>;
  remove: (id: string) => Promise<void>;
  /** Open Inspector tabs per SBOM id. Absent means none open this session. */
  inspectorTabs: Record<string, InspectorTabs>;
  /** Appends the purl if it is not already open, and makes it active either way. */
  openInspectorTab: (sbomId: string, purl: string) => void;
  closeInspectorTab: (sbomId: string, purl: string) => void;

  // --- projects and folders (B19) --------------------------------------------------

  /** Every project and folder, flat — the sidebar assembles the tree itself. */
  folders: Folder[];
  createFolder: (name: string, parentId?: string) => Promise<Folder>;
  renameFolder: (id: string, name: string) => Promise<Folder>;
  moveFolder: (id: string, parentId?: string) => Promise<Folder>;
  /** Its contents move up to the parent. No document is ever deleted. */
  deleteFolder: (id: string) => Promise<void>;
  moveSbomToFolder: (sbomId: string, folderId?: string) => Promise<void>;
  /** Rewrites the manual order of one level (V10). */
  reorderLevel: (parentId: string | undefined, order: { folderIds?: string[]; sbomIds?: string[] }) => Promise<void>;
  /** Restores alphabetical order within one level. */
  sortLevelByName: (parentId?: string) => Promise<void>;

  // --- workspace relink (B20) -------------------------------------------------------

  /** Sets, changes or clears a document's workspace after upload. */
  attachWorkspace: (sbomId: string, workspacePath?: string) => Promise<void>;
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

  /**
   * @param quiet skips the loading flag. The scan poll below runs every couple of seconds
   *              while something is being scanned, and flipping `loading` on each pass would
   *              blink the sidebar into its "Loading…" state for a list that is already there.
   */
  const load = useCallback(async (quiet: boolean) => {
    if (!quiet) {
      setLoading(true);
    }
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

  const reload = useCallback(() => load(false), [load]);

  useEffect(() => {
    void reload();
  }, [reload]);

  // An automatic scan finishes on the backend with nothing to announce it, so the list is
  // polled while one is in flight and left completely alone otherwise — the same list call
  // clears the marker and brings the new counts, so there is no moment where a card claims
  // to be scanning something that has already been counted.
  const anyScanning = sboms.some((sbom) => sbom.scanning);
  useEffect(() => {
    if (!anyScanning) {
      return;
    }
    const timer = window.setInterval(() => void load(true), 2000);
    return () => window.clearInterval(timer);
  }, [anyScanning, load]);

  const upload = useCallback(
    async (files: File[], workspacePath?: string): Promise<UploadOutcome[]> => {
      const outcomes: UploadOutcome[] = [];

      // Sequential, not Promise.all. Each import is a transaction that writes a document to
      // disk and parses it back off again, and the failure of one must not be entangled with
      // the progress of another — which is the whole reason this reports per file.
      for (const file of files) {
        try {
          const created = await uploadSbom(file, workspacePath);
          outcomes.push({ filename: file.name, sbomId: created.id });
        } catch (e) {
          outcomes.push({ filename: file.name, error: messageOf(e) });
        }
      }

      // One reload for the batch: five uploads should not redraw the sidebar five times.
      await reload();

      // The last one that worked, as a single upload already does. Deliberately not the last
      // one attempted — landing on a document that failed to import would select nothing.
      const lastImported = [...outcomes].reverse().find((outcome) => outcome.sbomId);
      if (lastImported?.sbomId) {
        setSelectedId(lastImported.sbomId);
      }
      return outcomes;
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

  // --- projects and folders (B19) ---------------------------------------------------
  //
  // A second top-level list beside `sboms`, on the same "backend is the source of truth"
  // rule: every mutation is followed by a reload rather than patched locally. Kept as its
  // own piece of state rather than nested under `sboms` because the sidebar renders both
  // lists together and needs to tell "no folders yet" apart from "still loading".
  const [folders, setFolders] = useState<Folder[]>([]);

  const reloadFolders = useCallback(async () => {
    try {
      setFolders(await fetchFolders());
    } catch (e) {
      setError(messageOf(e));
    }
  }, []);

  useEffect(() => {
    void reloadFolders();
  }, [reloadFolders]);

  const createFolder = useCallback(
    async (name: string, parentId?: string) => {
      const created = await createFolderRequest(name, parentId);
      await reloadFolders();
      return created;
    },
    [reloadFolders],
  );

  const renameFolder = useCallback(
    async (id: string, name: string) => {
      const renamed = await renameFolderRequest(id, name);
      await reloadFolders();
      return renamed;
    },
    [reloadFolders],
  );

  const moveFolder = useCallback(
    async (id: string, parentId?: string) => {
      const moved = await moveFolderRequest(id, parentId);
      await reloadFolders();
      return moved;
    },
    [reloadFolders],
  );

  const deleteFolderAction = useCallback(
    async (id: string) => {
      await deleteFolderRequest(id);
      // A deleted folder relocates its documents to the parent, so both lists move.
      await Promise.all([reloadFolders(), reload()]);
    },
    [reloadFolders, reload],
  );

  const moveSbomToFolder = useCallback(
    async (sbomId: string, folderId?: string) => {
      await moveSbomToFolderRequest(sbomId, folderId);
      await reload();
    },
    [reload],
  );

  const reorderLevel = useCallback(
    async (parentId: string | undefined, order: { folderIds?: string[]; sbomIds?: string[] }) => {
      await reorderLevelRequest(parentId, order);
      // Both lists carry order, so both are refetched — a reorder of folders leaves the
      // document order untouched but the two are read from one tree.
      await Promise.all([reloadFolders(), reload()]);
    },
    [reloadFolders, reload],
  );

  const sortLevelByName = useCallback(
    async (parentId?: string) => {
      await sortLevelByNameRequest(parentId);
      await Promise.all([reloadFolders(), reload()]);
    },
    [reloadFolders, reload],
  );

  // --- workspace relink (B20) --------------------------------------------------------

  const attachWorkspaceAction = useCallback(
    async (sbomId: string, workspacePath?: string) => {
      await attachWorkspaceRequest(sbomId, workspacePath);
      await reload();
    },
    [reload],
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
      folders,
      createFolder,
      renameFolder,
      moveFolder,
      deleteFolder: deleteFolderAction,
      moveSbomToFolder,
      reorderLevel,
      sortLevelByName,
      attachWorkspace: attachWorkspaceAction,
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
      folders,
      createFolder,
      renameFolder,
      moveFolder,
      deleteFolderAction,
      moveSbomToFolder,
      reorderLevel,
      sortLevelByName,
      attachWorkspaceAction,
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
