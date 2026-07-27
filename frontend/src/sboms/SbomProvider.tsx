import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';

import { deleteSbom, fetchSboms, uploadSbom } from '../api/client';
import type { Sbom } from '../api/client';

/**
 * Holds the uploaded SBOMs and which one is selected.
 *
 * <p>Both main views operate on the same selection, so it lives above them rather than
 * in either one. The backend remains the source of truth: every mutation is followed by
 * a reload rather than patching local state, which keeps the list honest even when an
 * import partly fails.
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
}

const SbomContext = createContext<SbomContextValue | undefined>(undefined);

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : 'Something went wrong.';
}

export function SbomProvider({ children }: { children: ReactNode }) {
  const [sboms, setSboms] = useState<Sbom[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

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
      await reload();
    },
    [reload],
  );

  const selected = useMemo(
    () => sboms.find((sbom) => sbom.id === selectedId) ?? null,
    [sboms, selectedId],
  );

  const value = useMemo(
    () => ({ sboms, selected, loading, error, select: setSelectedId, reload, upload, remove }),
    [sboms, selected, loading, error, reload, upload, remove],
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
