/**
 * State that survives navigation and reload, backed by localStorage.
 *
 * <p>The findings view holds a lot of choices — sort, severity bands, page size, which
 * columns to show — and losing them on every trip to Settings made the view feel like it
 * kept forgetting. These are preferences about how someone works, not transient state.
 *
 * <p>localStorage rather than the URL: SBOMscope runs on one machine for one person, so
 * there is nobody to share a link with, and the query string would be noise. Revisit if
 * bookmarkable views ever become a real need.
 */
import { useCallback, useEffect, useState } from 'react';
import type { Dispatch, SetStateAction } from 'react';

const PREFIX = 'sbomscope.';

/**
 * @param revive fixes up a stored value before it is used — for dropping fields that
 *               should not persist, and for filling in ones added since it was written.
 *               Stored state outlives the code that wrote it, so it is never trusted as-is.
 */
export function usePersistentState<T>(
  key: string,
  fallback: T,
  revive?: (stored: T) => T,
): [T, Dispatch<SetStateAction<T>>] {
  const storageKey = PREFIX + key;

  const [value, setValue] = useState<T>(() => {
    try {
      const raw = window.localStorage.getItem(storageKey);
      if (raw === null) {
        return fallback;
      }
      const parsed = JSON.parse(raw) as T;
      return revive ? revive(parsed) : parsed;
    } catch {
      // Corrupt or unreadable — a stale preference is never worth failing a render over.
      return fallback;
    }
  });

  useEffect(() => {
    try {
      window.localStorage.setItem(storageKey, JSON.stringify(value));
    } catch {
      // Private browsing, or the quota is full. Losing the preference is acceptable;
      // breaking the page over it is not.
    }
  }, [storageKey, value]);

  return [value, setValue];
}

/** The common case: a flag that remembers itself. */
export function usePersistentToggle(
  key: string,
  fallback: boolean,
): [boolean, () => void] {
  const [value, setValue] = usePersistentState<boolean>(key, fallback, (stored) =>
    typeof stored === 'boolean' ? stored : fallback,
  );
  const toggle = useCallback(() => setValue((current) => !current), [setValue]);
  return [value, toggle];
}
