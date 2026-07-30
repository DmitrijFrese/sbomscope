import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';

/** What the user chose. 'system' defers to the OS setting. */
export type ThemePreference = 'light' | 'dark' | 'system';

/** What is actually rendered — 'system' has been resolved away. */
export type ResolvedTheme = 'light' | 'dark';

const STORAGE_KEY = 'sbomscope.theme';
const DARK_QUERY = '(prefers-color-scheme: dark)';

interface ThemeContextValue {
  preference: ThemePreference;
  resolved: ResolvedTheme;
  /**
   * What the OS is currently asking for, whether or not 'system' is selected.
   *
   * <p>Distinct from `resolved`, and the distinction is the whole point of exposing it: with
   * 'light' chosen, `resolved` is 'light' and says nothing about what picking 'system' would
   * give you. The System option is labelled from this, so it describes itself rather than
   * appearing to do nothing on a machine whose OS already matches the chosen theme.
   */
  systemTheme: ResolvedTheme;
  setPreference: (preference: ThemePreference) => void;
}

const ThemeContext = createContext<ThemeContextValue | undefined>(undefined);

function isPreference(value: unknown): value is ThemePreference {
  return value === 'light' || value === 'dark' || value === 'system';
}

function readStoredPreference(): ThemePreference {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    return isPreference(stored) ? stored : 'system';
  } catch {
    // Private browsing or blocked storage: fall back to the OS setting.
    return 'system';
  }
}

function currentSystemTheme(): ResolvedTheme {
  return window.matchMedia(DARK_QUERY).matches ? 'dark' : 'light';
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [preference, setPreferenceState] = useState<ThemePreference>(readStoredPreference);
  const [systemTheme, setSystemTheme] = useState<ResolvedTheme>(currentSystemTheme);

  // Track OS changes so 'system' stays live rather than sampled once at startup.
  useEffect(() => {
    const query = window.matchMedia(DARK_QUERY);
    const onChange = (event: MediaQueryListEvent) => {
      setSystemTheme(event.matches ? 'dark' : 'light');
    };
    query.addEventListener('change', onChange);
    return () => query.removeEventListener('change', onChange);
  }, []);

  const resolved: ResolvedTheme = preference === 'system' ? systemTheme : preference;

  // The inline script in index.html sets this before first paint; this keeps it
  // in sync afterwards.
  useEffect(() => {
    document.documentElement.dataset.theme = resolved;
  }, [resolved]);

  const setPreference = useCallback((next: ThemePreference) => {
    try {
      localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // Preference simply will not persist; the session still switches correctly.
    }
    setPreferenceState(next);
  }, []);

  const value = useMemo(
    () => ({ preference, resolved, systemTheme, setPreference }),
    [preference, resolved, systemTheme, setPreference],
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error('useTheme must be used inside a ThemeProvider');
  }
  return context;
}
