import { useEffect } from 'react';
import { useLocation } from 'react-router-dom';

import { ExploitFeedPanel } from '../components/ExploitFeedPanel';
import { ExportSettingsPanel } from '../components/ExportSettingsPanel';
import { MavenSettingsPanel } from '../components/MavenSettingsPanel';
import { PurgePanel } from '../components/PurgePanel';
import { ScannerSettingsPanel } from '../components/ScannerSettingsPanel';
import { useTheme } from '../theme/ThemeProvider';
import type { ThemePreference } from '../theme/ThemeProvider';

const THEME_OPTIONS: ReadonlyArray<{
  value: ThemePreference;
  label: string;
  hint: string;
}> = [
  { value: 'light', label: 'Light', hint: 'Always use the light theme.' },
  { value: 'dark', label: 'Dark', hint: 'Always use the dark theme.' },
  { value: 'system', label: 'System', hint: 'Follow your operating system setting.' },
];

export function SettingsPage() {
  const { preference, resolved, systemTheme, setPreference } = useTheme();
  const { hash } = useLocation();

  // React Router only pushes history on an in-app <Link>; it does not repeat the browser's
  // own scroll-to-fragment-on-load behaviour, so a link to e.g. #settings-maven from another
  // page would otherwise land on top of the page instead of the section it named.
  useEffect(() => {
    if (!hash) return;
    document.getElementById(hash.slice(1))?.scrollIntoView({ block: 'start' });
  }, [hash]);

  return (
    <>
      <div className="page-header">
        <h1>Settings</h1>
        <p>Appearance is stored in this browser; everything else is stored locally by the application.</p>
      </div>

      <ScannerSettingsPanel />

      {/* Directly after the scanner: both are vulnerability data the user downloads, and this
          one enriches exactly what that one produces. Before the Maven probe, which is a
          different kind of thing entirely — an external process rather than a file. */}
      <ExploitFeedPanel />

      <MavenSettingsPanel />

      <ExportSettingsPanel />

      <section className="panel" aria-labelledby="settings-ui">
        <h2 className="panel__title" id="settings-ui">
          UI
        </h2>
        <p className="panel__hint">Appearance of the SBOMscope interface.</p>

        <fieldset className="setting-group">
          <legend className="setting-group__legend">Theme</legend>

          {THEME_OPTIONS.map((option) => (
            <label className="setting-option" key={option.value}>
              <input
                type="radio"
                name="theme"
                value={option.value}
                checked={preference === option.value}
                onChange={() => setPreference(option.value)}
              />
              <span>
                <span className="setting-option__label">
                  {option.label}
                  {/* On a machine whose OS is already dark, "System" and "Dark" render
                      identically, so the option looked inert. Saying what it currently
                      resolves to — live, since ThemeProvider tracks the media query — is
                      the whole fix; the mechanism was never wrong. Shown whichever option
                      is selected, because it also answers "what would I get if I picked
                      this", which `resolved` cannot. */}
                  {option.value === 'system' && (
                    <span className="setting-option__resolved">
                      {' '}
                      (currently {systemTheme})
                    </span>
                  )}
                </span>
                <span className="setting-option__hint">{option.hint}</span>
              </span>
            </label>
          ))}

          <p className="setting-group__note">
            Currently showing the <strong>{resolved}</strong> theme.
          </p>
        </fieldset>
      </section>

      {/* Last, and visually separated: nothing above it can destroy anything. */}
      <PurgePanel />
    </>
  );
}
