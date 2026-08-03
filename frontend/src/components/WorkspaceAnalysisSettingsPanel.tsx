import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';

import { fetchWorkspaceAnalysisSettings, saveWorkspaceAnalysisSettings } from '../api/client';

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : 'Something went wrong.';
}

/**
 * Inputs for the isolated, bytecode-only call-graph analysis.
 *
 * <p>The Maven probe intentionally has a different cache and a different ownership contract:
 * its process can write/download, while this panel only identifies a directory that the analyzer
 * is allowed to read after the user's own build has put artifacts there.
 */
export function WorkspaceAnalysisSettingsPanel() {
  const [mavenLocalRepository, setMavenLocalRepository] = useState('');
  const [maxRunMinutes, setMaxRunMinutes] = useState(10);
  const [maxHeapMegabytes, setMaxHeapMegabytes] = useState(1024);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    fetchWorkspaceAnalysisSettings()
      .then((settings) => {
        setMavenLocalRepository(settings.mavenLocalRepository);
        setMaxRunMinutes(settings.maxRunMinutes);
        setMaxHeapMegabytes(settings.maxHeapMegabytes);
      })
      .catch((e: unknown) => setError(messageOf(e)));
  }, []);

  async function save(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setSaved(false);
    try {
      const savedSettings = await saveWorkspaceAnalysisSettings({
        mavenLocalRepository: mavenLocalRepository.trim(),
        maxRunMinutes,
        maxHeapMegabytes,
      });
      setMavenLocalRepository(savedSettings.mavenLocalRepository);
      setMaxRunMinutes(savedSettings.maxRunMinutes);
      setMaxHeapMegabytes(savedSettings.maxHeapMegabytes);
      setSaved(true);
    } catch (e) {
      setError(messageOf(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel" aria-labelledby="settings-workspace-analysis">
      <h2 className="panel__title" id="settings-workspace-analysis">
        Workspace reachability
      </h2>
      <p className="panel__hint">
        SBOMscope analyses compiled production output already present in the attached workspace.
        It never runs your build. Dependency JARs are read from the Maven cache below, which must
        already contain the versions named by the SBOM.
      </p>

      <form onSubmit={save}>
        <label className="field">
          <span className="field__label">Maven local repository</span>
          <input
            type="text"
            value={mavenLocalRepository}
            placeholder="C:\\Users\\you\\.m2\\repository"
            onChange={(event) => setMavenLocalRepository(event.target.value)}
          />
          <span className="field__hint">
            <strong>Read-only.</strong> SBOMscope never downloads, creates, changes or deletes
            files here. This is not the separate <span className="mono">probe-repo</span> used by
            Maven upgrade probes.
          </span>
        </label>

        <label className="field">
          <span className="field__label">Analysis heap limit (MB)</span>
          <input type="number" min="256" max="8192" step="256" value={maxHeapMegabytes}
            onChange={(event) => setMaxHeapMegabytes(Number(event.target.value))} />
          <span className="field__hint">
            Defaults to 1024 MB. The limit applies only to SBOMscope&apos;s isolated worker and
            prevents a large call graph from exhausting the machine.
          </span>
        </label>

        <label className="field">
          <span className="field__label">Analysis time limit (minutes)</span>
          <input type="number" min="1" max="60" value={maxRunMinutes}
            onChange={(event) => setMaxRunMinutes(Number(event.target.value))} />
          <span className="field__hint">
            Defaults to 10 minutes. When the limit is reached, SBOMscope terminates only its
            isolated reachability worker; your workspace and Maven processes are untouched.
          </span>
        </label>

        <div className="upload-form__actions">
          <button type="submit" className="button button--primary" disabled={busy}>
            {busy ? 'Saving…' : 'Save'}
          </button>
        </div>
      </form>

      {saved && <p className="notice" style={{ marginTop: 'var(--space-4)' }}>Settings saved.</p>}
      {error && <p className="form-error" role="alert">{error}</p>}
    </section>
  );
}
