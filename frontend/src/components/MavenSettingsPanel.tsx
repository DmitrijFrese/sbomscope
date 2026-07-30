import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';

import { fetchMavenSettings, saveMavenSettings, testMaven } from '../api/client';
import type { MavenSettings, MavenTestResult } from '../api/client';

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : 'Something went wrong.';
}

/**
 * The Maven probe (Phase 8 Tier 2): drives the user's own {@code mvn} to check whether
 * bumping the declaring dependency brings a clean version, when Tier 1's offline answer
 * cannot say. Configured exactly like OSV-Scanner — a path, never downloaded, unavailable
 * rather than broken when absent.
 */
const MIN_PROBES = 1;
const MAX_PROBES = 200;
const MIN_RUN_BUDGET_MINUTES = 1;
const MAX_RUN_BUDGET_MINUTES = 60;

export function MavenSettingsPanel() {
  const [enabled, setEnabled] = useState(false);
  const [executablePath, setExecutablePath] = useState('');
  const [maxProbes, setMaxProbes] = useState(20);
  const [runBudgetMinutes, setRunBudgetMinutes] = useState(8);
  const [profiles, setProfiles] = useState('');

  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [test, setTest] = useState<MavenTestResult | null>(null);

  function apply(next: MavenSettings) {
    setEnabled(next.enabled);
    setExecutablePath(next.executablePath ?? '');
    setMaxProbes(next.maxProbes);
    setRunBudgetMinutes(next.runBudgetMinutes);
    setProfiles(next.profiles ?? '');
  }

  useEffect(() => {
    fetchMavenSettings().then(apply).catch((e: unknown) => setError(messageOf(e)));
  }, []);

  async function save(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setSaved(false);
    setTest(null);
    try {
      apply(
        await saveMavenSettings({
          enabled,
          executablePath: executablePath.trim() || null,
          maxProbes,
          runBudgetMinutes,
          profiles: profiles.trim() || null,
        }),
      );
      setSaved(true);
    } catch (e) {
      setError(messageOf(e));
    } finally {
      setBusy(false);
    }
  }

  async function runTest() {
    setBusy(true);
    setError(null);
    try {
      setTest(await testMaven());
    } catch (e) {
      setError(messageOf(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel" aria-labelledby="settings-maven">
      <h2 className="panel__title" id="settings-maven">
        Maven probe
      </h2>
      <p className="panel__hint">
        For a transitive finding, Tier 1 can pin it precisely but cannot say whether a newer
        version of what pulls it in already ships the fix — that needs reading a version
        nobody has installed yet. This drives your own <span className="mono">mvn</span> to
        check, in an isolated local repository that never touches <span className="mono">~/.m2</span>.
        No settings are parsed and no credentials are read here — Maven reads its own{' '}
        <span className="mono">settings.xml</span>, so mirrors and authentication come along
        for free.
      </p>

      <form onSubmit={save}>
        <label className="setting-option" style={{ maxWidth: '100%' }}>
          <input
            type="checkbox"
            checked={enabled}
            onChange={(event) => setEnabled(event.target.checked)}
          />
          <span>
            <span className="setting-option__label">Enable the Maven probe</span>
            <span className="setting-option__hint">
              Requires a path to mvn below. Probing is a real external process and can take
              real time, which is why it stays opt-in on its own.
            </span>
          </span>
        </label>

        <label className="field" style={{ marginTop: 'var(--space-4)' }}>
          <span className="field__label">mvn path</span>
          <input
            type="text"
            value={executablePath}
            placeholder="C:\tools\apache-maven\bin\mvn.cmd"
            onChange={(event) => setExecutablePath(event.target.value)}
          />
          <span className="field__hint">
            The Maven you already build with — never downloaded by SBOMscope.
          </span>
        </label>

        <label className="field" style={{ marginTop: 'var(--space-4)' }}>
          <span className="field__label">Maven profiles</span>
          <input
            type="text"
            value={profiles}
            placeholder="prod,internal-repo"
            onChange={(event) => setProfiles(event.target.value)}
          />
          <span className="field__hint">
            Comma-separated profile IDs, passed to every probe exactly as{' '}
            <span className="mono">mvn -P{profiles.trim() || 'profile1,profile2'}</span> would. Leave
            blank to activate none.
          </span>
        </label>

        <div className="field-row" style={{ marginTop: 'var(--space-4)' }}>
          <label className="field">
            <span className="field__label">Maximum probes</span>
            <input
              type="number"
              min={MIN_PROBES}
              max={MAX_PROBES}
              value={maxProbes}
              onChange={(event) => setMaxProbes(Number(event.target.value))}
            />
            <span className="field__hint">
              Ceiling on how many <span className="mono">mvn</span> invocations one bump probe may
              spend, ranking every major line. Between {MIN_PROBES} and {MAX_PROBES}.
            </span>
          </label>

          <label className="field">
            <span className="field__label">Run budget (minutes)</span>
            <input
              type="number"
              min={MIN_RUN_BUDGET_MINUTES}
              max={MAX_RUN_BUDGET_MINUTES}
              value={runBudgetMinutes}
              onChange={(event) => setRunBudgetMinutes(Number(event.target.value))}
            />
            <span className="field__hint">
              Wall-clock ceiling for the same run — usually the binding constraint, since a cold
              probe repository can spend minutes on probes that take seconds once warm. Between{' '}
              {MIN_RUN_BUDGET_MINUTES} and {MAX_RUN_BUDGET_MINUTES}.
            </span>
          </label>
        </div>

        <div className="upload-form__actions">
          <button type="submit" className="button button--primary" disabled={busy}>
            {busy ? 'Saving…' : 'Save'}
          </button>
          <button
            type="button"
            className="button"
            onClick={runTest}
            disabled={busy || !executablePath.trim()}
          >
            Test Maven
          </button>
        </div>
      </form>

      {saved && <p className="notice" style={{ marginTop: 'var(--space-4)' }}>Settings saved.</p>}

      {test && (
        <p
          className={test.ok ? 'notice' : 'form-error'}
          style={{ marginTop: 'var(--space-4)' }}
          role="status"
        >
          {test.ok ? `Working: ${test.version}` : test.error}
        </p>
      )}

      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
    </section>
  );
}
