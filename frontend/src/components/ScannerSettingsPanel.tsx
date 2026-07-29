import { useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';

import {
  fetchDownloadProgress,
  fetchScannerStatus,
  saveScannerSettings,
  startDatabaseDownload,
  startDatabaseIndexing,
  testScanner,
} from '../api/client';
import type {
  DatabaseStatus,
  DownloadProgress,
  ScannerStatus,
  ScannerTestResult,
} from '../api/client';

/** Shown in full so it is obvious where the data comes from before anything is fetched. */
const OSV_BASE_URL = 'https://osv-vulnerabilities.storage.googleapis.com';

/** Where to obtain the scanner. Linked rather than fetched — we never download it. */
const OSV_SCANNER_RELEASES = 'https://github.com/google/osv-scanner/releases/latest';

/** Rough sizes, so the npm download is not a surprise on a slow or metered link. */
const APPROXIMATE_SIZES: Record<string, string> = {
  Maven: '~10 MB',
  npm: '~200 MB',
};

const POLL_INTERVAL_MS = 400;

function formatBytes(bytes: number): string {
  if (bytes <= 0) return '—';
  const mb = bytes / 1024 / 1024;
  return mb >= 1 ? `${mb.toFixed(1)} MB` : `${(bytes / 1024).toFixed(0)} KB`;
}

function formatDate(iso: string | null): string {
  if (!iso) return 'never';
  const date = new Date(iso);
  return Number.isNaN(date.getTime())
    ? iso
    : date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : 'Something went wrong.';
}

/**
 * Two jobs, reported as two steps.
 *
 * Fetching the archive has a known total and gets a real bar. Parsing it into the index has
 * none — the archive announces no advisory count — so it gets a counter and an indeterminate
 * bar rather than one inventing a scale. Collapsing them into a single bar would mean either
 * stalling at 100% for five seconds or lying about how far along it is.
 */
function DownloadBar({ progress }: { progress: DownloadProgress }) {
  const indexing = progress.phase === 'INDEX';
  const known = !indexing && progress.totalBytes > 0;
  const percent = known
    ? Math.min(100, Math.round((progress.bytesDownloaded / progress.totalBytes) * 100))
    : 0;

  const label = indexing ? 'Indexing' : 'Downloading';

  return (
    <div className="progress" role="group" aria-label={`${label} ${progress.ecosystem}`}>
      <div className="progress__header">
        <span>
          {label} <strong>{progress.ecosystem}</strong>
          <span className="progress__step"> · step {indexing ? 2 : 1} of 2</span>
        </span>
        <span className="mono">
          {indexing
            ? `${progress.advisoriesIndexed.toLocaleString()} advisories`
            : `${formatBytes(progress.bytesDownloaded)}${
                known ? ` of ${formatBytes(progress.totalBytes)} · ${percent}%` : ''
              }`}
        </span>
      </div>

      <div
        className="progress__track"
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={known ? percent : undefined}
      >
        <div
          className={`progress__bar ${known ? '' : 'progress__bar--indeterminate'}`}
          style={known ? { width: `${percent}%` } : undefined}
        />
      </div>
    </div>
  );
}

export function ScannerSettingsPanel() {
  const [status, setStatus] = useState<ScannerStatus | null>(null);
  const [enabled, setEnabled] = useState(false);
  const [executablePath, setExecutablePath] = useState('');
  const [databaseDirectory, setDatabaseDirectory] = useState('');

  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [test, setTest] = useState<ScannerTestResult | null>(null);
  const [download, setDownload] = useState<DownloadProgress | null>(null);
  /** Escape hatch from the gate below: staging data for a machine that will scan. */
  const [overrideGate, setOverrideGate] = useState(false);

  const pollTimer = useRef<number | null>(null);

  function apply(next: ScannerStatus) {
    setStatus(next);
    setEnabled(next.settings.enabled);
    setExecutablePath(next.settings.executablePath ?? '');
    setDatabaseDirectory(next.settings.databaseDirectory);
    setDownload(next.download.state === 'IDLE' ? null : next.download);
  }

  useEffect(() => {
    fetchScannerStatus().then(apply).catch((e: unknown) => setError(messageOf(e)));
    return () => {
      if (pollTimer.current !== null) window.clearTimeout(pollTimer.current);
    };
  }, []);

  /** Polls until the download stops running, then refreshes the on-disk status. */
  function pollUntilFinished() {
    pollTimer.current = window.setTimeout(async () => {
      try {
        const current = await fetchDownloadProgress();
        setDownload(current);

        if (current.state === 'RUNNING') {
          pollUntilFinished();
          return;
        }
        // Finished either way: pick up the new file size and timestamp.
        apply({ ...(await fetchScannerStatus()), download: current });
        setDownload(current);
      } catch (e) {
        setError(messageOf(e));
      }
    }, POLL_INTERVAL_MS);
  }

  async function save(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setSaved(false);
    setTest(null);
    try {
      apply(await saveScannerSettings({
        enabled,
        executablePath: executablePath.trim() || null,
        databaseDirectory: databaseDirectory.trim(),
      }));
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
      setTest(await testScanner());
    } catch (e) {
      setError(messageOf(e));
    } finally {
      setBusy(false);
    }
  }

  async function beginDownload(ecosystem: string) {
    setError(null);
    try {
      setDownload(await startDatabaseDownload(ecosystem));
      pollUntilFinished();
    } catch (e) {
      setError(messageOf(e));
    }
  }

  /** Indexing an archive already on disk: the same background job, without the fetch. */
  async function beginIndexing(ecosystem: string) {
    setError(null);
    try {
      setDownload(await startDatabaseIndexing(ecosystem));
      pollUntilFinished();
    } catch (e) {
      setError(messageOf(e));
    }
  }

  const downloading = download?.state === 'RUNNING';

  // Gated on the *saved* setting rather than the checkbox, so the gate reflects how the
  // application is actually configured rather than an unsaved edit. With scanning off
  // nothing here can read the database, so downloading it is a dead end — but staging it
  // for another machine is legitimate, hence the override.
  const scanningOn = status?.settings.enabled ?? false;
  const downloadsLocked = !scanningOn && !overrideGate;

  return (
    <section className="panel" aria-labelledby="settings-scanning">
      <h2 className="panel__title" id="settings-scanning">
        Vulnerability scanning
      </h2>
      <p className="panel__hint">
        SBOMscope matches components against known vulnerabilities using OSV-Scanner, which
        you install yourself — it is never downloaded for you. With scanning switched off,
        SBOMscope still works as an SBOM inventory.
      </p>

      <form onSubmit={save}>
        <label className="setting-option" style={{ maxWidth: '100%' }}>
          <input
            type="checkbox"
            checked={enabled}
            onChange={(event) => setEnabled(event.target.checked)}
          />
          <span>
            <span className="setting-option__label">Use OSV-Scanner</span>
            <span className="setting-option__hint">
              Requires a path to the binary below. Everything runs offline against the
              local database.
            </span>
          </span>
        </label>

        <label className="field" style={{ marginTop: 'var(--space-4)' }}>
          <span className="field__label">osv-scanner path</span>
          <input
            type="text"
            value={executablePath}
            placeholder="C:\tools\osv-scanner_windows_amd64.exe"
            onChange={(event) => setExecutablePath(event.target.value)}
          />
          <span className="field__hint">
            A single portable executable — no installer, nothing to extract. Download the
            build for your platform from{' '}
            <a href={OSV_SCANNER_RELEASES} target="_blank" rel="noreferrer">
              the OSV-Scanner releases page
            </a>{' '}
            (for example <span className="mono">osv-scanner_windows_amd64.exe</span>,
            around 55&nbsp;MB) and put it anywhere you like. SBOMscope never downloads it
            for you — the releases page publishes SHA256 checksums so you can verify what
            you run.
          </span>
        </label>

        <label className="field">
          <span className="field__label">Vulnerability database directory</span>
          <input
            type="text"
            value={databaseDirectory}
            onChange={(event) => setDatabaseDirectory(event.target.value)}
          />
          <span className="field__hint">
            On a machine without internet access, copy this directory across from one that
            has it.
          </span>
        </label>

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
            Test scanner
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

      <h3 className="panel__title" style={{ marginTop: 'var(--space-6)' }}>
        Offline vulnerability database
      </h3>
      <p className="panel__hint">
        This is the public OSV.dev advisory database: every known vulnerability for an
        ecosystem, as individual JSON records inside a zip archive. It is open data in the
        OSV schema — not executable code, and not specific to any one tool — and it is what
        lets scanning work with no network access. Downloaded only when you ask, one
        ecosystem at a time, from:
      </p>
      <p className="source-origin mono">
        <a href={`${OSV_BASE_URL}/`} target="_blank" rel="noreferrer">
          {OSV_BASE_URL}
        </a>
        <span className="source-origin__suffix">/&lt;ecosystem&gt;/all.zip</span>
      </p>

      {downloadsLocked && (
        <div className="gate" role="note">
          <p className="gate__text">
            Downloading is unavailable because scanning is switched off — nothing in
            SBOMscope would read this data yet.
          </p>
          <p className="gate__text">
            Turn on <strong>Use OSV-Scanner</strong> above, or continue anyway if you are
            fetching the database to copy onto a machine that has no internet access.
          </p>
          <button type="button" className="button button--small" onClick={() => setOverrideGate(true)}>
            Download anyway
          </button>
        </div>
      )}

      {download && download.state === 'RUNNING' && <DownloadBar progress={download} />}

      {download?.state === 'FAILED' && (
        <p className="form-error" role="alert">
          {download.message}
        </p>
      )}

      {download?.state === 'COMPLETED' && (
        <p className="notice">
          Finished downloading {download.ecosystem} ({formatBytes(download.bytesDownloaded)}).
        </p>
      )}

      <div className="table-scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th scope="col">Ecosystem</th>
              <th scope="col">Size</th>
              <th scope="col">Last updated</th>
              <th scope="col">Location on disk</th>
              <th scope="col" />
            </tr>
          </thead>
          <tbody>
            {(status?.database ?? []).map((entry: DatabaseStatus) => (
              <tr key={entry.ecosystem}>
                <td>
                  <span className="mono">{entry.ecosystem}</span>
                  {!entry.present && <span className="badge">not downloaded</span>}
                </td>
                <td>
                  {entry.present
                    ? formatBytes(entry.sizeBytes)
                    : (APPROXIMATE_SIZES[entry.ecosystem] ?? '—')}
                </td>
                <td>{formatDate(entry.lastModified)}</td>
                <td>
                  <span className="mono path-cell" title={entry.path}>
                    {entry.path}
                  </span>
                  <a
                    className="path-cell__source"
                    href={entry.sourceUrl}
                    target="_blank"
                    rel="noreferrer"
                  >
                    source
                  </a>
                </td>
                <td className="db-actions">
                  <button
                    type="button"
                    className="button button--small"
                    onClick={() => beginDownload(entry.ecosystem)}
                    disabled={downloading || downloadsLocked}
                    title={
                      downloadsLocked
                        ? 'Enable scanning, or choose "Download anyway" to stage this for another machine.'
                        : undefined
                    }
                  >
                    {entry.present ? 'Refresh' : 'Download'}
                  </button>

                  {/* Only for an archive that is present but not indexed — one carried
                      across by hand, or downloaded before the index existed. Re-fetching
                      200 MB to fix that would be absurd, and on an air-gapped machine
                      impossible. */}
                  {entry.present && !entry.indexed && (
                    <button
                      type="button"
                      className="button button--small"
                      onClick={() => beginIndexing(entry.ecosystem)}
                      disabled={downloading}
                      title="Parse this archive so upgrade paths can check candidate versions against it."
                    >
                      Index
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
