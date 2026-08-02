import { useState } from 'react';

import { purge } from '../api/client';
import type { PurgeResult, PurgeTarget } from '../api/client';
import { useSboms } from '../sboms/SbomProvider';

interface TargetOption {
  value: PurgeTarget;
  label: string;
  hint: string;
  /** Expensive or slow to get back, so it says so before you tick it. */
  costly?: boolean;
}

const TARGETS: readonly TargetOption[] = [
  {
    value: 'SBOMS',
    label: 'Uploaded SBOMs',
    hint: 'Every uploaded document, its components and its dependency graph. Re-uploading is quick.',
  },
  {
    value: 'FINDINGS',
    label: 'Vulnerability results',
    hint: 'The scan cache shared across all SBOMs. Deleting SBOMs alone keeps this, which is why a re-upload gets its findings back without re-scanning. Clearing it means scanning again.',
  },
  {
    value: 'SETTINGS',
    label: 'Settings',
    hint: 'Scanner path, whether scanning is on, the database location and the export preference. You will have to point SBOMscope at osv-scanner again.',
  },
  {
    value: 'OSV_DATABASE',
    label: 'Offline vulnerability data',
    hint: 'OSV archives and index, plus KEV and EPSS files and rows. Replacing OSV means downloading roughly 10 MB for Maven and 200 MB for npm — which a machine with no internet access cannot do at all.',
    costly: true,
  },
  {
    value: 'ROLLED_LOGS',
    label: 'Rolled log history',
    hint: 'The eight inactive numbered logs. The active sbomscope.log and activity.jsonl remain while the application is running; stop SBOMscope to remove those too.',
  },
  {
    value: 'MAVEN_PROBE_CACHE',
    label: 'Maven probe cache',
    hint: 'The isolated probe-repo, never ~/.m2. No probe may be queued or running. Later probes must download missing plugins, metadata and candidate artifacts again and may be unavailable while disconnected.',
    costly: true,
  },
];

/**
 * Erases local data, behind a typed confirmation.
 *
 * <p>Separate choices rather than one button, because they differ by orders of
 * magnitude in what they cost to undo: re-uploading an SBOM is a drag and drop, while
 * replacing the npm archive is a 200 MB download that the target environment for this
 * tool may not be able to perform at all.
 */
export function PurgePanel() {
  const { reload } = useSboms();

  const [selected, setSelected] = useState<PurgeTarget[]>([]);
  const [confirmation, setConfirmation] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<PurgeResult | null>(null);

  const confirmed = ['PURGE', 'DELETE'].includes(confirmation.trim().toUpperCase());
  const ready = confirmed && selected.length > 0 && !busy;

  function toggle(target: PurgeTarget) {
    setResult(null);
    setSelected((current) =>
      current.includes(target) ? current.filter((t) => t !== target) : [...current, target],
    );
  }

  async function run() {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await purge(confirmation, selected));
      // Anything holding a list of SBOMs is now describing rows that no longer exist.
      await reload();
      setSelected([]);
      setConfirmation('');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Nothing was deleted.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel panel--danger" aria-labelledby="settings-purge">
      <h2 className="panel__title" id="settings-purge">
        Erase local data
      </h2>
      <p className="panel__hint">
        Permanent, and there is nothing to undo it with. Everything SBOMscope stores lives in{' '}
        <span className="mono">~/.sbomscope</span>.
      </p>

      <fieldset className="setting-group" disabled={busy}>
        <legend className="setting-group__legend">What to erase</legend>

        {TARGETS.map((target) => (
          <label className="setting-option" key={target.value}>
            <input
              type="checkbox"
              checked={selected.includes(target.value)}
              onChange={() => toggle(target.value)}
            />
            <span>
              <span className="setting-option__label">
                {target.label}
                {target.costly && <span className="badge badge--warn">expensive to replace</span>}
              </span>
              <span className="setting-option__hint">{target.hint}</span>
            </span>
          </label>
        ))}
      </fieldset>

      {/* The database file itself is never touched — H2 holds it open — so a schema the
          application will not start on cannot be fixed from in here. Said plainly, because
          reaching for this button in that situation is the obvious mistake. */}
      <p className="setting-group__note">
        This empties tables; it does not delete the database file, which H2 keeps locked while
        SBOMscope is running. If the application will not start at all, stop it and delete{' '}
        <span className="mono">~/.sbomscope/db/sbomscope.mv.db</span> instead — and leave{' '}
        <span className="mono">osv-db</span> alone unless you mean to re-download it.
      </p>

      <label className="field purge__confirm">
        <span className="field__label">
          Type <strong>PURGE</strong> to confirm
        </span>
        <input
          type="text"
          value={confirmation}
          onChange={(event) => setConfirmation(event.target.value)}
          placeholder="PURGE"
          autoComplete="off"
          spellCheck={false}
          disabled={busy}
          aria-describedby="purge-help"
        />
        <span className="field__hint" id="purge-help">
          {selected.length === 0
            ? 'Choose at least one thing to erase.'
            : `${selected.length} selected. This cannot be undone.`}
        </span>
      </label>

      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}

      {result && (
        <div className="notice" role="status">
          <strong>Erased.</strong>
          <ul className="purge__result">
            {Object.entries(result.removed).map(([target, summary]) => (
              <li key={target}>{summary}</li>
            ))}
          </ul>
        </div>
      )}

      <button type="button" className="button button--danger" onClick={run} disabled={!ready}>
        {busy ? 'Erasing…' : 'Erase selected data'}
      </button>
    </section>
  );
}
