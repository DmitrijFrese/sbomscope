import { useEffect, useMemo, useState } from 'react';

import { ApiError, applyBump, fetchBumpPlan, previewBump } from '../api/client';
import type { ApplyResult, PreviewFile, PreviewResult } from '../api/client';
import {
  apply,
  compareSemver,
  compareVersions,
  editsFor,
  redo,
  rowKey,
  sharedImpact,
  siteVersion,
  startSession,
  undo,
} from '../bump/model';
import type { BumpRow, Session, TextRange } from '../bump/model';
import { SearchField } from '../components/SearchField';
import { buildMatcher, rowMatches } from '../components/searchMatcher';
import { useSboms } from '../sboms/SbomProvider';

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : 'Something went wrong.';
}

function isMissingWorkspace(error: unknown): boolean {
  return error instanceof ApiError && error.status === 409
    && /no workspace attached/i.test(error.message);
}

function HighlightedText({ text, ranges }: { text: string; ranges: TextRange[] }) {
  const bytes = new TextEncoder().encode(text);
  const decoder = new TextDecoder();
  const pieces: Array<{ text: string; changed: boolean }> = [];
  let cursor = 0;

  for (const range of [...ranges].sort((left, right) => left.start - right.start)) {
    const start = Math.max(cursor, Math.min(bytes.length, range.start));
    const end = Math.max(start, Math.min(bytes.length, range.end));
    if (start > cursor) pieces.push({ text: decoder.decode(bytes.slice(cursor, start)), changed: false });
    if (end > start) pieces.push({ text: decoder.decode(bytes.slice(start, end)), changed: true });
    cursor = end;
  }
  if (cursor < bytes.length) pieces.push({ text: decoder.decode(bytes.slice(cursor)), changed: false });

  return (
    <pre className="bump-editor__highlights" aria-hidden="true">
      {pieces.map((piece, index) => piece.changed
        ? <mark key={index}>{piece.text}</mark>
        : <span key={index}>{piece.text}</span>)}
    </pre>
  );
}

/**
 * Whether the workspace already holds a version at least as new as the advisories ask for.
 *
 * This happens whenever the SBOM is older than the poms — which is most of the time, since a
 * document is uploaded once and a source tree keeps moving. Such a row is still listed, because
 * every vulnerable component is; it is simply not preselected and contributes no edit. Offering
 * to write 3.1.5 over 3.1.5 would take a `.orig` backup and an activity-log entry for a change
 * that never happened, and both of those are worth less once they record things that did not.
 */
function isSatisfied(row: BumpRow): boolean {
  if (!row.minimalTarget || row.site.kind === 'UNDECLARED' || row.site.kind === 'IMPORTED_BOM') {
    // A structural remedy adds an entry that is not there; "already at that version" is not a
    // question that can be asked about it.
    return false;
  }
  const compare = row.site.ecosystem === 'NPM' ? compareSemver : compareVersions;
  return compare(row.site.currentVersion, row.minimalTarget) >= 0;
}

function npmLiteralFor(site: BumpRow['site'], version: string): string {
  return `${site.versionLiteral.slice(0, -site.currentVersion.length)}${version}`;
}

function unsupportedLiteralNote(row: BumpRow, notes: string[]): string | null {
  const identifiers = [row.site.id, row.site.file, row.site.artifactId, row.site.versionLiteral];
  return notes.find((note) => identifiers.some((identifier) => note.includes(identifier))) ?? null;
}

function LinkedValue({ value, url }: { value: string; url: string | null }) {
  return url ? (
    <a href={url} target="_blank" rel="noreferrer" className="mono">{value}</a>
  ) : <span className="mono">{value}</span>;
}

function RowControls({ row, session, notes, onChange }: {
  row: BumpRow;
  session: Session;
  notes: string[];
  onChange: (next: Session) => void;
}) {
  const key = rowKey(row.site);
  const selection = session.state.selection[key];
  const resolved = siteVersion(session.state, row.site.id);
  const satisfied = isSatisfied(row);
  const structural = row.site.kind === 'IMPORTED_BOM' || row.site.kind === 'UNDECLARED';
  const npm = row.site.ecosystem === 'NPM';
  const rangeAdmitsFix = npm && row.site.rangeAdmitsFix;
  const unsupportedLiteral = row.site.kind === 'NPM_DIRECT' && row.site.versionRange === null;
  const unsupportedUndeclared = npm && row.site.kind === 'UNDECLARED'
    && row.site.insertionPoint === null;
  const unavailable = rangeAdmitsFix || unsupportedLiteral || unsupportedUndeclared;
  const unsupportedNote = unsupportedLiteral || unsupportedUndeclared
    ? unsupportedLiteralNote(row, notes) : null;
  const coordinate = `${row.site.groupId}:${row.site.artifactId}`;
  const impact = row.site.kind === 'PROPERTY' && row.site.sharedWith.length > 0
    ? sharedImpact(session.state, row.site.id)
    : [];
  const choose = (version: string, source: 'minimal' | 'latest' | 'custom') => {
    onChange(apply(session, { kind: 'select', row: key, version, source }));
  };

  return (
    <tr data-row-key={key}>
      <td>
        {unavailable ? <span className="text-muted">â€”</span> : (
          <input
            type="checkbox"
            aria-label={`Select ${coordinate}`}
            checked={Boolean(selection)}
            onChange={(event) => {
              if (!event.target.checked) {
                onChange(apply(session, { kind: 'deselect', row: key }));
                return;
              }
              choose(row.minimalTarget ?? row.latestTarget ?? row.site.currentVersion, 'minimal');
            }}
          />
        )}
      </td>
      <td className="bump-location">
        {row.artifactUrl ? (
          <strong><a href={row.artifactUrl} target="_blank" rel="noreferrer" className="mono">
            {coordinate}
          </a></strong>
        ) : <strong className="mono">{coordinate}</strong>}
        <span>{row.site.file}{row.site.module ? ` · ${row.site.module}` : ' · workspace root'}</span>
        <span>{structural
          ? npm
            ? unsupportedUndeclared ? 'Transitive npm dependency' : 'Adds an npm overrides entry'
            : 'Adds a new managed entry'
          : row.site.kind.toLowerCase()}</span>
        {impact.length > 0 && (
          <span className="bump-shared-warning" role="note">
            Shared property moves: {impact.join(', ')}
          </span>
        )}
        {row.site.exclusions.length > 0 && (
          <span>Existing exclusions: {row.site.exclusions.join(', ')}</span>
        )}
        {rangeAdmitsFix && row.minimalTarget && (
          <span className="bump-npm-diagnosis" role="note">
            <span className="mono">{row.site.versionLiteral}</span> already allows {row.minimalTarget}
            {' â€” '}your lockfile is pinned to an older version; run <span className="mono">npm install</span>
          </span>
        )}
        {unsupportedNote && <span className="bump-npm-diagnosis" role="note">{unsupportedNote}</span>}
      </td>
      <td>{npm && row.site.versionLiteral !== row.site.currentVersion
        ? <span className="mono">{row.site.versionLiteral}</span>
        : <LinkedValue value={npm ? row.site.versionLiteral : row.site.currentVersion}
          url={row.currentVersionUrl} />}</td>
      <td>
        {unavailable ? <span className="text-muted">No manifest edit</span> : row.minimalTarget ? (
          <label className="bump-target">
            <input
              type="radio"
              name={`target-${key}`}
              aria-label={`Minimal ${row.minimalTarget} for ${coordinate}`}
              checked={selection?.source === 'minimal'}
              onChange={() => choose(row.minimalTarget!, 'minimal')}
            />
            <LinkedValue value={row.minimalTarget} url={row.minimalTargetUrl} />
          </label>
        ) : <span className="text-muted">No fix named</span>}
      </td>
      <td>
        {unavailable ? <span className="text-muted">No manifest edit</span> : row.latestTarget ? (
          <label className="bump-target">
            <input
              type="radio"
              name={`target-${key}`}
              aria-label={`Latest available ${row.latestTarget} for ${coordinate}`}
              checked={selection?.source === 'latest'}
              onChange={() => choose(row.latestTarget!, 'latest')}
            />
            <LinkedValue value={row.latestTarget} url={row.latestTargetUrl} />
          </label>
        ) : <span className="text-muted">Not available</span>}
      </td>
      <td>
        {unavailable ? <span className="text-muted">No manifest edit</span> : <label className="bump-custom">
          <input
            aria-label={`Custom version for ${coordinate}`}
            value={selection?.source === 'custom' ? selection.version : ''}
            placeholder="Custom"
            onChange={(event) => choose(event.target.value, 'custom')}
          />
          {resolved
            ? <small>Will write <span className="mono">{npm ? npmLiteralFor(row.site, resolved) : resolved}</span></small>
            : satisfied && (
              <small className="text-muted">
                Already at <span className="mono">{row.site.currentVersion}</span>
              </small>
            )}
        </label>}
      </td>
      <td>{row.advisories.length > 0 ? row.advisories.map((advisory, index) => {
        const label = advisory.cveId ?? advisory.osvId;
        const url = advisory.cveId ? advisory.cveUrl : advisory.osvUrl;
        return <span key={advisory.osvId}>
          {index > 0 && ', '}
          {url ? <a href={url} target="_blank" rel="noreferrer">{label}</a> : label}
        </span>;
      }) : 'None'}</td>
    </tr>
  );
}

export function BumpPage() {
  const { selected } = useSboms();
  const [session, setSession] = useState<Session | null>(null);
  const [preview, setPreview] = useState<PreviewResult | null>(null);
  const [openFile, setOpenFile] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [workspaceMissing, setWorkspaceMissing] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [applying, setApplying] = useState(false);
  const [applyError, setApplyError] = useState<string | null>(null);
  const [overrideGate, setOverrideGate] = useState(false);
  const [applied, setApplied] = useState<ApplyResult | null>(null);
  // Session state, like the Component Inspector's finder: a filter is where you are in a task,
  // not a preference, and a stored one would silently hide rows on a later visit.
  const [filter, setFilter] = useState('');
  const [filterRegex, setFilterRegex] = useState(false);
  const [filterNegate, setFilterNegate] = useState(false);

  const matcher = useMemo(() => buildMatcher(filter, filterRegex), [filter, filterRegex]);
  const visibleRows = useMemo(() => {
    const rows = session?.state.plan.rows ?? [];
    if (!filter) return rows;
    // Searchable by everything the row displays: a reader filtering for "tomcat" and one
    // filtering for "CVE-2026-65905" or "frontend/package.json" are all asking a reasonable
    // question of this table.
    return rows.filter((row) => rowMatches(matcher, filterNegate, [
      `${row.site.groupId}:${row.site.artifactId}`,
      row.site.file,
      row.site.module,
      row.site.currentVersion,
      row.site.versionLiteral,
      row.minimalTarget,
      row.latestTarget,
      ...row.advisories.flatMap((advisory) => [advisory.osvId, advisory.cveId]),
    ]));
  }, [session?.state.plan.rows, matcher, filterNegate, filter]);
  const [copyState, setCopyState] = useState<'idle' | 'copied' | 'failed'>('idle');

  const previewEdits = useMemo(
    () => session ? editsFor(session.state) : [],
    [session?.state.plan, session?.state.selection],
  );
  const editSignature = JSON.stringify(previewEdits);

  useEffect(() => {
    let cancelled = false;
    setSession(null);
    setPreview(null);
    setOpenFile(null);
    setError(null);
    setWorkspaceMissing(false);
    if (!selected?.workspacePath) {
      setLoading(false);
      return () => { cancelled = true; };
    }

    setLoading(true);
    fetchBumpPlan(selected.id)
      .then((plan) => {
        if (cancelled) return;
        let next = startSession(plan);
        const selections = plan.rows
          .filter((row) => row.minimalTarget !== null && !isSatisfied(row)
            && !row.site.rangeAdmitsFix
            && !(row.site.versionRange === null && row.site.insertionPoint === null))
          .map((row) => ({
            row: rowKey(row.site),
            version: row.minimalTarget!,
            source: 'minimal' as const,
          }));
        if (selections.length > 0) next = apply(next, { kind: 'selectMany', selections });
        setSession(next);
        setOpenFile(plan.files[0]?.path ?? null);
      })
      .catch((reason: unknown) => {
        if (cancelled) return;
        if (isMissingWorkspace(reason)) {
          setWorkspaceMissing(true);
        } else {
          setError(messageOf(reason));
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, [selected?.id, selected?.workspacePath]);

  useEffect(() => {
    if (!selected?.workspacePath || !session) return;
    let cancelled = false;
    const timer = window.setTimeout(() => {
      previewBump(selected.id, previewEdits)
        .then((result) => {
          if (cancelled) return;
          setPreview(result);
          setError(null);
          setOpenFile((current) =>
            current && result.files.some((file) => file.path === current)
              ? current
              : result.files[0]?.path ?? session.state.plan.files[0]?.path ?? null);
        })
        .catch((reason: unknown) => {
          if (cancelled) return;
          if (isMissingWorkspace(reason)) {
            setWorkspaceMissing(true);
            setError(null);
          } else {
            setError(messageOf(reason));
          }
        });
    }, 250);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [selected?.id, selected?.workspacePath, editSignature]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (!(event.ctrlKey || event.metaKey) || event.key.toLowerCase() !== 'z') return;
      const target = event.target;
      if (target instanceof HTMLElement && target.closest('textarea, [contenteditable="true"]')) return;
      event.preventDefault();
      setSession((current) => current ? (event.shiftKey ? redo(current) : undo(current)) : current);
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  useEffect(() => {
    if (copyState !== 'copied') return;
    const timer = window.setTimeout(() => setCopyState('idle'), 1600);
    return () => window.clearTimeout(timer);
  }, [copyState]);

  const previewFiles: PreviewFile[] = useMemo(() => {
    if (!session) return [];
    if (preview) return preview.files;
    return session.state.plan.files.map((file) => ({
      path: file.path,
      fingerprint: file.fingerprint,
      patched: file.text,
      changed: [],
      editCount: 0,
    }));
  }, [preview, session?.state.plan]);
  // Only a real preview can be applied. `previewFiles` falls back to the plan's untouched files
  // so the editor has something to show before any selection, and those carry no edits at all —
  // applying them would write every pom back over itself.
  const filesToWrite = useMemo(
    () => (preview?.files ?? []).filter((file) => file.editCount > 0),
    [preview],
  );
  const shown = previewFiles.find((file) => file.path === openFile) ?? previewFiles[0] ?? null;
  const editorText = shown && session
    ? session.state.files[shown.path] ?? shown.patched
    : '';

  if (!selected) {
    return <div className="empty-state">Select an SBOM from the sidebar to plan version bumps.</div>;
  }
  if (!selected.workspacePath || workspaceMissing) {
    return (
      <div className="empty-state">
        Attach a workspace from this document&apos;s ⋯ menu before planning version bumps.
      </div>
    );
  }

  return (
    <>
      <div className="page-header page-header--split">
        <div className="page-header__identity">
          <h1>Dependency updates</h1>
          <p>{selected.filename} · {selected.workspacePath}</p>
        </div>
        <div className="page-header__actions">
          <button type="button" className="button" disabled={!session?.canUndo}
            title={session?.undoLabel ?? undefined}
            onClick={() => setSession((current) => current ? undo(current) : current)}>Undo</button>
          <button type="button" className="button" disabled={!session?.canRedo}
            title={session?.redoLabel ?? undefined}
            onClick={() => setSession((current) => current ? redo(current) : current)}>Redo</button>
          <button
            type="button"
            className="button button--primary"
            disabled={filesToWrite.length === 0 || applying}
            title={filesToWrite.length === 0 ? 'Nothing to write' : undefined}
            onClick={() => { setOverrideGate(false); setApplyError(null); setConfirming(true); }}
          >
            Apply
          </button>
        </div>
      </div>

      {confirming && (
        <div className="bump-confirm" role="dialog" aria-modal="true" aria-labelledby="bump-confirm-title">
          <div className="bump-confirm__panel">
            <h2 id="bump-confirm-title">Write these files?</h2>
            <p>
              This changes files in <span className="mono">{selected.workspacePath}</span>.
              A <span className="mono">.orig</span> backup is written beside each one.
            </p>
            {/* The file list is the third gate, and the one the other two cannot stand in for:
                git and the backups both assume the right files were chosen. This is where a
                preview that resolved somewhere unexpected becomes visible before anything is
                written. */}
            <ul className="bump-confirm__files">
              {filesToWrite.map((file) => (
                <li key={file.path}>
                  <span className="mono">{file.path}</span>
                  <span>{file.editCount} edit{file.editCount === 1 ? '' : 's'}</span>
                </li>
              ))}
            </ul>
            {applyError && <div className="notice notice--warn" role="alert">{applyError}</div>}
            {applyError?.includes('confirm explicitly') && (
              <label className="bump-confirm__override">
                <input
                  type="checkbox"
                  checked={overrideGate}
                  onChange={(event) => setOverrideGate(event.target.checked)}
                />
                This workspace is not a git repository — apply anyway, with no git undo
              </label>
            )}
            <div className="bump-confirm__actions">
              <button type="button" className="button" disabled={applying}
                onClick={() => setConfirming(false)}>Cancel</button>
              <button
                type="button"
                className="button button--primary"
                disabled={applying}
                onClick={() => {
                  setApplying(true);
                  setApplyError(null);
                  applyBump(selected.id, filesToWrite.map((file) => ({
                    path: file.path,
                    fingerprint: file.fingerprint,
                    text: file.patched,
                  })), overrideGate)
                    .then((result) => {
                      setApplied(result);
                      setConfirming(false);
                    })
                    .catch((cause: unknown) => {
                      setApplyError(cause instanceof ApiError
                        ? cause.message
                        : 'The apply failed. Nothing was written.');
                    })
                    .finally(() => setApplying(false));
                }}
              >
                {applying ? 'Writing…' : 'Write files'}
              </button>
            </div>
          </div>
        </div>
      )}

      {applied && (
        <div className="notice" role="status">
          {applied.written.length > 0
            ? `Wrote ${applied.written.join(', ')}. Backups: ${applied.backups.join(', ')}.`
            : 'Nothing needed writing — every file already matched.'}
          {applied.skipped.length > 0 && ` Unchanged: ${applied.skipped.join(', ')}.`}
        </div>
      )}

      {error && <div className="notice notice--warn" role="alert">{error}</div>}
      {loading && <div className="empty-state">Building bump plan…</div>}

      {session && (
        <div className="bump-workspace">
          <section className="panel bump-rows" aria-labelledby="bump-rows-title">
            <h2 id="bump-rows-title" className="panel__title">Vulnerable declarations</h2>
            {session.state.plan.notes.length > 0 && (
              <section className="bump-note-group" aria-label="Plan notes">
                <h3 className="bump-note-group__title">Plan notes</h3>
                {session.state.plan.notes.map((note) => <p className="notice" key={note}>{note}</p>)}
              </section>
            )}
            {session.state.plan.lockfileNotes.length > 0 && (
              <section className="bump-note-group" aria-label="Lockfile notes">
                <h3 className="bump-note-group__title">Lockfile notes</h3>
                {session.state.plan.lockfileNotes.map((note) => <p className="notice" key={note}>{note}</p>)}
              </section>
            )}
            <div className="bump-rows__toolbar">
              <SearchField
                value={filter}
                onValueChange={setFilter}
                regex={filterRegex}
                onRegexChange={setFilterRegex}
                negate={filterNegate}
                onNegateChange={setFilterNegate}
                placeholder="Filter declarations"
                ariaLabel="Filter vulnerable declarations"
                note={matcher.error}
                inputClassName="bump-filter__input"
              />
              {/* The count is the filter's own feedback. Without it a pattern that matches
                  nothing is indistinguishable from a plan that found nothing — and on this
                  screen those two mean very different things. */}
              <span className="bump-rows__count">
                {filter
                  ? `${visibleRows.length} of ${session.state.plan.rows.length} declarations`
                  : `${session.state.plan.rows.length} declarations`}
              </span>
            </div>
            <div className="table-scroll">
              <table className="data-table bump-table">
                <thead><tr>
                  <th scope="col">Use</th><th scope="col">Declaration</th><th scope="col">Current</th>
                  <th scope="col">Minimal</th><th scope="col">Latest available</th>
                  <th scope="col">Target</th><th scope="col">Advisories</th>
                </tr></thead>
                <tbody>
                  {visibleRows.map((row) => (
                    <RowControls key={rowKey(row.site)} row={row} session={session}
                      notes={session.state.plan.notes} onChange={setSession} />
                  ))}
                </tbody>
              </table>
            </div>
            {/* A filter hides rows; it never deselects them. Saying so matters because the
                preview and Apply still carry every selected row, including ones scrolled out of
                sight by a pattern — silently applying an edit the user cannot see would be the
                worst version of this feature. */}
            {filter && visibleRows.length < session.state.plan.rows.length && (
              <p className="bump-rows__hidden-note">
                Filtered rows stay selected and are still written by Apply.
              </p>
            )}
          </section>

          <section className="panel bump-preview" aria-labelledby="bump-preview-title">
            <div className="bump-preview__header">
              <h2 id="bump-preview-title" className="panel__title">File preview</h2>
              <div className="bump-preview__controls">
                <div className="bump-file-tabs" role="tablist" aria-label="Preview files">
                  {previewFiles.map((file) => (
                    <button type="button" role="tab" aria-selected={file.path === shown?.path}
                      className="button" key={file.path} onClick={() => {
                        setOpenFile(file.path);
                        setCopyState('idle');
                      }}>
                      {file.path} <span>{file.editCount} {file.editCount === 1 ? 'edit' : 'edits'}</span>
                    </button>
                  ))}
                </div>
                <button type="button" className="button" disabled={!shown}
                  onClick={async () => {
                    try {
                      await navigator.clipboard.writeText(editorText);
                      setCopyState('copied');
                    } catch {
                      setCopyState('failed');
                    }
                  }}>
                  {copyState === 'copied' ? 'Copied' : 'Copy whole file'}
                </button>
              </div>
            </div>
            {copyState === 'failed' && (
              <p className="notice notice--warn" role="alert">Could not copy the displayed file.</p>
            )}
            {preview?.warnings.map((warning) => (
              <p className="notice notice--warn" key={warning}>{warning}</p>
            ))}
            {shown ? (
              <div className="bump-editor">
                <HighlightedText text={editorText} ranges={shown.changed} />
                <textarea
                  aria-label={`Edit ${shown.path}`}
                  spellCheck={false}
                  value={editorText}
                  onScroll={(event) => {
                    const highlighter = event.currentTarget.previousElementSibling;
                    if (highlighter instanceof HTMLElement) {
                      highlighter.scrollTop = event.currentTarget.scrollTop;
                      highlighter.scrollLeft = event.currentTarget.scrollLeft;
                    }
                  }}
                  onChange={(event) => setSession((current) => current
                    ? apply(current, { kind: 'editFile', path: shown.path, text: event.target.value })
                    : current)}
                />
              </div>
            ) : <div className="empty-state">No file is touched by the current selection.</div>}
          </section>
        </div>
      )}
    </>
  );
}
