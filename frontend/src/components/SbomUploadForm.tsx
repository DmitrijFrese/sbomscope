import { useRef, useState } from 'react';
import type { DragEvent, FormEvent } from 'react';

import { useSboms } from '../sboms/SbomProvider';
import type { UploadOutcome } from '../sboms/SbomProvider';

/** Rounded to whole units — an exact byte count tells the user nothing here. */
function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/**
 * Upload control for CycloneDX SBOMs, with the optional workspace path.
 *
 * <p>The path is offered here rather than later because it is validated at import
 * time — a typo should surface immediately, not when the workspace view is first opened.
 * It applies to every file in one batch, which is the honest limit of a single form: files
 * dropped together are being treated as one act.
 *
 * <p>The file control is a dropzone rather than a bare {@code <input type="file">}. The
 * native control renders its own "Choose file / no file selected" text at a width the
 * browser decides and refuses to ellipsize, so inside a 280px sidebar it was simply cut off.
 * A dropzone also makes the obvious gesture work: several SBOMs have just been generated
 * into a folder the user is already looking at.
 */
export function SbomUploadForm({ onDone }: { onDone: () => void }) {
  const { upload } = useSboms();
  const fileInput = useRef<HTMLInputElement>(null);

  const [files, setFiles] = useState<File[]>([]);
  const [dragging, setDragging] = useState(false);
  const [workspacePath, setWorkspacePath] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [outcomes, setOutcomes] = useState<UploadOutcome[]>([]);

  function choose(chosen: FileList | null | undefined) {
    if (!chosen || chosen.length === 0) return;
    setError(null);
    setOutcomes([]);

    // Checked here only to fail early with a clear message; the backend decides what is
    // genuinely a CycloneDX document, and an unhelpful extension is not proof either way.
    // The valid files are kept rather than discarded with them: rejecting a whole selection
    // because one name is wrong makes the user redo the part that was fine.
    const accepted: File[] = [];
    const rejected: string[] = [];
    for (const file of Array.from(chosen)) {
      if (file.name.toLowerCase().endsWith('.json')) {
        accepted.push(file);
      } else {
        rejected.push(file.name);
      }
    }

    if (rejected.length > 0) {
      setError(
        `${rejected.join(', ')} ${rejected.length === 1 ? 'is not a .json file' : 'are not .json files'}. ` +
          'SBOMscope reads CycloneDX in JSON.',
      );
    }
    if (accepted.length > 0) {
      setFiles(accepted);
    }
  }

  function onDrop(event: DragEvent<HTMLLabelElement>) {
    event.preventDefault();
    setDragging(false);
    choose(event.dataTransfer.files);
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (files.length === 0) {
      setError('Choose a CycloneDX JSON file first.');
      return;
    }

    setBusy(true);
    setError(null);
    setOutcomes([]);
    try {
      const results = await upload(files, workspacePath);
      const failed = results.filter((result) => result.error);

      // The form closes only when there is nothing left to read. With a partial failure it
      // stays open holding the per-file report — closing it would leave the sidebar showing
      // four new cards and no account of the fifth.
      if (failed.length === 0) {
        setWorkspacePath('');
        setFiles([]);
        if (fileInput.current) fileInput.current.value = '';
        onDone();
        return;
      }
      setOutcomes(results);
      setFiles([]);
      if (fileInput.current) fileInput.current.value = '';
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Upload failed.');
    } finally {
      setBusy(false);
    }
  }

  const totalSize = files.reduce((sum, file) => sum + file.size, 0);

  return (
    <form className="upload-form" onSubmit={submit}>
      {/* A label wrapping a visually-hidden input: clicking anywhere opens the picker, and
          the input still receives focus, so this works from the keyboard too. */}
      <label
        className="dropzone"
        data-dragging={dragging}
        data-selected={files.length > 0}
        onDragOver={(event) => {
          event.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
      >
        <input
          ref={fileInput}
          type="file"
          accept="application/json,.json"
          multiple
          className="visually-hidden"
          disabled={busy}
          onChange={(event) => choose(event.target.files)}
        />

        {files.length > 0 ? (
          <>
            <span
              className="dropzone__name"
              title={files.map((file) => file.name).join('\n')}
            >
              {files.length === 1 ? files[0]!.name : `${files.length} files`}
            </span>
            <span className="dropzone__hint">
              {formatSize(totalSize)} · click to replace
            </span>
          </>
        ) : (
          <>
            <span className="dropzone__name">Drop CycloneDX JSON files</span>
            <span className="dropzone__hint">or click to browse — several at once is fine</span>
          </>
        )}
      </label>

      <label className="field">
        <span className="field__label">Workspace path (optional)</span>
        <input
          type="text"
          value={workspacePath}
          placeholder="C:\path\to\your\project"
          disabled={busy}
          onChange={(event) => setWorkspacePath(event.target.value)}
        />
        <span className="field__hint">
          Needed only to detect whether vulnerable libraries are actually used in source.
          Applied to every file in this upload.
        </span>
      </label>

      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}

      {/* Per file, and both halves shown. A list of only the failures would leave the reader
          to work out which of five names is missing from it. */}
      {outcomes.length > 0 && (
        <ul className="upload-results" role="status">
          {/* Keyed by position, not by name: two files selected from different folders can
              carry the same name, and this list is never reordered or filtered. */}
          {outcomes.map((outcome, index) => (
            <li
              key={`${index}-${outcome.filename}`}
              className="upload-result"
              data-failed={outcome.error !== undefined}
            >
              <span className="upload-result__name" title={outcome.filename}>
                {outcome.filename}
              </span>
              <span className="upload-result__detail">
                {outcome.error ?? 'imported'}
              </span>
            </li>
          ))}
        </ul>
      )}

      <div className="upload-form__actions">
        <button type="submit" className="button button--primary" disabled={busy || files.length === 0}>
          {busy ? 'Importing…' : files.length > 1 ? `Import ${files.length} SBOMs` : 'Import SBOM'}
        </button>
        <button type="button" className="button" onClick={onDone} disabled={busy}>
          {outcomes.length > 0 ? 'Close' : 'Cancel'}
        </button>
      </div>
    </form>
  );
}
