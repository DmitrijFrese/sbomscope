import { useRef, useState } from 'react';
import type { DragEvent, FormEvent } from 'react';

import { useSboms } from '../sboms/SbomProvider';

/** Rounded to whole units — an exact byte count tells the user nothing here. */
function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/**
 * Upload control for a CycloneDX SBOM, with the optional workspace path.
 *
 * <p>The path is offered here rather than later because it is validated at import
 * time — a typo should surface immediately, not when the workspace view is first opened.
 *
 * <p>The file control is a dropzone rather than a bare {@code <input type="file">}. The
 * native control renders its own "Choose file / no file selected" text at a width the
 * browser decides and refuses to ellipsize, so inside a 280px sidebar it was simply cut off.
 * A dropzone also makes the obvious gesture work: an SBOM has just been generated into a
 * folder the user is already looking at.
 */
export function SbomUploadForm({ onDone }: { onDone: () => void }) {
  const { upload } = useSboms();
  const fileInput = useRef<HTMLInputElement>(null);

  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [workspacePath, setWorkspacePath] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function choose(chosen: File | null | undefined) {
    if (!chosen) return;
    setError(null);
    // Checked here only to fail early with a clear message; the backend decides what is
    // genuinely a CycloneDX document, and an unhelpful extension is not proof either way.
    if (!chosen.name.toLowerCase().endsWith('.json')) {
      setError(`${chosen.name} is not a .json file. SBOMscope reads CycloneDX in JSON.`);
      return;
    }
    setFile(chosen);
  }

  function onDrop(event: DragEvent<HTMLLabelElement>) {
    event.preventDefault();
    setDragging(false);
    const dropped = event.dataTransfer.files;
    if (dropped.length > 1) {
      setError('Drop one file at a time.');
      return;
    }
    choose(dropped[0]);
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!file) {
      setError('Choose a CycloneDX JSON file first.');
      return;
    }

    setBusy(true);
    setError(null);
    try {
      await upload(file, workspacePath);
      setWorkspacePath('');
      setFile(null);
      if (fileInput.current) fileInput.current.value = '';
      onDone();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Upload failed.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="upload-form" onSubmit={submit}>
      {/* A label wrapping a visually-hidden input: clicking anywhere opens the picker, and
          the input still receives focus, so this works from the keyboard too. */}
      <label
        className="dropzone"
        data-dragging={dragging}
        data-selected={file !== null}
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
          className="visually-hidden"
          disabled={busy}
          onChange={(event) => choose(event.target.files?.[0])}
        />

        {file ? (
          <>
            <span className="dropzone__name" title={file.name}>
              {file.name}
            </span>
            <span className="dropzone__hint">{formatSize(file.size)} · click to replace</span>
          </>
        ) : (
          <>
            <span className="dropzone__name">Drop a CycloneDX JSON file</span>
            <span className="dropzone__hint">or click to browse</span>
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
        </span>
      </label>

      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}

      <div className="upload-form__actions">
        <button type="submit" className="button button--primary" disabled={busy || !file}>
          {busy ? 'Importing…' : 'Import SBOM'}
        </button>
        <button type="button" className="button" onClick={onDone} disabled={busy}>
          Cancel
        </button>
      </div>
    </form>
  );
}
