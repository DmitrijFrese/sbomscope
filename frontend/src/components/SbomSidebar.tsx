import { useState } from 'react';
import type { FormEvent } from 'react';

import { siblingNameTaken } from '../sboms/folderTree';
import { useSboms } from '../sboms/SbomProvider';
import { SbomUploadForm } from './SbomUploadForm';
import { SidebarTree } from './SidebarTree';
import { ChevronLeftIcon, ChevronRightIcon } from './icons';

interface SbomSidebarProps {
  collapsed: boolean;
  onToggleCollapsed: () => void;
}

/** Lists uploaded SBOMs, organised into projects and folders (B19). Selection drives both main views. */
export function SbomSidebar({ collapsed, onToggleCollapsed }: SbomSidebarProps) {
  const { sboms, folders, loading, error, createFolder } = useSboms();
  const [uploading, setUploading] = useState(false);
  const [creatingProject, setCreatingProject] = useState(false);
  const [projectName, setProjectName] = useState('');
  const [createError, setCreateError] = useState<string | null>(null);

  // Collapsed leaves a rail rather than nothing at all: a sidebar that vanishes entirely
  // gives no clue how to bring it back, and the count is worth keeping in view.
  if (collapsed) {
    return (
      <aside className="sidebar sidebar--rail" aria-label="Uploaded SBOMs">
        <button
          type="button"
          className="icon-button"
          onClick={onToggleCollapsed}
          aria-expanded={false}
          aria-label="Expand the SBOM list"
          title="Expand the SBOM list"
        >
          <ChevronRightIcon className="navitem__icon" />
        </button>
        <span className="sidebar__rail-label" aria-hidden="true">
          SBOMs
        </span>
        <span className="sidebar__rail-count">{sboms.length}</span>
      </aside>
    );
  }

  // Checked as the reader types, against the folder list the sidebar already holds — the
  // backend enforces the same rule and stays the authority, but there is no reason to make
  // someone submit a name only to have it come back red.
  const projectNameTaken = siblingNameTaken(folders, undefined, projectName);
  const canCreateProject = projectName.trim().length > 0 && !projectNameTaken;

  async function submitNewProject(event: FormEvent) {
    event.preventDefault();
    if (!canCreateProject) return;
    setCreateError(null);
    try {
      await createFolder(projectName);
      setProjectName('');
      setCreatingProject(false);
    } catch (e) {
      setCreateError(e instanceof Error ? e.message : 'Could not create that project.');
    }
  }

  return (
    <aside className="sidebar" aria-label="Uploaded SBOMs">
      <div className="sidebar__header">
        <h2 className="sidebar__title">SBOMs</h2>
        <div className="sidebar__header-actions">
          <button
            type="button"
            className="button button--small"
            onClick={() => setCreatingProject((open) => !open)}
            aria-expanded={creatingProject}
          >
            {creatingProject ? 'Close' : 'New project'}
          </button>
          <button
            type="button"
            className="button button--small"
            onClick={() => setUploading((open) => !open)}
            aria-expanded={uploading}
          >
            {uploading ? 'Close' : 'Upload'}
          </button>
          <button
            type="button"
            className="icon-button"
            onClick={onToggleCollapsed}
            aria-expanded={true}
            aria-label="Collapse the SBOM list"
            title="Collapse the SBOM list"
          >
            <ChevronLeftIcon className="navitem__icon" />
          </button>
        </div>
      </div>

      {uploading && <SbomUploadForm onDone={() => setUploading(false)} />}

      {creatingProject && (
        <form className="sidebar__new-project" onSubmit={submitNewProject}>
          <div className="folder-name-form__row">
            <input
              type="text"
              value={projectName}
              onChange={(event) => setProjectName(event.target.value)}
              placeholder="Project name"
              autoFocus
              aria-invalid={projectNameTaken}
            />
            <button type="submit" className="button button--small" disabled={!canCreateProject}>
              Create
            </button>
          </div>
          {projectNameTaken && (
            <p className="folder-name-form__note" role="status">
              There is already a project called "{projectName.trim()}".
            </p>
          )}
        </form>
      )}

      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      {createError && (
        <p className="form-error" role="alert">
          {createError}
        </p>
      )}

      {loading && sboms.length === 0 && folders.length === 0 && (
        <p className="sidebar__note">Loading…</p>
      )}

      {!loading && sboms.length === 0 && folders.length === 0 && !uploading && !creatingProject && (
        <div className="sidebar__empty">
          <div className="empty-state">
            <p style={{ margin: 0 }}>No SBOMs uploaded yet.</p>
          </div>
        </div>
      )}

      {(sboms.length > 0 || folders.length > 0) && <SidebarTree />}
    </aside>
  );
}
