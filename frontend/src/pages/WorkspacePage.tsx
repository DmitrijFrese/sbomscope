import { useSboms } from '../sboms/SbomProvider';

/**
 * Second view: where a vulnerable library is actually referenced in source, with
 * per-hit previews. Scanning itself is implemented in Phase 7; this already reflects
 * whether the selected SBOM has a workspace to scan at all.
 */
export function WorkspacePage() {
  const { selected } = useSboms();

  return (
    <>
      <div className="page-header">
        <h1>Workspace</h1>
        <p>Where vulnerable libraries are referenced in your source tree.</p>
      </div>

      {!selected && (
        <div className="empty-state">
          <p style={{ margin: 0 }}>Upload an SBOM, or select one from the sidebar.</p>
        </div>
      )}

      {selected && !selected.workspacePath && (
        <div className="empty-state">
          <p style={{ margin: 0 }}>
            <strong>{selected.filename}</strong> was imported without a workspace path.
          </p>
          <p style={{ marginBottom: 0 }}>
            Re-import it with a path to your source tree to detect which libraries are
            actually used.
          </p>
        </div>
      )}

      {selected?.workspacePath && (
        <>
          <div className="notice">
            Scanning is implemented in a later phase. This SBOM is linked to a workspace
            and will be scanned from here.
          </div>
          <div className="panel">
            <h2 className="panel__title">Workspace</h2>
            <p className="panel__hint mono">{selected.workspacePath}</p>
          </div>
        </>
      )}
    </>
  );
}
