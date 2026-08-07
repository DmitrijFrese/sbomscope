import { describe, expect, it } from 'vitest';

import {
  buildFolderTree,
  canMoveFolder,
  canMoveSbom,
  descendantIds,
  findNode,
  flattenFolderOptions,
  reorderWithin,
  rollupSeverity,
  sbomsUnder,
  siblingNameTaken,
} from './folderTree';
import type { Folder, Sbom } from '../api/client';

function folder(id: string, name: string, parentId?: string): Folder {
  return { id, name, parentId, createdAt: '2026-08-06T00:00:00Z' };
}

function sbom(id: string, filename: string, folderId?: string, critical = 0): Sbom {
  return {
    id,
    filename,
    uploadedAt: '2026-08-06T00:00:00Z',
    specVersion: '1.6',
    componentCount: 1,
    scannedComponents: 1,
    severityCounts: critical > 0 ? { CRITICAL: critical } : {},
    scanning: false,
    folderId,
  };
}

/**
 * Building the tree from the two flat lists the backend sends.
 *
 * <p>The shape worth pinning is the one the sidebar asked for: folders and loose documents
 * both need to be reachable at the same level, and nesting has to be exact rather than
 * approximate, since a document filed under the wrong node would look uploaded correctly
 * and simply never appear where the reader is looking.
 */
describe('buildFolderTree', () => {
  it('separates loose documents from ones filed into a project', () => {
    const folders = [folder('p1', 'Payments')];
    const sboms = [sbom('s1', 'loose.cdx.json'), sbom('s2', 'filed.cdx.json', 'p1')];

    const tree = buildFolderTree(folders, sboms);

    expect(tree.looseSboms.map((s) => s.id)).toEqual(['s1']);
    expect(tree.roots[0]!.sboms.map((s) => s.id)).toEqual(['s2']);
  });

  it('nests a subfolder under its project, two levels deep', () => {
    const folders = [
      folder('project', 'Payments'),
      folder('backend', 'backend', 'project'),
      folder('modules', 'modules', 'backend'),
    ];
    const tree = buildFolderTree(folders, []);

    const project = tree.roots[0]!;
    expect(project.folder.name).toBe('Payments');
    expect(project.children[0]!.folder.name).toBe('backend');
    expect(project.children[0]!.children[0]!.folder.name).toBe('modules');
  });

  it('preserves the order the backend sent, rather than re-sorting', () => {
    // Since V10 the display order is stored, so the server's order is the reader's own
    // arrangement. Sorting here — as this did until 2026-08-07 — would silently discard it.
    const folders = [folder('b', 'Zebra'), folder('a', 'Alpha')];
    const tree = buildFolderTree(folders, []);

    expect(tree.roots.map((n) => n.folder.name)).toEqual(['Zebra', 'Alpha']);
  });
});

describe('reorderWithin', () => {
  it('moves an item downward to the right place, not one short of it', () => {
    // The off-by-one this exists to prevent: computing the destination against the original
    // array puts a downward move one position too high, because the item is still in front
    // of the anchor while the index is taken.
    expect(reorderWithin(['a', 'b', 'c', 'd'], 'a', 'c', 'after')).toEqual(['b', 'c', 'a', 'd']);
  });

  it('moves an item upward', () => {
    expect(reorderWithin(['a', 'b', 'c', 'd'], 'd', 'b', 'before')).toEqual(['a', 'd', 'b', 'c']);
  });

  it('is a no-op when the item is dropped on itself or against something absent', () => {
    expect(reorderWithin(['a', 'b'], 'a', 'a', 'before')).toEqual(['a', 'b']);
    expect(reorderWithin(['a', 'b'], 'a', 'zz', 'after')).toEqual(['a', 'b']);
  });
});

describe('rollupSeverity and sbomsUnder', () => {
  it('sums severity counts across every document at every depth, not just the top', () => {
    const folders = [folder('project', 'Payments'), folder('sub', 'backend', 'project')];
    const sboms = [
      sbom('s1', 'api.cdx.json', 'project', 3),
      sbom('s2', 'worker.cdx.json', 'sub', 5),
    ];
    const tree = buildFolderTree(folders, sboms);

    const project = tree.roots[0]!;
    expect(sbomsUnder(project).map((s) => s.id).sort()).toEqual(['s1', 's2']);
    expect(rollupSeverity(project).CRITICAL).toBe(8);
  });

  it('omits a band entirely rather than reporting a zero for it', () => {
    // The chip rendering treats a present-but-zero band differently from an absent one
    // (dimmed vs. never drawn); the rollup must not manufacture zeros nothing actually had.
    const folders = [folder('project', 'Payments')];
    const sboms = [sbom('s1', 'clean.cdx.json', 'project', 0)];
    const tree = buildFolderTree(folders, sboms);

    expect(rollupSeverity(tree.roots[0]!)).toEqual({});
  });
});

describe('descendantIds', () => {
  it('includes the folder itself and every folder beneath it, and nothing else', () => {
    const folders = [
      folder('project', 'Payments'),
      folder('backend', 'backend', 'project'),
      folder('modules', 'modules', 'backend'),
      folder('other-project', 'Shipping'),
    ];
    const tree = buildFolderTree(folders, []);
    const project = findNode(tree.roots, 'project')!;

    const ids = descendantIds(project);
    expect(ids).toEqual(new Set(['project', 'backend', 'modules']));
    expect(ids.has('other-project')).toBe(false);
  });
});

/**
 * The "Move to…" control's option list. The case worth pinning: a folder must never be
 * offered as its own destination or as a destination inside itself, since the depth and
 * cycle checks live on the backend and a stale client-side list would let a doomed request
 * through with no explanation beyond a generic error.
 */
describe('flattenFolderOptions', () => {
  it('labels each option with its depth, for the text-prefix indent the <select> uses', () => {
    const folders = [
      folder('project', 'Payments'),
      folder('backend', 'backend', 'project'),
    ];
    const tree = buildFolderTree(folders, []);

    const options = flattenFolderOptions(tree.roots);
    expect(options).toEqual([
      { id: 'project', name: 'Payments', depth: 0 },
      { id: 'backend', name: 'backend', depth: 1 },
    ]);
  });
});

/**
 * The client-side copy of FolderService's move rules.
 *
 * <p>These exist so the UI can refuse an impossible drop *before* it lands, rather than
 * letting a drag succeed visually and then fail on the server. They are a mirror, never the
 * authority — hence the tests pin the same boundaries the backend tests pin, so the two
 * cannot drift into disagreeing about what is legal.
 */
describe('siblingNameTaken', () => {
  it('compares case-insensitively, like the backend does', () => {
    const folders = [folder('a', 'Payments')];
    expect(siblingNameTaken(folders, undefined, 'payments')).toBe(true);
    expect(siblingNameTaken(folders, undefined, '  PAYMENTS  ')).toBe(true);
  });

  it('scopes to the parent, so the same name under two projects is fine', () => {
    const folders = [
      folder('p1', 'Project A'),
      folder('p2', 'Project B'),
      folder('b1', 'backend', 'p1'),
    ];
    expect(siblingNameTaken(folders, 'p1', 'backend')).toBe(true);
    expect(siblingNameTaken(folders, 'p2', 'backend')).toBe(false);
  });

  it('excludes the folder being renamed, so renaming to its own name is not a collision', () => {
    const folders = [folder('a', 'Payments')];
    expect(siblingNameTaken(folders, undefined, 'Payments', 'a')).toBe(false);
  });
});

describe('canMoveFolder', () => {
  const folders = [
    folder('project', 'Payments'),
    folder('backend', 'backend', 'project'),
    folder('deep', 'deep', 'backend'),
    folder('other', 'Shipping'),
    folder('clash', 'backend', 'other'),
  ];

  it('refuses a move to where it already is', () => {
    expect(canMoveFolder(folders, 'backend', 'project')).toMatchObject({ ok: false });
  });

  it('refuses a folder into itself or into its own descendant', () => {
    expect(canMoveFolder(folders, 'project', 'project').ok).toBe(false);
    expect(canMoveFolder(folders, 'project', 'deep')).toMatchObject({
      ok: false,
      reason: expect.stringContaining('contains'),
    });
  });

  it('measures the depth limit against the height of the subtree, not the folder alone', () => {
    // `backend` carries `deep`, so landing it under a level-2 folder would put `deep` at
    // level 4. The folder itself would have fitted — the subtree is what does not.
    expect(canMoveFolder(folders, 'backend', 'clash')).toMatchObject({
      ok: false,
      reason: expect.stringContaining('levels deep'),
    });
  });

  it('refuses a move where the name is already taken at the destination', () => {
    // `other` already contains a "backend"; moving the other one in would collide.
    expect(canMoveFolder(folders, 'backend', 'other')).toMatchObject({
      ok: false,
      reason: expect.stringContaining('already a folder called'),
    });
  });

  it('allows a legal move to the top level', () => {
    expect(canMoveFolder(folders, 'deep', undefined)).toEqual({ ok: true });
  });
});

describe('canMoveSbom', () => {
  it('refuses only a move to where it already is', () => {
    expect(canMoveSbom(sbom('s', 'a.json', 'p1'), 'p1').ok).toBe(false);
    expect(canMoveSbom(sbom('s', 'a.json', 'p1'), 'p2')).toEqual({ ok: true });
    expect(canMoveSbom(sbom('s', 'a.json'), undefined).ok).toBe(false);
  });

  it('allows two documents to share a filename in one folder', () => {
    // Uploading the same SBOM twice is a real thing people do, so unlike folders there is
    // no name rule for documents at all.
    expect(canMoveSbom(sbom('s2', 'same.json'), 'p1')).toEqual({ ok: true });
  });
});
