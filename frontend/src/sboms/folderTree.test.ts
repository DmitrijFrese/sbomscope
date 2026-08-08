import { describe, expect, it } from 'vitest';

import {
  buildFolderTree,
  canMoveFolder,
  canMoveSbom,
  descendantIds,
  findNode,
  flattenFolderOptions,
  contributingSboms,
  reorderWithin,
  representativeSbom,
  rollupSeverity,
  sbomsUnder,
  siblingNameTaken,
} from './folderTree';
import type { Folder, RollupMode, Sbom } from '../api/client';

function folder(id: string, name: string, parentId?: string, rollupMode?: RollupMode): Folder {
  return { id, name, parentId, createdAt: '2026-08-06T00:00:00Z', rollupMode };
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

/**
 * The rollup modes (V11).
 *
 * <p>The property under all of these is that **a sum is only sound over disjoint things**. The
 * cases worth pinning are therefore the ones where a mode changes what an *ancestor* sees, not
 * only what the folder itself draws — a mode that stopped at the row would leave the same
 * double-count one level up, which is the bug this exists to remove.
 */
describe('rollup modes', () => {
  it('defaults to summing when the folder names no mode at all', () => {
    // A response predating V11, or any folder nobody has touched. The default is what keeps
    // this an added exception rather than a withdrawn feature.
    const tree = buildFolderTree(
      [folder('project', 'Payments')],
      [sbom('s1', 'a.cdx.json', 'project', 3), sbom('s2', 'b.cdx.json', 'project', 4)],
    );
    expect(rollupSeverity(tree.roots[0]!).CRITICAL).toBe(7);
  });

  it('CURRENT counts only the first document in display order, not the sum', () => {
    const tree = buildFolderTree(
      [folder('versions', 'Checkout', undefined, 'CURRENT')],
      [
        sbom('v3', 'checkout-1.3.cdx.json', 'versions', 2),
        sbom('v2', 'checkout-1.2.cdx.json', 'versions', 5),
        sbom('v1', 'checkout-1.1.cdx.json', 'versions', 9),
      ],
    );

    const node = tree.roots[0]!;
    expect(representativeSbom(node)?.id).toBe('v3');
    expect(rollupSeverity(node).CRITICAL).toBe(2);
  });

  it('CURRENT follows the reader dragging a different version to the top', () => {
    // The backend returns display order, so "the top one" is whatever sort_order says. This
    // is the whole reason the row carries a visible "current" mark: the rule is positional.
    const tree = buildFolderTree(
      [folder('versions', 'Checkout', undefined, 'CURRENT')],
      [
        sbom('v1', 'checkout-1.1.cdx.json', 'versions', 9),
        sbom('v3', 'checkout-1.3.cdx.json', 'versions', 2),
      ],
    );
    expect(rollupSeverity(tree.roots[0]!).CRITICAL).toBe(9);
  });

  it('CURRENT with only direct documents contributes exactly the top one upward, so an ancestor stays a sum of disjoint things', () => {
    const folders = [
      folder('project', 'Payments'),
      folder('versions', 'Checkout releases', 'project', 'CURRENT'),
    ];
    const sboms = [
      sbom('api', 'api.cdx.json', 'project', 1),
      sbom('v2', 'checkout-1.2.cdx.json', 'versions', 2),
      sbom('v1', 'checkout-1.1.cdx.json', 'versions', 40),
    ];
    const tree = buildFolderTree(folders, sboms);

    // 1 (the module) + 2 (the current version) — never 43.
    expect(rollupSeverity(tree.roots[0]!).CRITICAL).toBe(3);
  });

  /**
   * The maintainer's own scenario, verbatim: "I might have several sboms of the same
   * application and just want one version considered. The folders might contain sboms of sub
   * modules that I want to count towards the total sum." Raised 2026-08-08 after the first
   * version of CURRENT picked only the single topmost child of either kind, silently dropping
   * whichever subfolders did not happen to sit first — this is the test that would have caught
   * it, and every case in it is load-bearing: a subfolder that sums, a subfolder that is muted
   * (and must still be excluded), and direct siblings where only the top one may count.
   */
  it('CURRENT sums every subfolder unconditionally and picks only the top direct document', () => {
    const folders = [
      folder('app', 'MyApp', undefined, 'CURRENT'),
      folder('backend', 'backend', 'app'), // SUM by default — a submodule, always included
      folder('archived', 'archived', 'app', 'MUTED'), // explicitly excluded, even as a submodule
    ];
    const sboms = [
      // Three whole-app snapshots directly in MyApp — only the top one should count.
      sbom('v3', 'myapp-v3.cdx.json', 'app', 2),
      sbom('v2', 'myapp-v2.cdx.json', 'app', 5),
      sbom('v1', 'myapp-v1.cdx.json', 'app', 9),
      // The backend submodule's own SBOMs — always included, not competing with the snapshots.
      sbom('bapi', 'backend-api.cdx.json', 'backend', 3),
      sbom('bworker', 'backend-worker.cdx.json', 'backend', 1),
      // Sits in a muted subfolder — must not appear in the sum despite being a "submodule".
      sbom('old', 'old-snapshot.cdx.json', 'archived', 100),
    ];
    const tree = buildFolderTree(folders, sboms);
    const app = tree.roots[0]!;

    expect(representativeSbom(app)?.id).toBe('v3');
    // 2 (top snapshot) + 3 + 1 (backend, unconditionally) — never touching v2, v1 or the
    // muted archive's 100.
    expect(rollupSeverity(app).CRITICAL).toBe(6);
  });

  it('MUTED contributes nothing to itself or to any ancestor', () => {
    const folders = [
      folder('project', 'Payments'),
      folder('scratch', 'Scratch', 'project', 'MUTED'),
    ];
    const sboms = [
      sbom('api', 'api.cdx.json', 'project', 1),
      sbom('old', 'old.cdx.json', 'scratch', 99),
    ];
    const tree = buildFolderTree(folders, sboms);
    const project = tree.roots[0]!;
    const scratch = project.children[0]!;

    expect(rollupSeverity(scratch)).toEqual({});
    expect(rollupSeverity(project).CRITICAL).toBe(1);
  });

  it('muting a folder does not mute what is inside it', () => {
    // Muting stops what crosses this folder's boundary. A folder inside it still aggregates
    // and still shows its own numbers on its own row — otherwise "mute" would silently mean
    // "hide everything below", which is a much larger claim than the menu item makes.
    const folders = [
      folder('scratch', 'Scratch', undefined, 'MUTED'),
      folder('inner', 'Still counted here', 'scratch'),
    ];
    const tree = buildFolderTree(folders, [sbom('s1', 'a.cdx.json', 'inner', 7)]);
    const scratch = tree.roots[0]!;

    expect(rollupSeverity(scratch)).toEqual({});
    expect(rollupSeverity(scratch.children[0]!).CRITICAL).toBe(7);
  });

  it('a CURRENT folder with no direct documents sums every subfolder, picking none of them', () => {
    // No sibling documents to choose among, so there is no "current" pick at this level at
    // all — every subfolder counts, the same as SUM would, because a subfolder is never in
    // competition with anything for the slot only direct documents compete for.
    const folders = [
      folder('versions', 'Checkout', undefined, 'CURRENT'),
      folder('latest', '1.3', 'versions'),
      folder('older', '1.2', 'versions'),
    ];
    const tree = buildFolderTree(folders, [
      sbom('v3', 'checkout-1.3.cdx.json', 'latest', 2),
      sbom('v2', 'checkout-1.2.cdx.json', 'older', 8),
    ]);

    expect(representativeSbom(tree.roots[0]!)).toBeNull();
    expect(rollupSeverity(tree.roots[0]!).CRITICAL).toBe(10);
  });

  it('a CURRENT folder picks its own top document but still sums a subfolder alongside it', () => {
    // The direct document still wins the "which version" pick — that part is unchanged — but
    // a subfolder is a different kind of claim entirely (a submodule, not an alternate
    // version) and is summed in regardless of the pick, not discarded by it.
    const folders = [
      folder('versions', 'Checkout', undefined, 'CURRENT'),
      folder('archive', 'Archive', 'versions'),
    ];
    const tree = buildFolderTree(folders, [
      sbom('archived', 'old.cdx.json', 'archive', 30),
      sbom('here', 'current.cdx.json', 'versions', 4),
    ]);

    expect(representativeSbom(tree.roots[0]!)?.id).toBe('here');
    expect(rollupSeverity(tree.roots[0]!).CRITICAL).toBe(34);
  });

  it('a muted subfolder is excluded from a CURRENT folder\'s unconditional subfolder sum', () => {
    const folders = [
      folder('versions', 'Checkout', undefined, 'CURRENT'),
      folder('muted', 'Ignore me', 'versions', 'MUTED'),
      folder('real', 'Releases', 'versions'),
    ];
    const tree = buildFolderTree(folders, [
      sbom('hidden', 'hidden.cdx.json', 'muted', 50),
      sbom('shown', 'shown.cdx.json', 'real', 6),
    ]);

    // No direct documents, so nothing is "current" here — only the unconditional subfolder
    // sum, and the muted one still contributes nothing to it.
    expect(representativeSbom(tree.roots[0]!)).toBeNull();
    expect(rollupSeverity(tree.roots[0]!).CRITICAL).toBe(6);
  });

  it('sbomsUnder still reports everything beneath, whatever the modes say', () => {
    // Delete confirmations and the "of n versions" note count documents, not contributions —
    // a muted folder still relocates all of them when it is deleted.
    const folders = [
      folder('project', 'Payments'),
      folder('scratch', 'Scratch', 'project', 'MUTED'),
    ];
    const tree = buildFolderTree(folders, [
      sbom('api', 'api.cdx.json', 'project', 1),
      sbom('old', 'old.cdx.json', 'scratch', 99),
    ]);
    const project = tree.roots[0]!;

    expect(sbomsUnder(project).map((s) => s.id).sort()).toEqual(['api', 'old']);
    expect(contributingSboms(project).map((s) => s.id)).toEqual(['api']);
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
