/**
 * Assembles the sidebar's tree from two flat lists (B19).
 *
 * <p>Pure functions, deliberately separate from the sidebar component: the backend sends
 * `folder[]` and `sbom[]` flat — a tree over the wire would have to be rebuilt anyway to
 * interleave documents in, and keeping the assembly here makes it testable without React.
 */
import type { Folder, Sbom, SeverityBand } from '../api/client';
import { CARD_BANDS } from './severityRollup';

/**
 * A project, plus two levels beneath it. Mirrors `FolderService.MAX_DEPTH` on the backend —
 * duplicated rather than fetched, because it decides whether a UI control is offered at all,
 * and the backend is still the authority that enforces it: this only avoids offering a
 * "New subfolder" button that would immediately fail.
 */
export const MAX_FOLDER_DEPTH = 3;

export interface FolderNode {
  folder: Folder;
  children: FolderNode[];
  sboms: Sbom[];
}

export interface FolderTree {
  /** Projects — folders with no parent — sorted by name. */
  roots: FolderNode[];
  /** Documents filed nowhere, newest first, matching the backend's own ordering. */
  looseSboms: Sbom[];
}

/**
 * Moves one id to sit before or after another, and returns the new order.
 *
 * <p>Used for reordering within a sibling group. Removing first and then inserting is what
 * makes "after the row that was above me" behave: computing the destination index against the
 * original array would be off by one whenever an item moves downward.
 */
export function reorderWithin(
  ids: string[],
  movingId: string,
  relativeToId: string,
  edge: 'before' | 'after',
): string[] {
  if (movingId === relativeToId) return ids;
  const without = ids.filter((id) => id !== movingId);
  const anchor = without.indexOf(relativeToId);
  if (anchor < 0) return ids;
  const at = edge === 'before' ? anchor : anchor + 1;
  return [...without.slice(0, at), movingId, ...without.slice(at)];
}

/**
 * @param folders every project and folder, flat
 * @param sboms   every document, flat, already ordered newest-first by the backend
 */
export function buildFolderTree(folders: Folder[], sboms: Sbom[]): FolderTree {
  const byParent = new Map<string, Folder[]>();
  for (const folder of folders) {
    const key = folder.parentId ?? '';
    const siblings = byParent.get(key) ?? [];
    siblings.push(folder);
    byParent.set(key, siblings);
  }

  const sbomsByFolder = new Map<string, Sbom[]>();
  const looseSboms: Sbom[] = [];
  for (const sbom of sboms) {
    if (sbom.folderId) {
      const held = sbomsByFolder.get(sbom.folderId) ?? [];
      held.push(sbom);
      sbomsByFolder.set(sbom.folderId, held);
    } else {
      looseSboms.push(sbom);
    }
  }

  // No sorting here. Since V10 the backend returns both lists already in display order —
  // manual `sort_order` first, name or upload date as the tie-break — so re-sorting on the
  // client would silently discard the reader's own arrangement.
  function buildNode(folder: Folder): FolderNode {
    return {
      folder,
      children: (byParent.get(folder.id) ?? []).map(buildNode),
      sboms: sbomsByFolder.get(folder.id) ?? [],
    };
  }

  const roots = (byParent.get('') ?? []).map(buildNode);
  return { roots, looseSboms };
}

/**
 * Every document under a project, at any depth — what a project row's severity rollup and
 * a "delete this project" confirmation both need to know about.
 */
export function sbomsUnder(node: FolderNode): Sbom[] {
  return [...node.sboms, ...node.children.flatMap(sbomsUnder)];
}

/**
 * Summed severity counts across every document under a project, recursively.
 *
 * <p>Read from `Sbom.severityCounts`, which the sidebar already fetches for the flat list —
 * this is arithmetic over data already on the client, not a second query.
 */
export function rollupSeverity(node: FolderNode): Partial<Record<SeverityBand, number>> {
  const totals: Partial<Record<SeverityBand, number>> = {};
  for (const sbom of sbomsUnder(node)) {
    for (const band of CARD_BANDS) {
      const count = sbom.severityCounts[band] ?? 0;
      if (count > 0) {
        totals[band] = (totals[band] ?? 0) + count;
      }
    }
  }
  return totals;
}

export interface FolderOption {
  id: string;
  name: string;
  /** 0 for a project. Used to indent the option in the "Move to…" control. */
  depth: number;
}

/**
 * Every folder as a flat, depth-labelled list, in the same order the tree renders — what
 * the "Move to…" control's `<select>` needs, since an `<option>` cannot be styled with CSS
 * indentation reliably across browsers.
 */
export function flattenFolderOptions(roots: FolderNode[], depth = 0): FolderOption[] {
  return roots.flatMap((node) => [
    { id: node.folder.id, name: node.folder.name, depth },
    ...flattenFolderOptions(node.children, depth + 1),
  ]);
}

/** A folder's id plus every folder beneath it — what "move" must refuse as a destination. */
export function descendantIds(node: FolderNode): Set<string> {
  const ids = new Set<string>([node.folder.id]);
  for (const child of node.children) {
    for (const id of descendantIds(child)) {
      ids.add(id);
    }
  }
  return ids;
}

/** Finds a node anywhere in the tree by folder id, for locating a folder before moving it. */
export function findNode(roots: FolderNode[], folderId: string): FolderNode | null {
  for (const node of roots) {
    if (node.folder.id === folderId) return node;
    const found = findNode(node.children, folderId);
    if (found) return found;
  }
  return null;
}

// --- move rules, computed from the flat list -------------------------------------------
//
// These mirror FolderService's checks so the UI can refuse an impossible move *before* it is
// attempted — greying out a drop target rather than letting a drag land and then fail. The
// backend stays the authority: two browser tabs, or a stale list, can still race, and the
// server's error is what the user sees if they do. This only avoids offering the impossible.

/**
 * Whether a sibling already carries this name, compared case-insensitively.
 *
 * <p>Matches `FolderRepository.siblingNameExists`, including that it scopes to the parent —
 * "backend" under two different projects is the ordinary case, not a collision.
 */
export function siblingNameTaken(
  folders: Folder[],
  parentId: string | undefined,
  name: string,
  excludingId?: string,
): boolean {
  const wanted = name.trim().toLowerCase();
  if (!wanted) return false;
  return folders.some(
    (folder) =>
      folder.id !== excludingId &&
      (folder.parentId ?? undefined) === (parentId ?? undefined) &&
      folder.name.trim().toLowerCase() === wanted,
  );
}

/** 1 for a project, counting up through the parent chain. Bounded so a cycle cannot hang. */
function depthOfId(folders: Folder[], id: string | undefined): number {
  let depth = 0;
  let cursor = id;
  while (cursor && depth <= MAX_FOLDER_DEPTH) {
    depth++;
    cursor = folders.find((f) => f.id === cursor)?.parentId;
  }
  return depth;
}

/** 1 for a folder with no children — how many levels the subtree occupies. */
function heightOfId(folders: Folder[], id: string): number {
  const children = folders.filter((f) => f.parentId === id);
  return children.length === 0
    ? 1
    : 1 + Math.max(...children.map((child) => heightOfId(folders, child.id)));
}

function isDescendantOf(folders: Folder[], candidate: string, ancestor: string): boolean {
  let cursor: string | undefined = candidate;
  let guard = 0;
  while (cursor && guard++ <= MAX_FOLDER_DEPTH + 1) {
    if (cursor === ancestor) return true;
    cursor = folders.find((f) => f.id === cursor)?.parentId;
  }
  return false;
}

/** Why a move cannot happen, or that it can. `reason` is written to be shown to the reader. */
export interface MoveCheck {
  ok: boolean;
  reason?: string;
}

const ALLOWED: MoveCheck = { ok: true };

/**
 * Whether a folder may move under `targetParentId` (undefined meaning the top level).
 *
 * <p>Four refusals, in the order a reader would notice them: it is already there, it would
 * contain itself, the subtree it carries would not fit, or the name is taken where it lands.
 * The third is the one that is easy to get wrong — the limit applies to the **height of what
 * is being dragged**, not to the folder alone, so a two-level branch cannot go under a
 * level-2 folder even though the folder itself would fit.
 */
export function canMoveFolder(
  folders: Folder[],
  folderId: string,
  targetParentId: string | undefined,
): MoveCheck {
  const folder = folders.find((f) => f.id === folderId);
  if (!folder) return { ok: false, reason: 'That folder no longer exists.' };

  if ((folder.parentId ?? undefined) === (targetParentId ?? undefined)) {
    return { ok: false, reason: 'Already here.' };
  }
  if (targetParentId === folderId) {
    return { ok: false, reason: 'A folder cannot go inside itself.' };
  }
  if (targetParentId && isDescendantOf(folders, targetParentId, folderId)) {
    return { ok: false, reason: `"${folder.name}" cannot go inside something it contains.` };
  }

  const targetDepth = targetParentId ? depthOfId(folders, targetParentId) : 0;
  const subtreeHeight = heightOfId(folders, folderId);
  if (targetDepth + subtreeHeight > MAX_FOLDER_DEPTH) {
    return {
      ok: false,
      reason: `Folders go ${MAX_FOLDER_DEPTH} levels deep, and "${folder.name}" brings ${
        subtreeHeight === 1 ? 'itself' : `${subtreeHeight} levels`
      }.`,
    };
  }
  if (siblingNameTaken(folders, targetParentId, folder.name, folderId)) {
    return { ok: false, reason: `There is already a folder called "${folder.name}" here.` };
  }
  return ALLOWED;
}

/**
 * Whether a document may move into `targetFolderId` (undefined meaning outside every project).
 *
 * <p>Deliberately laxer than a folder move: two documents may share a filename — uploading the
 * same SBOM twice is a real thing people do — so only "already there" is refused.
 */
export function canMoveSbom(sbom: Sbom, targetFolderId: string | undefined): MoveCheck {
  return (sbom.folderId ?? undefined) === (targetFolderId ?? undefined)
    ? { ok: false, reason: 'Already here.' }
    : ALLOWED;
}
