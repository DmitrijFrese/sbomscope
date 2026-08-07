import { createContext, useContext, useEffect, useLayoutEffect, useRef, useState } from 'react';
import type { DragEvent, FormEvent } from 'react';
import { createPortal } from 'react-dom';

import { SEVERITY_LABELS, sbomDocumentUrl } from '../api/client';
import type { Folder, Sbom, SeverityBand } from '../api/client';
import {
  buildFolderTree,
  canMoveFolder,
  canMoveSbom,
  descendantIds,
  findNode,
  flattenFolderOptions,
  MAX_FOLDER_DEPTH,
  reorderWithin,
  rollupSeverity,
  siblingNameTaken,
} from '../sboms/folderTree';
import type { FolderNode, MoveCheck } from '../sboms/folderTree';
import { CARD_BANDS } from '../sboms/severityRollup';
import { useSboms } from '../sboms/SbomProvider';
import { usePersistentState } from '../state/persisted';
import { useSidebarDrag } from './useSidebarDrag';
import type { DropTarget, SidebarDrag } from './useSidebarDrag';
import {
  DisclosureIcon,
  DownloadIcon,
  FolderIcon,
  LinkIcon,
  MoveIcon,
  PencilIcon,
} from './icons';

/**
 * Pixels of indentation per nesting level.
 *
 * Deliberately small: three levels of 16px cost 48px of a 280px column, and the folder name
 * is what the row exists to show. 12px still reads as a step without spending the width.
 */
const INDENT_PX = 12;

/** Used to place the menu before it has been measured; the real width wins once it mounts. */
const MENU_WIDTH_PX = 170;

/**
 * How much of a row's height, top and bottom, means "insert here" rather than "drop into".
 *
 * <p>A folder row is two targets at once — a container to drop into, and a neighbour to
 * order against — so the edges reorder and the middle files. A document row has no inside,
 * so it splits in half instead. 0.28 leaves a comfortable middle for the commoner gesture
 * while keeping the edges wide enough to hit deliberately.
 */
const EDGE_FRACTION = 0.28;

/** Which of the two things a drop on this row would mean, from where the pointer is in it. */
function edgeFor(event: DragEvent, element: HTMLElement, splitInHalf: boolean):
  'before' | 'after' | 'into' {
  const box = element.getBoundingClientRect();
  const ratio = (event.clientY - box.top) / Math.max(1, box.height);
  if (splitInHalf) return ratio < 0.5 ? 'before' : 'after';
  if (ratio < EDGE_FRACTION) return 'before';
  if (ratio > 1 - EDGE_FRACTION) return 'after';
  return 'into';
}

function formatUploadedAt(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime())
    ? iso
    : date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

/**
 * Everything the rows need that is not their own: the live drag, the flat folder list the
 * move rules are computed from, and the expansion state spring-loading has to open.
 *
 * <p>A context rather than props because the tree nests three levels and every level needs
 * all of it — prop-drilling the same six values through two intermediate components would
 * be noise, and the provider is one component away in the same file.
 */
interface TreeContextValue {
  drag: SidebarDrag;
  folders: Folder[];
  sboms: Sbom[];
  folderOptions: { id: string; name: string; depth: number }[];
  isExpanded: (folderId: string) => boolean;
  setExpanded: (folderId: string, open: boolean) => void;
  moveSbom: (sbomId: string, folderId?: string) => Promise<unknown>;
  moveFolder: (folderId: string, parentId?: string) => Promise<unknown>;
  reportError: (message: string | null) => void;
  /**
   * Applies a reorder within one sibling group.
   *
   * <p>Takes the level and the row dropped against; the tree works out the resulting order,
   * so no caller has to reimplement {@link reorderWithin}.
   */
  reorder: (
    parentId: string | undefined,
    kind: 'folder' | 'sbom',
    movingId: string,
    relativeToId: string,
    edge: 'before' | 'after',
  ) => Promise<void>;
  sortByName: (parentId?: string) => Promise<void>;
}

const TreeContext = createContext<TreeContextValue | null>(null);

function useTree(): TreeContextValue {
  const context = useContext(TreeContext);
  if (!context) throw new Error('SidebarTree rows must render inside the tree provider');
  return context;
}

/** Renders a set of severity counts as the same small chips the SBOM card uses. */
function SeverityChips({ counts }: { counts: Partial<Record<SeverityBand, number>> }) {
  const total = CARD_BANDS.reduce((sum, band) => sum + (counts[band] ?? 0), 0);
  if (total === 0) return null;
  return (
    <span className="sbom-card__risk">
      {CARD_BANDS.map((band) => {
        const count = counts[band] ?? 0;
        return (
          <span key={band} className="risk-count" data-band={band.toLowerCase()} data-empty={count === 0}>
            <strong>{count}</strong> {SEVERITY_LABELS[band].toLowerCase()}
          </span>
        );
      })}
    </span>
  );
}

/**
 * The same numbers on a folder row, without the words.
 *
 * <p>A folder row has to fit a disclosure, an icon, a name, a rollup and a menu into 280px
 * less indentation, and the name is what the row is *for*. Spelling out "12 critical 40 high"
 * there costs about half the available width to repeat labels the colours already carry, so
 * the rollup keeps the counts and drops the words. Empty bands are omitted entirely rather
 * than dimmed — on the card there is room for a zero to mean "checked, none", here there is
 * not, and the full breakdown is one click away on the document itself.
 */
function SeverityRollup({ counts }: { counts: Partial<Record<SeverityBand, number>> }) {
  const present = CARD_BANDS.filter((band) => (counts[band] ?? 0) > 0);
  if (present.length === 0) return null;
  return (
    <span
      className="folder-row__rollup"
      title={present.map((band) => `${counts[band]} ${SEVERITY_LABELS[band].toLowerCase()}`).join(', ')}
    >
      {present.map((band) => (
        <span key={band} className="risk-count" data-band={band.toLowerCase()}>
          <strong>{counts[band]}</strong>
        </span>
      ))}
    </span>
  );
}

/**
 * A row's actions behind one control.
 *
 * <p>Four always-present buttons reserved roughly a third of the column — they were hidden
 * with `opacity`, which hides them without giving the space back — and that was what made
 * folder names unreadable.
 *
 * <p><b>Drawn over the tree, not inside it.</b> The first version rendered the menu inline
 * below the trigger, which was wrong twice over: as a flex sibling it took a share of the
 * row and squeezed the name it was meant to protect down to "b…", and it pushed every row
 * beneath it down as it opened. It is a `position: fixed` layer in a portal instead, so it
 * overlays the tree and is clipped by nothing — the list is `overflow: auto`, which would
 * have cropped an absolutely-positioned menu near the bottom of the column.
 *
 * <p>Dismissal is deliberately generous: Escape, a click anywhere outside, scrolling the
 * list, or resizing the window. A menu that can only be closed by pressing its own trigger
 * again is a trap, and the pointer is usually already somewhere else by then.
 */
function RowMenu({
  label,
  open,
  onToggle,
  children,
}: {
  label: string;
  open: boolean;
  onToggle: () => void;
  children: React.ReactNode;
}) {
  const trigger = useRef<HTMLButtonElement>(null);
  const menu = useRef<HTMLDivElement>(null);
  const [position, setPosition] = useState<{ top: number; left: number } | null>(null);

  // useLayoutEffect, not useEffect: this measures and then moves the menu, and doing that
  // after paint would show it in the wrong place for a frame. The same reason the findings
  // table's frozen-column offset is measured this way.
  useLayoutEffect(() => {
    if (!open || !trigger.current) {
      setPosition(null);
      return;
    }
    const anchor = trigger.current.getBoundingClientRect();
    const height = menu.current?.offsetHeight ?? 0;
    const width = menu.current?.offsetWidth ?? MENU_WIDTH_PX;

    // Flip above the trigger when there is not room below, so a folder near the bottom of a
    // long list still gets a whole menu rather than a cropped one.
    const below = anchor.bottom + 4;
    const flipUp = height > 0 && below + height > window.innerHeight - 8;

    setPosition({
      top: flipUp ? Math.max(8, anchor.top - height - 4) : below,
      left: Math.max(8, Math.min(anchor.right - width, window.innerWidth - width - 8)),
    });
  }, [open]);

  useEffect(() => {
    if (!open) return undefined;

    const onPointerDown = (event: MouseEvent) => {
      const target = event.target as Node;
      if (menu.current?.contains(target) || trigger.current?.contains(target)) return;
      onToggle();
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onToggle();
    };
    // Capture phase, and `true` on scroll: the sidebar list is its own scroller, and a
    // scroll event from it does not bubble to window.
    document.addEventListener('mousedown', onPointerDown, true);
    document.addEventListener('keydown', onKeyDown, true);
    document.addEventListener('scroll', onToggle, true);
    window.addEventListener('resize', onToggle);
    return () => {
      document.removeEventListener('mousedown', onPointerDown, true);
      document.removeEventListener('keydown', onKeyDown, true);
      document.removeEventListener('scroll', onToggle, true);
      window.removeEventListener('resize', onToggle);
    };
  }, [open, onToggle]);

  return (
    <>
      <button
        ref={trigger}
        type="button"
        className="icon-button folder-row__action"
        aria-label={label}
        aria-haspopup="menu"
        aria-expanded={open}
        title={label}
        onClick={onToggle}
      >
        ⋯
      </button>
      {open &&
        createPortal(
          <div
            ref={menu}
            className="row-menu"
            role="menu"
            style={
              position
                ? { top: position.top, left: position.left }
                : // First pass: rendered so it can be measured, not yet shown. Both happen
                  // inside one layout effect, so nothing is painted in the wrong place.
                  { top: 0, left: 0, visibility: 'hidden' }
            }
          >
            {children}
          </div>,
          document.body,
        )}
    </>
  );
}

function SbomRisk({ sbom }: { sbom: Sbom }) {
  if (sbom.scanning) return <span className="sbom-card__meta">Scanning…</span>;
  if (sbom.scannedComponents === 0) return <span className="sbom-card__meta">Not scanned</span>;
  return <SeverityChips counts={sbom.severityCounts} />;
}

/**
 * A drag must not start from a control inside the row.
 *
 * <p>`draggable` on a container makes its buttons and inputs draggable too, so pressing
 * Delete and moving a pixel would begin a drag instead of a click. Text selection in the
 * rename field would do the same.
 */
function startedFromAControl(event: DragEvent): boolean {
  const target = event.target as HTMLElement | null;
  return !!target?.closest('button, a, input, select, textarea, form');
}

/**
 * "Move to…", as a native `<select>` — the keyboard-reachable path that dragging supplements
 * rather than replaces. Destinations that would be refused are disabled with the reason, so
 * the menu and a drag agree about what is legal.
 */
function MoveToMenu({
  options,
  currentId,
  checkTarget,
  onMove,
  onCancel,
}: {
  options: { id: string; name: string; depth: number }[];
  currentId?: string;
  checkTarget: (target: string | undefined) => MoveCheck;
  onMove: (folderId?: string) => void;
  onCancel: () => void;
}) {
  const rootCheck = checkTarget(undefined);
  return (
    <select
      className="move-to-menu"
      autoFocus
      defaultValue={currentId ?? ''}
      aria-label="Move to"
      onChange={(event) => onMove(event.target.value === '' ? undefined : event.target.value)}
      onBlur={onCancel}
      onKeyDown={(event) => {
        if (event.key === 'Escape') onCancel();
      }}
    >
      <option value="" disabled={!rootCheck.ok}>
        Top level{rootCheck.ok ? '' : ` — ${rootCheck.reason}`}
      </option>
      {options.map((option) => {
        const check = checkTarget(option.id);
        return (
          <option key={option.id} value={option.id} disabled={!check.ok}>
            {'—'.repeat(option.depth)} {option.name}
            {check.ok ? '' : ` — ${check.reason}`}
          </option>
        );
      })}
    </select>
  );
}

/**
 * A name field that refuses a duplicate before it is submitted.
 *
 * <p>The sidebar already holds every folder, so the sibling-name rule can be checked as the
 * reader types rather than by a round trip that comes back red. The backend check stays the
 * authority — two tabs can still race — this only avoids offering a submit that cannot work.
 */
function NameField({
  value,
  onChange,
  parentId,
  excludingId,
  placeholder,
  submitLabel,
  onSubmit,
  onCancel,
  autoFocus = true,
}: {
  value: string;
  onChange: (value: string) => void;
  parentId?: string;
  excludingId?: string;
  placeholder: string;
  submitLabel: string;
  onSubmit: () => void;
  onCancel: () => void;
  autoFocus?: boolean;
}) {
  const { folders } = useTree();
  const trimmed = value.trim();
  const taken = siblingNameTaken(folders, parentId, trimmed, excludingId);
  const canSubmit = trimmed.length > 0 && !taken;
  const form = useRef<HTMLFormElement>(null);

  return (
    <form
      ref={form}
      className="folder-name-form"
      onSubmit={(event) => {
        event.preventDefault();
        if (canSubmit) onSubmit();
      }}
      // A rename (or a new-subfolder draft) ends the moment focus leaves it — the
      // standard file-manager rule, and the reason two rows could end up in edit mode
      // at once before this existed: nothing ever told the first one it had been
      // abandoned. `relatedTarget` is what is receiving focus; when that is still
      // inside this form — clicking the submit button, or Tab moving to it — this must
      // NOT cancel, or the submit action would blur itself out of existence before it
      // could run. `contains(null)` is false, so a click that focuses nothing at all
      // (a plain div) correctly cancels too.
      onBlur={(event) => {
        if (!form.current?.contains(event.relatedTarget as Node | null)) {
          onCancel();
        }
      }}
    >
      <div className="folder-name-form__row">
        <input
          type="text"
          value={value}
          onChange={(event) => onChange(event.target.value)}
          placeholder={placeholder}
          autoFocus={autoFocus}
          aria-invalid={taken}
          onKeyDown={(event) => {
            if (event.key === 'Escape') onCancel();
          }}
        />
        <button type="submit" className="button button--small" disabled={!canSubmit}>
          {submitLabel}
        </button>
      </div>
      {taken && (
        <p className="folder-name-form__note" role="status">
          {parentId
            ? `This folder already contains "${trimmed}".`
            : `There is already a project called "${trimmed}".`}
        </p>
      )}
    </form>
  );
}

function SbomListItem({ sbom, depth }: { sbom: Sbom; depth: number }) {
  const { selected, select, remove } = useSboms();
  const { drag, folderOptions, moveSbom, reportError, sboms, reorder } = useTree();
  const [moving, setMoving] = useState(false);
  const [editingWorkspace, setEditingWorkspace] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);

  const isSelected = selected?.id === sbom.id;
  const isDragging = drag.dragging?.kind === 'sbom' && drag.dragging.id === sbom.id;

  async function onRemove() {
    if (!window.confirm(`Delete ${sbom.filename}? Its components and analysis are removed too.`)) return;
    try {
      await remove(sbom.id);
    } catch (e) {
      reportError(e instanceof Error ? e.message : 'Could not delete that SBOM.');
    }
  }

  async function onMove(folderId?: string) {
    setMoving(false);
    try {
      await moveSbom(sbom.id, folderId);
    } catch (e) {
      reportError(e instanceof Error ? e.message : 'Could not move that document.');
    }
  }

  return (
    <li
      className="sbom-row"
      style={{ paddingLeft: depth * INDENT_PX }}
      // Same reasoning as the folder row: a `draggable` ancestor can hijack text
      // selection inside a descendant input, so it is switched off while the workspace
      // path field is open.
      draggable={!editingWorkspace}
      data-dragging={isDragging}
      data-insert={drag.insertion?.rowId === sbom.id ? drag.insertion.edge : undefined}
      onDragStart={(event) => {
        if (startedFromAControl(event)) {
          event.preventDefault();
          return;
        }
        drag.begin({ kind: 'sbom', id: sbom.id }, event);
      }}
      onDragEnd={drag.end}
      onDragOver={(event) => {
        const item = drag.current();
        // Only a document dragged within the same group can reorder against this row.
        // Anything else falls through to the folder beneath, which handles filing.
        if (!item || item.kind !== 'sbom' || item.id === sbom.id) return;
        const moving = sboms.find((candidate) => candidate.id === item.id);
        if (!moving || (moving.folderId ?? undefined) !== (sbom.folderId ?? undefined)) return;
        event.preventDefault();
        event.stopPropagation();
        event.dataTransfer.dropEffect = 'move';
        drag.setInsertion({
          rowId: sbom.id,
          edge: edgeFor(event, event.currentTarget as HTMLElement, true) as 'before' | 'after',
        });
      }}
      onDragLeave={() => {
        if (drag.insertion?.rowId === sbom.id) drag.setInsertion(null);
      }}
      onDrop={(event) => {
        const item = drag.current();
        const insertion = drag.insertion;
        if (!item || item.kind !== 'sbom' || !insertion || insertion.rowId !== sbom.id) return;
        event.preventDefault();
        event.stopPropagation();
        drag.end();
        void reorder(sbom.folderId, 'sbom', item.id, sbom.id, insertion.edge);
      }}
    >
      <button
        type="button"
        className="sbom-card"
        aria-current={isSelected ? 'true' : undefined}
        data-selected={isSelected}
        onClick={() => select(sbom.id)}
      >
        <span className="sbom-card__name">{sbom.filename}</span>
        <span className="sbom-card__meta">
          {formatUploadedAt(sbom.uploadedAt)} · {sbom.componentCount} components
        </span>
        <span className="sbom-card__meta">CycloneDX {sbom.specVersion}</span>
        <SbomRisk sbom={sbom} />
        {sbom.workspacePath && !editingWorkspace && (
          <span className="sbom-card__meta sbom-card__path" title={sbom.workspacePath}>
            {sbom.workspacePath}
          </span>
        )}
      </button>

      {editingWorkspace && <WorkspaceEditor sbom={sbom} onDone={() => setEditingWorkspace(false)} />}

      <div className="sbom-row__actions">
        <RowMenu
          label={`Actions for ${sbom.filename}`}
          open={menuOpen}
          onToggle={() => setMenuOpen((open) => !open)}
        >
          <a
            className="row-menu__item"
            role="menuitem"
            href={sbomDocumentUrl(sbom.id)}
            download
            onClick={() => setMenuOpen(false)}
          >
            <DownloadIcon className="row-menu__icon" /> Download
          </a>
          <button
            type="button"
            role="menuitem"
            className="row-menu__item"
            onClick={() => {
              setMenuOpen(false);
              setEditingWorkspace(true);
            }}
          >
            <LinkIcon className="row-menu__icon" />{' '}
            {sbom.workspacePath ? 'Change workspace' : 'Attach a workspace'}
          </button>
          <button
            type="button"
            role="menuitem"
            className="row-menu__item"
            onClick={() => {
              setMenuOpen(false);
              setMoving(true);
            }}
          >
            <MoveIcon className="row-menu__icon" /> Move
          </button>
          <button
            type="button"
            role="menuitem"
            className="row-menu__item row-menu__item--danger"
            onClick={() => {
              setMenuOpen(false);
              void onRemove();
            }}
          >
            <span className="row-menu__icon" aria-hidden="true">
              ×
            </span>{' '}
            Delete
          </button>
        </RowMenu>
      </div>

      {moving && (
        <MoveToMenu
          options={folderOptions}
          currentId={sbom.folderId}
          checkTarget={(target) => canMoveSbom(sbom, target)}
          onMove={onMove}
          onCancel={() => setMoving(false)}
        />
      )}
    </li>
  );
}

/**
 * Set once, changed or cleared, inline (B20). An absolute-path text field rather than a
 * picker: B11 dropped the directory-browser idea on 2026-08-02, and this must not
 * quietly reintroduce it.
 */
function WorkspaceEditor({ sbom, onDone }: { sbom: Sbom; onDone: () => void }) {
  const { attachWorkspace } = useSboms();
  const [value, setValue] = useState(sbom.workspacePath ?? '');
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  async function apply(path?: string) {
    setSaving(true);
    setError(null);
    try {
      await attachWorkspace(sbom.id, path);
      onDone();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not update the workspace path.');
    } finally {
      setSaving(false);
    }
  }

  return (
    <form
      className="workspace-editor"
      onSubmit={(event: FormEvent) => {
        event.preventDefault();
        void apply(value.trim() || undefined);
      }}
    >
      <input
        type="text"
        className="workspace-editor__input"
        value={value}
        onChange={(event) => setValue(event.target.value)}
        placeholder="Absolute path to the source tree"
        autoFocus
        disabled={saving}
      />
      <div className="workspace-editor__actions">
        <button type="submit" className="button button--small" disabled={saving}>
          Save
        </button>
        {sbom.workspacePath && (
          <button type="button" className="button button--small" onClick={() => void apply(undefined)} disabled={saving}>
            Clear
          </button>
        )}
        <button type="button" className="button button--small" onClick={onDone} disabled={saving}>
          Cancel
        </button>
      </div>
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
    </form>
  );
}

function FolderRow({ node, depth }: { node: FolderNode; depth: number }) {
  const { createFolder, renameFolder, deleteFolder } = useSboms();
  const {
    drag,
    folders,
    sboms,
    folderOptions,
    isExpanded,
    setExpanded,
    moveSbom,
    moveFolder,
    reportError,
    reorder,
    sortByName,
  } = useTree();

  const [renaming, setRenaming] = useState(false);
  const [nameDraft, setNameDraft] = useState(node.folder.name);
  const [creatingChild, setCreatingChild] = useState(false);
  const [childName, setChildName] = useState('');
  const [moving, setMoving] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);

  const id = node.folder.id;
  const isEmpty = node.children.length === 0 && node.sboms.length === 0;
  const isOpen = !isEmpty && isExpanded(id);
  const isDragging = drag.dragging?.kind === 'folder' && drag.dragging.id === id;
  const isDropTarget = drag.activeTarget === id;

  /** The one rule, asked the same way by the drag, the menu and the drop. */
  function checkDropInto(target: string | undefined): MoveCheck {
    const item = drag.current();
    if (!item) return { ok: false };
    if (item.kind === 'folder') return canMoveFolder(folders, item.id, target);
    const dragged = sboms.find((candidate) => candidate.id === item.id);
    return dragged ? canMoveSbom(dragged, target) : { ok: false };
  }

  function checkFolderMove(target: string | undefined): MoveCheck {
    return canMoveFolder(folders, id, target);
  }

  async function performDrop() {
    const item = drag.current();
    drag.end();
    if (!item) return;
    try {
      if (item.kind === 'folder') {
        await moveFolder(item.id, id);
      } else {
        await moveSbom(item.id, id);
      }
    } catch (e) {
      reportError(e instanceof Error ? e.message : 'Could not move that item.');
    }
  }

  async function submitRename() {
    try {
      await renameFolder(id, nameDraft);
      setRenaming(false);
    } catch (e) {
      reportError(e instanceof Error ? e.message : 'Could not rename that folder.');
    }
  }

  async function submitNewChild() {
    try {
      await createFolder(childName, id);
      setChildName('');
      setCreatingChild(false);
      setExpanded(id, true);
    } catch (e) {
      reportError(e instanceof Error ? e.message : 'Could not create that folder.');
    }
  }

  async function onDelete() {
    const noun = node.folder.parentId ? 'folder' : 'project';
    if (
      !window.confirm(
        `Delete the ${noun} "${node.folder.name}"? Its contents move up a level — nothing inside it is deleted.`,
      )
    ) {
      return;
    }
    try {
      await deleteFolder(id);
    } catch (e) {
      reportError(e instanceof Error ? e.message : 'Could not delete that folder.');
    }
  }

  const rollup = rollupSeverity(node);
  const excluded = descendantIds(node);
  const moveOptions = folderOptions.filter((option) => !excluded.has(option.id));

  return (
    <li className="folder-row">
      <div
        className="folder-row__header"
        // On the row, never on the name button: a `title` there displaces the button's
        // accessible name, which is how every folder briefly announced itself as the
        // tooltip text instead of as its own name. Ellipsis plus a hover tooltip is what
        // VS Code and IntelliJ do with a tree item too wide for its column.
        title={node.folder.name}
        style={{ paddingLeft: depth * INDENT_PX }}
        data-dragging={isDragging}
        data-drop-target={isDropTarget}
        data-insert={drag.insertion?.rowId === id ? drag.insertion.edge : undefined}
        // Never draggable while the rename field lives inside this row. A `draggable`
        // ancestor changes how the browser resolves mousedown-and-move on a descendant
        // text input — some browsers start an element drag instead of a text selection —
        // so a reader trying to select part of the name ends up dragging the folder
        // instead. The `startedFromAControl` check in onDragStart is not enough on its
        // own: by the time that JS runs, the browser may already have chosen "drag" over
        // "select". Turning the attribute off is what actually restores normal selection.
        draggable={!renaming}
        onDragStart={(event) => {
          if (startedFromAControl(event)) {
            event.preventDefault();
            return;
          }
          drag.begin({ kind: 'folder', id }, event);
        }}
        onDragEnd={drag.end}
        onDragEnter={() => drag.springLoad(id, !isOpen, () => setExpanded(id, true))}
        onDragOver={(event) => {
          event.stopPropagation();
          const item = drag.current();
          if (!item) return;

          // A folder row is two targets. Its edges reorder it against its siblings — but only
          // for a folder from the same group, since documents never sit among folders — and
          // its middle files the dragged thing inside it.
          const sameGroupFolder =
            item.kind === 'folder' &&
            item.id !== id &&
            (folders.find((f) => f.id === item.id)?.parentId ?? undefined) ===
              (node.folder.parentId ?? undefined);

          if (sameGroupFolder) {
            const where = edgeFor(event, event.currentTarget as HTMLElement, false);
            if (where !== 'into') {
              event.preventDefault();
              event.dataTransfer.dropEffect = 'move';
              drag.setInsertion({ rowId: id, edge: where });
              drag.leave(id);
              return;
            }
          }
          drag.setInsertion(null);
          drag.over(id, () => checkDropInto(id), event);
        }}
        onDragLeave={() => {
          drag.cancelSpringLoad(id);
          drag.leave(id);
          if (drag.insertion?.rowId === id) drag.setInsertion(null);
        }}
        onDrop={(event) => {
          event.preventDefault();
          event.stopPropagation();
          const item = drag.current();
          const insertion = drag.insertion;
          if (item?.kind === 'folder' && insertion?.rowId === id) {
            drag.end();
            void reorder(node.folder.parentId, 'folder', item.id, id, insertion.edge);
            return;
          }
          void performDrop();
        }}
      >
        {/* An empty folder keeps its chevron's space but greys it out and stays closed —
            there is nothing to disclose, and a control that expands to reveal nothing reads
            as broken. Disabled rather than hidden so the row's columns stay aligned down
            the tree, and so the folder is still a drop target: filing something into it is
            exactly how it stops being empty. */}
        <button
          type="button"
          className="icon-button folder-row__disclosure"
          onClick={() => setExpanded(id, !isOpen)}
          disabled={isEmpty}
          data-empty={isEmpty}
          aria-expanded={isEmpty ? undefined : isOpen}
          aria-label={
            isEmpty
              ? `${node.folder.name} is empty`
              : isOpen
                ? `Collapse ${node.folder.name}`
                : `Expand ${node.folder.name}`
          }
        >
          <DisclosureIcon
            className="folder-row__disclosure-icon"
            style={{ transform: !isEmpty && isOpen ? 'rotate(90deg)' : undefined }}
          />
        </button>

        <FolderIcon className="folder-row__icon" />

        {renaming ? (
          <NameField
            value={nameDraft}
            onChange={setNameDraft}
            parentId={node.folder.parentId}
            excludingId={id}
            placeholder="Folder name"
            submitLabel="Rename"
            onSubmit={() => void submitRename()}
            onCancel={() => {
              setNameDraft(node.folder.name);
              setRenaming(false);
            }}
          />
        ) : (
          // Clicking the name toggles the folder, which is what a tree is expected to do.
          // Renaming is the explicit control beside it, plus double-click as the shortcut
          // people try first. Single-click used to rename, which made the obvious gesture
          // do the surprising thing and left renaming undiscoverable.
          // No `title` here: it displaces the button's accessible name, so every folder
          // announced as "click to open, double-click to rename" instead of what it is
          // called. Caught by reading the accessibility tree rather than by looking. The
          // Rename control beside it is what makes renaming discoverable.
          <button
            type="button"
            className="folder-row__name"
            onClick={() => setExpanded(id, !isOpen)}
            onDoubleClick={() => {
              setNameDraft(node.folder.name);
              setRenaming(true);
            }}
          >
            {node.folder.name}
          </button>
        )}

        {/* Hidden while renaming: the field is already tight on a 280px row, and the rollup
            plus the menu trigger were taking the width back from it for information that is
            not what the reader is doing right now. Both return the moment the field closes. */}
        {!renaming && <SeverityRollup counts={rollup} />}

        {!renaming && (
          <RowMenu
            label={`Actions for ${node.folder.name}`}
            open={menuOpen}
            onToggle={() => setMenuOpen((open) => !open)}
          >
          <button
            type="button"
            role="menuitem"
            className="row-menu__item"
            onClick={() => {
              setMenuOpen(false);
              setNameDraft(node.folder.name);
              setRenaming(true);
            }}
          >
            <PencilIcon className="row-menu__icon" /> Rename
          </button>
          {/* "New" and "Move" rather than "New subfolder" and "Move to…": the menu belongs
              to a folder row, so what is new and what is moving is already established by
              where the menu was opened from. */}
          {depth < MAX_FOLDER_DEPTH - 1 && (
            <button
              type="button"
              role="menuitem"
              className="row-menu__item"
              onClick={() => {
                setMenuOpen(false);
                setCreatingChild(true);
              }}
            >
              <FolderIcon className="row-menu__icon" /> New
            </button>
          )}
          <button
            type="button"
            role="menuitem"
            className="row-menu__item"
            onClick={() => {
              setMenuOpen(false);
              setMoving(true);
            }}
          >
            <MoveIcon className="row-menu__icon" /> Move
          </button>
          {!isEmpty && (
            <button
              type="button"
              role="menuitem"
              className="row-menu__item"
              onClick={() => {
                setMenuOpen(false);
                void sortByName(id);
              }}
            >
              <span className="row-menu__icon" aria-hidden="true">
                A↓
              </span>{' '}
              Sort by name
            </button>
          )}
          <button
            type="button"
            role="menuitem"
            className="row-menu__item row-menu__item--danger"
            onClick={() => {
              setMenuOpen(false);
              void onDelete();
            }}
          >
            <span className="row-menu__icon" aria-hidden="true">
              ×
            </span>{' '}
            Delete
          </button>
          </RowMenu>
        )}
      </div>

      {moving && (
        <MoveToMenu
          options={moveOptions}
          currentId={node.folder.parentId}
          checkTarget={checkFolderMove}
          onMove={(parentId) => {
            setMoving(false);
            void moveFolder(id, parentId).catch((e: unknown) =>
              reportError(e instanceof Error ? e.message : 'Could not move that folder.'),
            );
          }}
          onCancel={() => setMoving(false)}
        />
      )}

      {creatingChild && (
        <div style={{ paddingLeft: (depth + 1) * INDENT_PX }}>
          <NameField
            value={childName}
            onChange={setChildName}
            parentId={id}
            placeholder="Folder name"
            submitLabel="Add"
            onSubmit={() => void submitNewChild()}
            onCancel={() => setCreatingChild(false)}
          />
        </div>
      )}

      {isOpen && (
        <ul className="folder-row__children">
          {node.children.map((child) => (
            <FolderRow key={child.folder.id} node={child} depth={depth + 1} />
          ))}
          {node.sboms.map((sbom) => (
            <SbomListItem key={sbom.id} sbom={sbom} depth={depth + 1} />
          ))}
        </ul>
      )}
    </li>
  );
}

/**
 * The sidebar's tree: projects and folders interleaved with loose documents (B19).
 *
 * <p>Assembly is pure and lives in `sboms/folderTree.ts`; this is the rendering, the
 * per-node interaction state, and the drag wiring from `useSidebarDrag`.
 */
export function SidebarTree() {
  const { sboms, folders, moveSbomToFolder, moveFolder, reorderLevel, sortLevelByName } =
    useSboms();
  const drag = useSidebarDrag();
  const [dropError, setDropError] = useState<string | null>(null);

  const tree = buildFolderTree(folders, sboms);
  const folderOptions = flattenFolderOptions(tree.roots);

  // Expanded by id; absent means expanded, so a folder just created does not appear shut.
  const [expanded, setExpandedMap] = usePersistentState<Record<string, boolean>>(
    'sidebar.expandedFolders',
    {},
    (stored) => (stored && typeof stored === 'object' ? stored : {}),
  );

  const context: TreeContextValue = {
    drag,
    folders,
    sboms,
    folderOptions,
    isExpanded: (folderId) => expanded[folderId] ?? true,
    setExpanded: (folderId, open) => setExpandedMap((current) => ({ ...current, [folderId]: open })),
    moveSbom: moveSbomToFolder,
    moveFolder,
    reportError: setDropError,
    reorder: async (parentId, kind, movingId, relativeToId, edge) => {
      // The group's current membership comes from the same tree that is on screen, so the
      // list sent is exactly what the reader sees — which is also what the backend checks.
      const level = parentId
        ? findNode(tree.roots, parentId)
        : { children: tree.roots, sboms: tree.looseSboms };
      if (!level) return;
      const ids =
        kind === 'folder'
          ? level.children.map((child) => child.folder.id)
          : level.sboms.map((s) => s.id);
      const next = reorderWithin(ids, movingId, relativeToId, edge);
      if (next.join() === ids.join()) return;
      try {
        await reorderLevel(parentId, kind === 'folder' ? { folderIds: next } : { sbomIds: next });
      } catch (e) {
        setDropError(e instanceof Error ? e.message : 'Could not reorder that level.');
      }
    },
    sortByName: async (parentId) => {
      try {
        await sortLevelByName(parentId);
      } catch (e) {
        setDropError(e instanceof Error ? e.message : 'Could not sort that level.');
      }
    },
  };

  function checkRootDrop(): MoveCheck {
    const item = drag.current();
    if (!item) return { ok: false };
    if (item.kind === 'folder') return canMoveFolder(folders, item.id, undefined);
    const sbom = sboms.find((candidate) => candidate.id === item.id);
    return sbom ? canMoveSbom(sbom, undefined) : { ok: false };
  }

  async function dropOnRoot() {
    const item = drag.current();
    drag.end();
    if (!item) return;
    try {
      if (item.kind === 'folder') await moveFolder(item.id, undefined);
      else await moveSbomToFolder(item.id, undefined);
    } catch (e) {
      setDropError(e instanceof Error ? e.message : 'Could not move that item.');
    }
  }

  const rootActive = drag.activeTarget === (null as DropTarget);

  return (
    <TreeContext.Provider value={context}>
      {dropError && (
        <p className="form-error" role="alert">
          {dropError}
        </p>
      )}

      {/* Why the drop under the pointer is being refused, stated while the drag is still in
          the reader's hand rather than as an error after they let go. */}
      {drag.dragging && drag.refusal && (
        <p className="sidebar__drag-refusal" role="status">
          {drag.refusal}
        </p>
      )}

      <ul className="sidebar__list" ref={drag.scrollRef}>
        {tree.roots.map((node) => (
          <FolderRow key={node.folder.id} node={node} depth={0} />
        ))}
        {tree.looseSboms.map((sbom) => (
          <SbomListItem key={sbom.id} sbom={sbom} depth={0} />
        ))}
      </ul>

      {/* "Outside every project" is not a row, so it needs a target of its own. Shown only
          during a drag: a permanent strip would be clutter for a gesture nobody is making. */}
      {drag.dragging && (
        <div
          className="sidebar__root-drop"
          data-active={rootActive}
          onDragOver={(event) => drag.over(null, checkRootDrop, event)}
          onDragLeave={() => drag.leave(null)}
          onDrop={(event) => {
            event.preventDefault();
            void dropOnRoot();
          }}
        >
          Drop here to take it out of every project
        </div>
      )}
    </TreeContext.Provider>
  );
}
