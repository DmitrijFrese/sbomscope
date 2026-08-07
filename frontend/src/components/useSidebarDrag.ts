/**
 * Drag-and-drop plumbing for the sidebar tree (B19, second pass).
 *
 * <p><b>Native HTML5 drag-and-drop, no library.</b> `dnd-kit` and `react-dnd` both do this
 * better in general, and neither earns its weight here: there is no reordering to support —
 * folders sort by name and documents by date — so the only gestures are "onto this folder"
 * and "onto the root zone". That removes insertion lines, order persistence and the hit-testing
 * that makes tree DnD genuinely hard, and leaves something the platform already does.
 * Constraint 9 (keep the dependency tree lean) is the reason to check, and this is the answer.
 *
 * <p><b>Dragging is additive, never the only way to move something.</b> The "Move to…" menu
 * stays, because HTML5 DnD has no keyboard equivalent at all — a keyboard or screen-reader
 * user would otherwise be unable to file a document. That is the one objection to dragging
 * that does not survive being additive, and it is why this could be built at all.
 */
import { useCallback, useEffect, useRef, useState } from 'react';

/** What is being dragged. Documents and folders obey different move rules. */
export interface DragItem {
  kind: 'sbom' | 'folder';
  id: string;
}

/** `null` target means the root zone — outside every project. */
export type DropTarget = string | null;

/**
 * How close to an edge the pointer must be before the list scrolls itself, and how fast.
 *
 * <p>Auto-scroll is not optional polish: a drop target scrolled out of view is unreachable
 * during a drag, because the pointer is captured and the wheel does not always reach the
 * list. 48px is roughly one row, so the zone is discoverable without being easy to enter
 * by accident while aiming at the first or last row.
 */
const EDGE_ZONE_PX = 48;
const SCROLL_STEP_PX = 10;

/**
 * How long a collapsed folder must be hovered before it opens.
 *
 * <p>"Spring-loading", as Finder and Explorer call it. Without it a collapsed folder is a
 * dead end: you cannot drop into something whose children are not rendered. 600ms is long
 * enough that passing over a folder on the way somewhere else does not open it, and short
 * enough not to feel stuck.
 */
const SPRING_LOAD_MS = 600;

/**
 * Where a reorder drop would land: above or below the row under the pointer.
 *
 * <p>Only ever set for a row in the **same sibling group and of the same kind** as the item
 * being dragged. Reordering is an arrangement within a group; carrying an item into another
 * group is a move, and mixing the two would let one gesture mean two different things
 * depending on a few pixels.
 */
export interface Insertion {
  rowId: string;
  edge: 'before' | 'after';
}

export interface SidebarDrag {
  /** Drives rendering — the dimmed source row, the root zone appearing. */
  dragging: DragItem | null;
  /** The insertion line's position, or null when the drop would not be a reorder. */
  insertion: Insertion | null;
  setInsertion: (insertion: Insertion | null) => void;
  /**
   * The same item, readable **synchronously**.
   *
   * <p>`dragging` is state, so it is a render behind: a `dragover` arriving before React has
   * re-rendered would see `null` and judge every drop illegal. In practice a mouse moves
   * between `dragstart` and the first `dragover`, so the race is nearly invisible — which is
   * exactly what makes it worth removing rather than relying on. Drop legality is decided
   * from this; only appearance is decided from the state above.
   */
  current: () => DragItem | null;
  /** The target currently under the pointer, when the drop would be legal. */
  activeTarget: DropTarget | undefined;
  /** Why the hovered target is refusing the drop, for the reader. */
  refusal: string | null;
  begin: (item: DragItem, event: React.DragEvent) => void;
  end: () => void;
  /**
   * Handles `dragover` for one target. Calls `preventDefault` only when the drop is legal —
   * which is what makes the browser show a move cursor rather than "no entry", so the
   * refusal is felt before the mouse is released rather than reported after it.
   */
  over: (target: DropTarget, check: () => { ok: boolean; reason?: string }, event: React.DragEvent) => void;
  leave: (target: DropTarget) => void;
  /** Registers the scrollable list element so the drag can auto-scroll it. */
  scrollRef: (element: HTMLElement | null) => void;
  /** Called on dragenter of a collapsed folder; opens it after a dwell. */
  springLoad: (folderId: string, isCollapsed: boolean, expand: () => void) => void;
  cancelSpringLoad: (folderId: string) => void;
}

export function useSidebarDrag(): SidebarDrag {
  const [dragging, setDragging] = useState<DragItem | null>(null);
  const [activeTarget, setActiveTarget] = useState<DropTarget | undefined>(undefined);
  const [refusal, setRefusal] = useState<string | null>(null);
  const [insertion, setInsertion] = useState<Insertion | null>(null);

  const item = useRef<DragItem | null>(null);
  const scrollElement = useRef<HTMLElement | null>(null);
  const pointerY = useRef<number | null>(null);
  const frame = useRef<number | null>(null);
  const springTimer = useRef<{ id: string; timer: number } | null>(null);

  const stopAutoScroll = useCallback(() => {
    if (frame.current !== null) {
      cancelAnimationFrame(frame.current);
      frame.current = null;
    }
    pointerY.current = null;
  }, []);

  // One rAF loop for the whole drag rather than scrolling from the dragover handler: dragover
  // stops firing when the pointer holds still, and holding still near the edge is exactly the
  // gesture that means "keep scrolling".
  const runAutoScroll = useCallback(() => {
    const list = scrollElement.current;
    const y = pointerY.current;
    if (list && y !== null) {
      const box = list.getBoundingClientRect();
      if (y - box.top < EDGE_ZONE_PX) {
        list.scrollTop -= SCROLL_STEP_PX;
      } else if (box.bottom - y < EDGE_ZONE_PX) {
        list.scrollTop += SCROLL_STEP_PX;
      }
    }
    frame.current = requestAnimationFrame(runAutoScroll);
  }, []);

  const cancelSpringLoad = useCallback((folderId: string) => {
    if (springTimer.current?.id === folderId) {
      window.clearTimeout(springTimer.current.timer);
      springTimer.current = null;
    }
  }, []);

  const springLoad = useCallback(
    (folderId: string, isCollapsed: boolean, expand: () => void) => {
      if (!isCollapsed || springTimer.current?.id === folderId) {
        return;
      }
      if (springTimer.current) {
        window.clearTimeout(springTimer.current.timer);
      }
      springTimer.current = {
        id: folderId,
        timer: window.setTimeout(() => {
          expand();
          springTimer.current = null;
        }, SPRING_LOAD_MS),
      };
    },
    [],
  );

  const begin = useCallback(
    (dragged: DragItem, event: React.DragEvent) => {
      item.current = dragged;
      setDragging(dragged);
      event.dataTransfer.effectAllowed = 'move';
      // Some payload is required or Firefox refuses to start the drag at all. The value is
      // never read back: `dataTransfer.getData` is blocked during dragover for security, so
      // the live item is held in the ref above instead.
      event.dataTransfer.setData('text/plain', dragged.id);
      if (frame.current === null) {
        frame.current = requestAnimationFrame(runAutoScroll);
      }
    },
    [runAutoScroll],
  );

  const end = useCallback(() => {
    item.current = null;
    setDragging(null);
    setActiveTarget(undefined);
    setRefusal(null);
    setInsertion(null);
    stopAutoScroll();
    if (springTimer.current) {
      window.clearTimeout(springTimer.current.timer);
      springTimer.current = null;
    }
  }, [stopAutoScroll]);

  const over = useCallback(
    (target: DropTarget, check: () => { ok: boolean; reason?: string }, event: React.DragEvent) => {
      pointerY.current = event.clientY;
      const verdict = check();
      if (verdict.ok) {
        // Only a prevented dragover is a drop target. Skipping this for an illegal move is
        // what makes the cursor say no by itself.
        event.preventDefault();
        event.dataTransfer.dropEffect = 'move';
        setActiveTarget(target);
        setRefusal(null);
      } else {
        setActiveTarget(undefined);
        setRefusal(verdict.reason ?? null);
      }
    },
    [],
  );

  const leave = useCallback((target: DropTarget) => {
    setActiveTarget((current) => (current === target ? undefined : current));
  }, []);

  const scrollRef = useCallback((element: HTMLElement | null) => {
    scrollElement.current = element;
  }, []);

  // A drag can end without a drop — Escape, or released outside the window — and neither
  // fires dragend on the source in every browser. Cleaning up on unmount stops a stray rAF
  // loop outliving the component.
  useEffect(() => stopAutoScroll, [stopAutoScroll]);

  return {
    dragging,
    insertion,
    setInsertion,
    current: () => item.current,
    activeTarget,
    refusal,
    begin,
    end,
    over,
    leave,
    scrollRef,
    springLoad,
    cancelSpringLoad,
  };
}
