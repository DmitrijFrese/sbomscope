import { useCallback, useEffect, useRef, useState } from 'react';
import type { KeyboardEvent, PointerEvent } from 'react';

/**
 * The draggable boundary between the sidebar and the main panel.
 *
 * <p>The sidebar was a fixed 280px, which is enough for a flat list of documents and not
 * enough once folders nest three deep — a name indented twice has little room left. The
 * range starts at that same 280px rather than below it, so the narrowest setting is the
 * layout every existing screenshot and measurement was taken against, and stops at twice
 * that: past it the table the sidebar exists to serve starts losing columns.
 *
 * <p>Pointer events rather than mouse events, with capture: a fast drag leaves the 7px
 * handle behind long before the pointer stops moving, and without capture the element
 * stops receiving moves the moment that happens. The origin is held in a ref rather than
 * state for the reason the sidebar's own drag-and-drop records in AGENTS.md — a handler
 * firing before React has re-rendered would read a stale value — though here it is also
 * simply the only thing the move handler needs.
 *
 * <p>It is a `separator` with a value, so the width is reachable from the keyboard too.
 * Dragging has no keyboard equivalent, which is the same reason "Move to…" exists beside
 * dragging a document into a folder.
 */
export function SidebarResizer({
  width,
  min,
  max,
  onWidth,
}: {
  width: number;
  min: number;
  max: number;
  onWidth: (width: number) => void;
}) {
  const origin = useRef<{ pointer: number; width: number } | null>(null);
  const [dragging, setDragging] = useState(false);

  const clamp = useCallback(
    (value: number) => Math.min(max, Math.max(min, Math.round(value))),
    [max, min],
  );

  // Text elsewhere on the page selects as the pointer sweeps across it otherwise, which
  // leaves the shell looking broken after every drag. Restored on unmount as well as on
  // release: a page navigating away mid-drag never sees the pointerup.
  useEffect(() => {
    if (!dragging) return;
    const previous = document.body.style.userSelect;
    document.body.style.userSelect = 'none';
    return () => {
      document.body.style.userSelect = previous;
    };
  }, [dragging]);

  function onPointerDown(event: PointerEvent<HTMLDivElement>) {
    if (event.button !== 0) return;
    event.preventDefault();
    origin.current = { pointer: event.clientX, width };
    event.currentTarget.setPointerCapture(event.pointerId);
    setDragging(true);
  }

  function onPointerMove(event: PointerEvent<HTMLDivElement>) {
    const start = origin.current;
    if (!start) return;
    onWidth(clamp(start.width + (event.clientX - start.pointer)));
  }

  function onPointerUp(event: PointerEvent<HTMLDivElement>) {
    if (!origin.current) return;
    origin.current = null;
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
    setDragging(false);
  }

  function onKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    // 16px a step, 64px with shift: the same shape as a scrollbar's line and page moves.
    const step = event.shiftKey ? 64 : 16;
    if (event.key === 'ArrowLeft') onWidth(clamp(width - step));
    else if (event.key === 'ArrowRight') onWidth(clamp(width + step));
    else if (event.key === 'Home') onWidth(min);
    else if (event.key === 'End') onWidth(max);
    else return;
    event.preventDefault();
  }

  return (
    <div
      className="sidebar-resizer"
      data-dragging={dragging}
      role="separator"
      aria-orientation="vertical"
      aria-label="Sidebar width"
      aria-valuemin={min}
      aria-valuemax={max}
      aria-valuenow={width}
      tabIndex={0}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
      onPointerCancel={onPointerUp}
      onKeyDown={onKeyDown}
      // Restores the width the rest of the application was designed against, without
      // hunting for the exact pixel by hand.
      onDoubleClick={() => onWidth(min)}
    />
  );
}
