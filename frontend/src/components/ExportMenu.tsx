import { useEffect, useRef, useState } from 'react';

import { exportUrl } from '../api/client';
import type { FindingQuery } from '../api/client';

interface ExportMenuProps {
  sbomId: string;
  query: FindingQuery;
  /** Rows on the current page. */
  visibleCount: number;
  /** Rows matching the filter, across every page. */
  totalCount: number;
  /** Columns currently on screen; honoured or ignored per the export setting. */
  visibleColumns: string[];
}

interface ExportLinksMenuProps {
  visibleUrl: string;
  allUrl: string;
  visibleCount: number;
  totalCount: number;
  visibleHint: string;
  allHint: string;
}

/**
 * Split button: the primary action exports what is on screen, the caret offers both.
 *
 * <p>Opens on click rather than hover. A hover menu is unreachable by keyboard and simply
 * does not exist on a touch device, and this is the only route to a whole-inventory export.
 *
 * <p>Both entries keep their row counts. Two buttons became one, but the reason the counts
 * were there has not changed: sending a filtered subset while believing it is the whole
 * picture is the worst mistake this screen can cause.
 */
export function ExportMenu({
  sbomId,
  query,
  visibleCount,
  totalCount,
  visibleColumns,
}: ExportMenuProps) {
  return (
    <ExportLinksMenu
      visibleUrl={exportUrl(sbomId, query, 'visible', visibleColumns)}
      allUrl={exportUrl(sbomId, query, 'all', visibleColumns)}
      visibleCount={visibleCount}
      totalCount={totalCount}
      visibleHint="this page, filter and sort"
      allHint="keeps the sort and row selections"
    />
  );
}

/** The shared split-button shell; callers remain responsible for defining both scopes. */
export function ExportLinksMenu({
  visibleUrl,
  allUrl,
  visibleCount,
  totalCount,
  visibleHint,
  allHint,
}: ExportLinksMenuProps) {
  const [open, setOpen] = useState(false);
  const container = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;

    function onPointerDown(event: MouseEvent) {
      if (!container.current?.contains(event.target as Node)) {
        setOpen(false);
      }
    }
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') setOpen(false);
    }

    document.addEventListener('mousedown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('mousedown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [open]);

  return (
    <div className="export-menu" ref={container}>
      <a
        className="button button--small export-menu__primary"
        href={visibleUrl}
        onClick={() => setOpen(false)}
      >
        Export view ({visibleCount})
      </a>

      <button
        type="button"
        className="button button--small export-menu__caret"
        aria-expanded={open}
        aria-haspopup="menu"
        aria-label="Other export options"
        onClick={() => setOpen((current) => !current)}
      >
        <span aria-hidden="true">▾</span>
      </button>

      {open && (
        <div className="export-menu__list" role="menu">
          <a
            className="export-menu__item"
            role="menuitem"
            href={visibleUrl}
            onClick={() => setOpen(false)}
          >
            <span className="export-menu__item-label">Export view</span>
            <span className="export-menu__item-hint">
              {visibleCount} rows — {visibleHint}
            </span>
          </a>
          <a
            className="export-menu__item"
            role="menuitem"
            href={allUrl}
            onClick={() => setOpen(false)}
          >
            <span className="export-menu__item-label">Export all</span>
            <span className="export-menu__item-hint">
              {totalCount} rows — {allHint}
            </span>
          </a>
        </div>
      )}
    </div>
  );
}
