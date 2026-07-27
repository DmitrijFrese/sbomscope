import { useEffect, useRef, useState } from 'react';

import { COLUMNS, COMPACT_DEFAULT } from '../findings/columns';
import type { ColumnId } from '../findings/columns';
import { MoreIcon } from './icons';

interface ViewOptionsMenuProps {
  details: boolean;
  onDetailsChange: (details: boolean) => void;
  /** Which columns Compact shows. Details always shows everything. */
  compact: ColumnId[];
  onColumnsChange: (columns: ColumnId[]) => void;
}

/**
 * How the table is displayed: density, and which columns Compact carries.
 *
 * <p>Both used to sit inline in the controls row, between the severity chips and the export
 * button — which put "how it looks" in the middle of "which rows" and then an action, three
 * unrelated jobs reading as one strip. Collapsed into a single menu on the actions side, so
 * the row divides cleanly: filtering on the left, things you do to the result on the right.
 *
 * <p>Opens on click, closes on Escape or outside click, like the export menu beside it.
 */
export function ViewOptionsMenu({
  details,
  onDetailsChange,
  compact,
  onColumnsChange,
}: ViewOptionsMenuProps) {
  const [open, setOpen] = useState(false);
  const container = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;

    function onPointerDown(event: MouseEvent) {
      if (!container.current?.contains(event.target as Node)) setOpen(false);
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

  function toggle(id: ColumnId) {
    onColumnsChange(compact.includes(id) ? compact.filter((c) => c !== id) : [...compact, id]);
  }

  return (
    <div className="view-options" ref={container}>
      <button
        type="button"
        className="button button--small view-options__trigger"
        aria-expanded={open}
        aria-haspopup="dialog"
        aria-label="View options"
        title="View options"
        onClick={() => setOpen((current) => !current)}
      >
        <MoreIcon className="view-options__icon" />
      </button>

      {open && (
        <div className="view-options__panel" role="dialog" aria-label="View options">
          <fieldset className="view-options__group">
            <legend className="view-options__legend">Density</legend>
            <div className="viewswitch" role="group" aria-label="Table density">
              <button
                type="button"
                className="viewswitch__tab"
                aria-selected={!details}
                onClick={() => onDetailsChange(false)}
              >
                Compact
              </button>
              <button
                type="button"
                className="viewswitch__tab"
                aria-selected={details}
                onClick={() => onDetailsChange(true)}
              >
                Details
              </button>
            </div>
          </fieldset>

          <fieldset className="view-options__group">
            <legend className="view-options__legend">Columns</legend>

            {/* Said plainly, because ticking boxes and seeing nothing happen reads as a bug. */}
            {details && (
              <p className="view-options__note">
                Details is showing every column. These choices apply to Compact.
              </p>
            )}

            <ul className="column-picker__list">
              {COLUMNS.map((column) => {
                const checked = column.locked || compact.includes(column.id);
                return (
                  <li key={column.id}>
                    <label className="column-picker__item">
                      <input
                        type="checkbox"
                        checked={checked}
                        disabled={column.locked}
                        onChange={() => toggle(column.id)}
                      />
                      <span>
                        <span className="column-picker__label">
                          {column.label}
                          {column.locked && (
                            <span className="column-picker__always" title="Always shown">
                              always
                            </span>
                          )}
                        </span>
                        {column.note && (
                          <span className="column-picker__hint">{column.note}</span>
                        )}
                      </span>
                    </label>
                  </li>
                );
              })}
            </ul>

            <button
              type="button"
              className="button button--small column-picker__reset"
              onClick={() => onColumnsChange(COMPACT_DEFAULT)}
            >
              Reset to default
            </button>
          </fieldset>
        </div>
      )}
    </div>
  );
}
