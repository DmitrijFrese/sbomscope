import { useEffect, useMemo, useRef, useState } from 'react';

import { fetchComponents } from '../api/client';
import type { SbomComponent } from '../api/client';

/**
 * How many matches are offered at once.
 *
 * <p>A cap rather than a scroll: past a few dozen the list has stopped answering "which one
 * did you mean" and the honest response is to type more. The count of what was held back is
 * shown, because a silently shortened list of candidates reads as "there are no others".
 */
const MAX_SHOWN = 40;

interface ComponentFinderProps {
  sbomId: string;
  /** Highlighted in the list, so the finder shows where you already are. */
  selectedPurl: string | null;
  onSelect: (purl: string) => void;
}

/**
 * Type-ahead over the selected SBOM's components.
 *
 * <p>Filtering runs in the browser against the list already fetched. The whole component
 * list is a single request and a large SBOM is thousands of rows rather than millions, so a
 * round trip per keystroke would be slower, would flicker, and would put load on a database
 * to answer a question already answered.
 *
 * <p>Keyboard-first, because reaching for the mouse to pick from a list you are actively
 * typing into is the thing a finder exists to avoid: arrows move, Enter opens, Escape
 * clears.
 *
 * <p>Scoped to the current SBOM rather than searching every upload (decided 2026-07-26): a
 * component means something only in the context of the document that positions it.
 */
export function ComponentFinder({ sbomId, selectedPurl, onSelect }: ComponentFinderProps) {
  const [components, setComponents] = useState<SbomComponent[]>([]);
  const [query, setQuery] = useState('');
  const [highlighted, setHighlighted] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const listId = 'component-finder-results';
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    let cancelled = false;
    setComponents([]);
    setError(null);

    fetchComponents(sbomId)
      .then((result) => {
        if (!cancelled) setComponents(result);
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e.message : 'Could not load components.');
      });

    return () => {
      cancelled = true;
    };
  }, [sbomId]);

  // Components with no purl are omitted: the Inspector identifies a component by purl, so
  // there is nothing to open. They are rare, and offering one that cannot be opened would
  // be worse than not offering it.
  const identifiable = useMemo(
    () => components.filter((component) => !!component.purl),
    [components],
  );

  const matches = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return identifiable;
    return identifiable.filter(
      (component) =>
        component.coordinates.toLowerCase().includes(needle) ||
        (component.version ?? '').toLowerCase().includes(needle) ||
        (component.purl ?? '').toLowerCase().includes(needle),
    );
  }, [identifiable, query]);

  const shown = matches.slice(0, MAX_SHOWN);
  const withheld = matches.length - shown.length;

  // The highlight is an index into a list that shrinks as you type, so it is clamped rather
  // than trusted — otherwise Enter opens nothing, or the wrong thing.
  const active = Math.min(highlighted, Math.max(shown.length - 1, 0));

  function onKeyDown(event: React.KeyboardEvent<HTMLInputElement>) {
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      setHighlighted((current) => Math.min(current + 1, shown.length - 1));
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      setHighlighted((current) => Math.max(current - 1, 0));
    } else if (event.key === 'Enter') {
      event.preventDefault();
      const chosen = shown[active];
      if (chosen?.purl) onSelect(chosen.purl);
    } else if (event.key === 'Escape') {
      setQuery('');
      setHighlighted(0);
    }
  }

  return (
    <div className="finder">
      <input
        ref={inputRef}
        type="search"
        className="finder__input"
        placeholder="Find a library in this SBOM…"
        value={query}
        onChange={(event) => {
          setQuery(event.target.value);
          setHighlighted(0);
        }}
        onKeyDown={onKeyDown}
        role="combobox"
        aria-expanded={shown.length > 0}
        aria-controls={listId}
        aria-autocomplete="list"
        aria-label="Find a library in this SBOM"
      />

      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}

      {!error && identifiable.length > 0 && shown.length === 0 && (
        <p className="finder__note">Nothing in this SBOM matches “{query.trim()}”.</p>
      )}

      {shown.length > 0 && (
        <ul className="finder__results" id={listId} role="listbox">
          {shown.map((component, index) => (
            <li key={component.id}>
              <button
                type="button"
                role="option"
                aria-selected={component.purl === selectedPurl}
                className="finder__option"
                data-active={index === active}
                data-current={component.purl === selectedPurl}
                onMouseEnter={() => setHighlighted(index)}
                onClick={() => component.purl && onSelect(component.purl)}
              >
                <span className="finder__name mono">{component.coordinates}</span>
                <span className="finder__version mono">{component.version ?? '—'}</span>
              </button>
            </li>
          ))}
        </ul>
      )}

      {withheld > 0 && (
        <p className="finder__note">
          {withheld} more {withheld === 1 ? 'match' : 'matches'} — keep typing to narrow it.
        </p>
      )}
    </div>
  );
}
