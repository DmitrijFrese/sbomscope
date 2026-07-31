import { useEffect, useMemo, useRef, useState } from 'react';

import { fetchComponents } from '../api/client';
import type { SbomComponent } from '../api/client';
import { SearchField } from './SearchField';

/**
 * How many matches are offered at once.
 *
 * <p>A cap rather than a scroll: past a few dozen the list has stopped answering "which one
 * did you mean" and the honest response is to type more. The count of what was held back is
 * shown, because a silently shortened list of candidates reads as "there are no others".
 */
const MAX_SHOWN = 40;

/**
 * The seven states a row can be in — the six severity bands plus `unknown`.
 *
 * A union rather than a string, so the ordering below and the `data-band` attribute cannot
 * drift apart: adding a band to the API without giving it a rank stops compiling.
 */
type FinderBand = 'critical' | 'high' | 'medium' | 'low' | 'none' | 'unknown' | 'clean';

/**
 * Worst first, and the two entries at the bottom are the ones worth arguing about.
 *
 * `unknown` — never scanned — sits **above** `clean` rather than below it. Clean is the only
 * state where you know there is nothing to do; a gap is not an answer, and the plan's own
 * wording for the startup sweep applies here too: it "reads as nothing found to anyone who
 * does not know to check". It sits below `none` because an advisory of unknown severity is
 * still a known vulnerability, where this is the absence of a question having been asked.
 */
const SEVERITY_ORDER: Record<FinderBand, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  none: 4,
  unknown: 5,
  clean: 6,
};

/**
 * The band's value for `data-band`, or `unknown` where nothing has looked yet.
 *
 * <p>`severity: null` from the API means **no scan record**, which is not `CLEAN`. They get
 * different marks for the reason the `vulnerability_scan` table exists at all: an empty finding
 * list from a component nobody checked looks exactly like a clean bill of health, and in a
 * security tool that is the one confusion worth spending a visual state on.
 */
function bandOf(component: SbomComponent): FinderBand {
  switch (component.severity) {
    case null:
      return 'unknown';
    case 'CRITICAL':
      return 'critical';
    case 'HIGH':
      return 'high';
    case 'MEDIUM':
      return 'medium';
    case 'LOW':
      return 'low';
    case 'NONE':
      return 'none';
    case 'CLEAN':
      return 'clean';
  }
}

/** What the mark means, in words — the tooltip and the accessible name both read this. */
function severityTitle(component: SbomComponent): string {
  switch (component.severity) {
    case null:
      return 'Not checked — no scan has covered this component';
    case 'CLEAN':
      return 'Checked, nothing known against it';
    case 'NONE':
      return 'Known vulnerability, no CVSS score';
    default:
      return `Worst known: ${component.severity.charAt(0)}${component.severity.slice(1).toLowerCase()}`;
  }
}

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
  /**
   * Session state rather than a stored preference, matching the tab strip beside it — and not
   * shared with the findings table's own toggle, which searches different columns of a
   * different list and would be surprising to change from here.
   */
  const [regex, setRegex] = useState(false);
  const [negate, setNegate] = useState(false);
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
  //
  // Sorted worst-first, in both states rather than only on an empty box. There is no name
  // relevance being displaced: this is a plain substring filter with no ranking, so the order
  // it replaces is whatever the database happened to return. It also changes what the 40-row
  // cap withholds — previously an arbitrary 40 of N, now the 40 that matter most, which is the
  // difference between a cap that hides things and one that prioritises.
  const identifiable = useMemo(
    () =>
      components
        .filter((component) => !!component.purl)
        .sort(
          (a, b) =>
            SEVERITY_ORDER[bandOf(a)] - SEVERITY_ORDER[bandOf(b)] ||
            a.coordinates.localeCompare(b.coordinates) ||
            (a.version ?? '').localeCompare(b.version ?? ''),
        ),
    [components],
  );

  /**
   * The matcher, and the reason a bad pattern is not an error here either.
   *
   * <p>Returns a predicate, or the message explaining why it could not build one. A regex is
   * compiled once per query rather than once per component — `new RegExp` in a filter callback
   * would rebuild it for every row of a list this exists to search quickly.
   */
  const matcher = useMemo((): { test: (value: string) => boolean; error: string | null } => {
    const raw = regex ? query : query.trim().toLowerCase();
    if (!raw) {
      return { test: () => true, error: null };
    }
    if (!regex) {
      return { test: (value) => value.toLowerCase().includes(raw), error: null };
    }
    try {
      // 'i' to match the literal mode's case-insensitivity, so the toggle changes one thing.
      const compiled = new RegExp(raw, 'i');
      return { test: (value) => compiled.test(value), error: null };
    } catch (e) {
      return { test: () => false, error: e instanceof Error ? e.message : 'Invalid pattern.' };
    }
  }, [query, regex]);

  const matches = useMemo(() => {
    if (!query) return identifiable;
    // A pattern that will not compile matches nothing, and negating "nothing" would be
    // everything — so a half-typed exclusion would briefly show the entire SBOM as though the
    // filter had been cleared. An unusable pattern yields an unusable result in both polarities.
    if (matcher.error) return [];
    return identifiable.filter((component) => {
      // Negation applies to the whole row, not to each field: the positive form shows a
      // component when any of its three searchable strings matches, so the negative form has to
      // hide it on the same condition. Per-field negation would show a row whose purl contains
      // the term simply because its version does not.
      const hit =
        matcher.test(component.coordinates) ||
        matcher.test(component.version ?? '') ||
        matcher.test(component.purl ?? '');
      return negate ? !hit : hit;
    });
  }, [identifiable, matcher, negate, query]);

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
      {/* The note carries the browser's own wording, which is not Java's. This field filters a
          list already in memory — deliberately, since a round trip per keystroke would be
          slower than the search itself — so it runs on JavaScript's RegExp. The dialects agree
          on everything a library finder is realistically typed with; they part company over
          possessive quantifiers, atomic groups and \A/\z, which exist to control backtracking
          that costs nothing over a few thousand rows the browser already holds. */}
      <SearchField
        value={query}
        onValueChange={(value) => {
          setQuery(value);
          setHighlighted(0);
        }}
        regex={regex}
        negate={negate}
        onNegateChange={setNegate}
        onRegexChange={(next) => {
          setRegex(next);
          setHighlighted(0);
        }}
        placeholder="Find a library in this SBOM…"
        ariaLabel="Find a library in this SBOM"
        note={matcher.error}
        inputClassName="finder__input"
        inputRef={inputRef}
        inputProps={{
          onKeyDown,
          role: 'combobox',
          'aria-expanded': shown.length > 0,
          'aria-controls': listId,
          'aria-autocomplete': 'list',
        }}
      />

      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}

      {!error && !matcher.error && identifiable.length > 0 && shown.length === 0 && (
        <p className="finder__note">
          Nothing in this SBOM matches “{regex ? query : query.trim()}”.
        </p>
      )}

      {shown.length > 0 && (
        <ul className="finder__results" id={listId} role="listbox">
          {shown.map((component, index) => (
            // The band rides on the <li>, not the <button>: the button's background already
            // carries two states (keyboard-active and currently-open) and a third claim on the
            // same property would fight whichever row you are pointing at. The tint sits behind
            // the transparent button and the edge rule survives both.
            <li key={component.id} data-band={bandOf(component)} title={severityTitle(component)}>
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
                {/* Colour is the only channel for *which* band, so the band is also part of the
                    option's accessible name — otherwise the one piece of information this list
                    was given is the one piece a screen reader cannot reach. Padded with spaces
                    because the accessible name is a concatenation: without them it reads
                    "…vuln-test-parentChecked, nothing known against it1.0.0". */}
                <span className="visually-hidden">{` — ${severityTitle(component)} — `}</span>
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
