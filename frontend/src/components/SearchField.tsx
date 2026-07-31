import type { InputHTMLAttributes, Ref } from 'react';

interface SearchFieldProps {
  value: string;
  onValueChange: (value: string) => void;
  regex: boolean;
  onRegexChange: (regex: boolean) => void;
  negate: boolean;
  onNegateChange: (negate: boolean) => void;
  /** Shown when regex is off; the regex placeholder is derived from it. */
  placeholder: string;
  ariaLabel: string;
  /** Why the current pattern was rejected, if it was. Rendered as a note, not an alert. */
  note?: string | null;
  /** The input's own class, since the toolbar and the finder size their boxes differently. */
  inputClassName: string;
  inputRef?: Ref<HTMLInputElement>;
  /** Combobox wiring and key handling, for the callers that need it. */
  inputProps?: InputHTMLAttributes<HTMLInputElement>;
}

/**
 * A search box with a regular-expression toggle inside it.
 *
 * <p>One component rather than one per field: the toggle's meaning, its position, its pressed
 * state and the way a rejected pattern is reported are the same claim wherever a search field
 * appears, and four copies would be four places for that claim to drift.
 *
 * <p><b>The control is `.*`, inside the box, and not a magnifier.</b> A magnifier reads as
 * "search now", and search here runs as you type in both modes — the toggle changes what
 * matches, never when it runs. `.*` is what VS Code and IntelliJ use for exactly this, so it
 * arrives already meaning something to most readers.
 *
 * <p><b>A rejected pattern is a note, not an alert.</b> A filter field is typed into one
 * character at a time, so `^(org\.spring` exists on the way to every pattern that starts that
 * way — announcing each one would talk over somebody who is still typing, and blanking the
 * results underneath would make the whole field flicker. `aria-live="polite"` says it once the
 * typing stops.
 */
export function SearchField({
  value,
  onValueChange,
  regex,
  onRegexChange,
  negate,
  onNegateChange,
  placeholder,
  ariaLabel,
  note,
  inputClassName,
  inputRef,
  inputProps,
}: SearchFieldProps) {
  // Two independent modes, so the placeholder says which are on rather than naming one and
  // leaving the other to be discovered by its results.
  const modes = [negate ? 'excluding' : null, regex ? 'regular expression' : null].filter(Boolean);
  const described = modes.length > 0 ? `${placeholder} — ${modes.join(', ')}` : placeholder;

  return (
    <div className="search-field" data-negated={negate}>
      <input
        {...inputProps}
        ref={inputRef}
        type="search"
        className={inputClassName}
        placeholder={described}
        value={value}
        onChange={(event) => onValueChange(event.target.value)}
        spellCheck={false}
        autoComplete="off"
        aria-label={modes.length > 0 ? `${ariaLabel} (${modes.join(', ')})` : ariaLabel}
        aria-invalid={note ? true : undefined}
      />
      <div className="search-field__toggles">
        {/* Exclusion first, reading left to right as "not this pattern" — the negation applies
            to whatever the regex toggle beside it decides the pattern means, and putting it
            after would read as negating the mode rather than the match. */}
        <button
          type="button"
          className="search-field__toggle"
          data-active={negate}
          aria-pressed={negate}
          onClick={() => onNegateChange(!negate)}
          title={
            negate
              ? 'Hiding rows that match. Turn off to show them instead.'
              : 'Hide rows that match, instead of showing them'
          }
        >
          !
        </button>
        <button
          type="button"
          className="search-field__toggle"
          data-active={regex}
          aria-pressed={regex}
          onClick={() => onRegexChange(!regex)}
          title={
            regex
              ? 'Matching as a regular expression. Turn off to match literal text.'
              : 'Match as a regular expression'
          }
        >
          .*
        </button>
      </div>
      {note && (
        <p className="search-field__note" aria-live="polite">
          {note}
        </p>
      )}
    </div>
  );
}
