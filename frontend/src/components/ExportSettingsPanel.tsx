import { useEffect, useState } from 'react';

import { fetchExportSettings, saveExportSettings } from '../api/client';

const OPTIONS: ReadonlyArray<{ value: boolean; label: string; hint: string }> = [
  {
    value: false,
    label: 'Every column',
    hint: 'The workbook holds everything SBOMscope knows, whatever the table is showing. A spreadsheet has no width limit, and a reader cannot recover a column that was dropped before they received it.',
  },
  {
    value: true,
    label: 'Only the columns on screen',
    hint: 'The workbook mirrors the table exactly, including your Compact selection. Choose this when the export is meant to be what you are looking at.',
  },
];

/** Which columns an exported workbook carries. Rows are decided by the export menu. */
export function ExportSettingsPanel() {
  const [visibleColumnsOnly, setVisibleColumnsOnly] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetchExportSettings()
      .then((settings) => {
        if (!cancelled) setVisibleColumnsOnly(settings.visibleColumnsOnly);
      })
      .catch((e) => {
        if (!cancelled) setError(e instanceof Error ? e.message : 'Could not load export settings.');
      });
    return () => {
      cancelled = true;
    };
  }, []);

  async function choose(value: boolean) {
    const previous = visibleColumnsOnly;
    setVisibleColumnsOnly(value);
    setSaving(true);
    setError(null);
    try {
      await saveExportSettings({ visibleColumnsOnly: value });
    } catch (e) {
      // Put the control back where it was: a radio showing a choice the server did not
      // accept would misreport what the next export will actually do.
      setVisibleColumnsOnly(previous);
      setError(e instanceof Error ? e.message : 'Could not save that setting.');
    } finally {
      setSaving(false);
    }
  }

  return (
    <section className="panel" aria-labelledby="settings-export">
      <h2 className="panel__title" id="settings-export">
        Excel export
      </h2>
      <p className="panel__hint">
        How much of the table an exported workbook carries. Which <em>rows</em> it carries is
        chosen at the moment you export, from the Export menu.
      </p>

      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}

      <fieldset className="setting-group" disabled={visibleColumnsOnly === null || saving}>
        <legend className="setting-group__legend">Columns</legend>

        {OPTIONS.map((option) => (
          <label className="setting-option" key={String(option.value)}>
            <input
              type="radio"
              name="export-columns"
              checked={visibleColumnsOnly === option.value}
              onChange={() => choose(option.value)}
            />
            <span>
              <span className="setting-option__label">{option.label}</span>
              <span className="setting-option__hint">{option.hint}</span>
            </span>
          </label>
        ))}
      </fieldset>
    </section>
  );
}
