package dev.sbomscope.settings;

/**
 * How much of the table an export should carry.
 *
 * @param visibleColumnsOnly when false — the default — the workbook holds every column
 *                           SBOMscope has, whatever the screen was showing. A spreadsheet
 *                           has no width pressure, it is usually read by someone who never
 *                           saw the view it came from, and a recipient cannot recover a
 *                           column that was dropped before they received it. Set true when
 *                           "export what I am looking at" is what you actually mean.
 */
public record ExportSettings(boolean visibleColumnsOnly) {

    public static ExportSettings defaults() {
        return new ExportSettings(false);
    }
}
