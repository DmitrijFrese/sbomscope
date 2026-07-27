package dev.sbomscope.export;

import java.util.List;

import dev.sbomscope.scanner.FindingQuery;

/**
 * What produced this workbook, in the words a reader needs weeks later.
 *
 * <p>The provenance sheet already recorded what was scanned and when. It did not record what
 * was <em>selected</em> — so an export taken with a text filter and three severity bands
 * ticked could not explain why it held 40 rows instead of 600, and a reader had no way to
 * tell a complete picture from a slice of one. That is the same worry that keeps row counts
 * on the export buttons; this closes it on the receiving end.
 */
public record ExportDescription(
        String scope,
        String sortedBy,
        String severityFilter,
        String textFilter,
        String columns) {

    private static final String EVERYTHING = "all";

    public static ExportDescription of(boolean visibleScope, FindingQuery query,
                                       List<ExportColumn> columns) {
        return new ExportDescription(
                visibleScope
                        ? "Current view — this page, filter and sort"
                        : "All findings matching the severity selection",
                sortDescription(query),
                severityDescription(query),
                query.filter() == null || query.filter().isBlank() ? "none" : query.filter(),
                columnDescription(columns));
    }

    private static String sortDescription(FindingQuery query) {
        String direction = query.ascending() ? "ascending" : "descending";
        return switch (query.sort()) {
            case COMPONENT -> "Component, " + direction;
            case SEVERITY -> "Severity, " + direction;
        };
    }

    /** Named bands rather than "5 of 6 selected", which would leave the reader guessing. */
    private static String severityDescription(FindingQuery query) {
        if (query.selectsEverySeverity()) {
            return "every band, including components with no vulnerabilities";
        }
        List<String> names = query.severities().stream()
                .map(band -> switch (band) {
                    case CRITICAL -> "Critical";
                    case HIGH -> "High";
                    case MEDIUM -> "Medium";
                    case LOW -> "Low";
                    case NONE -> "Unscored";
                    case CLEAN -> "No vulnerabilities";
                })
                .toList();
        return String.join(", ", names);
    }

    private static String columnDescription(List<ExportColumn> columns) {
        if (columns.size() == ExportColumn.values().length) {
            return EVERYTHING;
        }
        return String.join(", ", columns.stream().map(ExportColumn::label).toList());
    }
}
