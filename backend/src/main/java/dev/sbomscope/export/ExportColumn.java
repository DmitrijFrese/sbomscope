package dev.sbomscope.export;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * The spreadsheet's columns, and the order they appear in.
 *
 * <p>Deliberately the same set, order and labels as the findings table. An export is
 * usually read by someone who never saw the screen it came from, but it is *produced* by
 * someone who did, and a spreadsheet whose columns are arranged differently from the view
 * makes them check every heading before trusting it.
 *
 * <p>{@link #id} matches the identifier the browser uses for the same column, which is what
 * lets the UI ask for a subset without either side maintaining a translation table.
 *
 * <p>Ordering groups each value with its source: the GHSA rating beside the OSV record it
 * comes from, the score leading the CVSS values that produced it.
 */
public enum ExportColumn {

    COMPONENT("component", "Component", 42),
    VERSION("version", "Version", 16),
    SCOPE("scope", "Scope", 12),
    OSV_ID("osvId", "OSV ID", 24),
    GHSA_RATING("ghsaRating", "GHSA rating", 14),
    CVE_ID("cveId", "CVE ID", 18),
    SEVERITY("severity", "Severity", 10),
    CVSS_VERSION("cvssVersion", "CVSS version", 14),
    CVSS_VECTOR("cvssVector", "CVSS vector", 46),
    FIXED_VERSION("fixedVersion", "Fixed in", 14),
    PUBLISHED("published", "Published", 18),
    /** Wide and untruncated — a spreadsheet has the room the table does not. */
    SUMMARY("summary", "Summary", 90),
    PURL("purl", "Package URL", 60);

    private final String id;
    private final String label;
    private final int width;

    ExportColumn(String id, String label, int width) {
        this.id = id;
        this.label = label;
        this.width = width;
    }

    public String id() {
        return id;
    }

    public String label() {
        return label;
    }

    /** Roughly in characters; POI counts in 1/256ths of one. */
    public int widthInCharacters() {
        return width;
    }

    public static List<ExportColumn> all() {
        return List.of(values());
    }

    /**
     * Resolves the browser's column ids, keeping this enum's order rather than the order
     * they arrived in — a spreadsheet whose columns follow whatever sequence someone happened
     * to tick boxes in would be needlessly surprising.
     *
     * <p>Unknown ids are ignored rather than rejected: they mean a UI newer or older than
     * this build, which is not worth failing an export over. An empty result falls back to
     * every column, so a malformed request produces a complete spreadsheet rather than a
     * blank one — the safe direction when the alternative is silently omitting findings.
     */
    public static List<ExportColumn> parse(List<String> ids) {
        if (ids == null || ids.isEmpty()) {
            return all();
        }
        List<String> wanted = ids.stream()
                .filter(id -> id != null && !id.isBlank())
                .map(id -> id.trim().toLowerCase(Locale.ROOT))
                .toList();

        List<ExportColumn> selected = new ArrayList<>();
        for (ExportColumn column : values()) {
            if (wanted.contains(column.id.toLowerCase(Locale.ROOT))) {
                selected.add(column);
            }
        }
        return selected.isEmpty() ? all() : List.copyOf(selected);
    }
}
