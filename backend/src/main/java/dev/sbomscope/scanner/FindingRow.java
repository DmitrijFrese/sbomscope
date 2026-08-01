package dev.sbomscope.scanner;

import java.math.BigDecimal;
import java.time.Instant;

import dev.sbomscope.exploit.ExploitSignals;
import dev.sbomscope.sbom.DependencyScope;

/**
 * One row of the vulnerability view: a component, together with one vulnerability
 * affecting it — or none.
 *
 * <p>A component with three advisories produces three rows, each self-contained and
 * actionable. A component with nothing known against it produces a single row with the
 * advisory fields empty, so the inventory and the findings live in one table rather than
 * two views of the same data.
 *
 * @param osvId null when this component has no known vulnerability. That is deliberately
 *              distinct from a finding whose {@code severityScore} is null, which means
 *              a real vulnerability of unknown severity — "we don't know how bad" must
 *              never be confused with "there is nothing wrong".
 * @param signals what CISA KEV and FIRST EPSS say about this row's CVE, joined at query time
 *              because both feeds are keyed by CVE alone. Never null; {@link ExploitSignals#NONE}
 *              where neither feed has anything, which for KEV is the overwhelming majority —
 *              measured, 4 of 212 distinct CVEs in the maintainer's own SBOMs
 */
public record FindingRow(
        String purl,
        /**
         * {@code group:name}, or just the name where there is no group.
         *
         * <p>Kept alongside the two halves below rather than replaced by them: the export writes
         * it, the Inspector's tab strip reads it, and it is what {@code COMPONENT} sorts by in
         * spirit. The halves exist because the table stacks them, and splitting this string back
         * apart in the browser would be a second reading of what a coordinate is.
         */
        String coordinates,
        /** Null for an npm package with no scope — {@code lodash} has no group at all. */
        String group,
        String name,
        String version,
        boolean root,
        DependencyScope scope,
        String osvId,
        String cveId,
        String summary,
        BigDecimal severityScore,
        String severityRating,
        String cvssVector,
        String cvssVersion,
        String fixedVersion,
        Instant publishedAt,
        ExploitSignals signals) {

    /**
     * A row with nothing from either exploitation feed.
     *
     * <p>For callers that genuinely have no feed data to attach — tests, and anything building a
     * row from a source that never carried signals. Kept as a constructor rather than left to
     * each caller passing {@link ExploitSignals#NONE} so that "no signals" is one value written
     * once, and so a row can never be built with a null in that position.
     */
    public FindingRow(String purl, String coordinates, String version, boolean root,
                      DependencyScope scope, String osvId, String cveId, String summary,
                      BigDecimal severityScore, String severityRating, String cvssVector,
                      String cvssVersion, String fixedVersion, Instant publishedAt) {
        this(purl, coordinates, groupOf(coordinates), nameOf(coordinates), version, root, scope,
                osvId, cveId, summary, severityScore, severityRating, cvssVector, cvssVersion,
                fixedVersion, publishedAt, ExploitSignals.NONE);
    }

    /**
     * The halves of a coordinate, for the convenience constructor only.
     *
     * <p>Deliberately not used by the query path, which reads {@code group_name} and {@code name}
     * from their own columns — this exists so a caller holding only a display string (a test, or
     * anything building a row by hand) still produces a consistent record rather than two nulls.
     * The last colon is the separator because a Maven artifact id cannot contain one, and an npm
     * package with no scope has no colon at all.
     */
    private static String groupOf(String coordinates) {
        int separator = coordinates == null ? -1 : coordinates.lastIndexOf(':');
        return separator < 0 ? null : coordinates.substring(0, separator);
    }

    private static String nameOf(String coordinates) {
        int separator = coordinates == null ? -1 : coordinates.lastIndexOf(':');
        return separator < 0 ? coordinates : coordinates.substring(separator + 1);
    }

    public FindingRow {
        signals = signals == null ? ExploitSignals.NONE : signals;
    }

    public boolean hasFinding() {
        return osvId != null;
    }
}
