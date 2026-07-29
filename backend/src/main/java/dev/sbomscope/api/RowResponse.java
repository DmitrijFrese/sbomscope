package dev.sbomscope.api;

import java.math.BigDecimal;
import java.time.Instant;

import dev.sbomscope.export.AdvisoryLinks;
import dev.sbomscope.export.RegistryLinks;
import dev.sbomscope.sbom.DependencyScope;
import dev.sbomscope.scanner.FindingRow;

/**
 * One row of the integrated view: a component, plus one vulnerability affecting it or none
 * at all.
 *
 * <p>Its own file rather than a nested record, because two endpoints now return it — the
 * findings table and the Component Inspector's view of a single component. A second shape
 * describing the same row would be free to drift from this one, and the whole reason the
 * Inspector reuses it is that a component must not look different depending on which screen
 * you meet it on.
 *
 * @param osvId null when the component has no known vulnerability — distinct from a finding
 *              with a null {@code severityScore}, which is a real vulnerability of unknown
 *              severity
 */
record RowResponse(
        String purl,
        String coordinates,
        String version,
        boolean root,
        /** APPLICATION, DIRECT or TRANSITIVE — what you can do about a finding. */
        DependencyScope scope,
        String osvId,
        String cveId,
        String summary,
        BigDecimal severityScore,
        /**
         * GitHub's own qualitative label, from the advisory's {@code database_specific}
         * block. A different scale from a different source than {@code severityScore} —
         * MODERATE is not a CVSS word — so the two are shown as separate columns.
         */
        String severityRating,
        /** Which CVSS revision produced the score; v3 and v4 are not comparable. */
        String cvssVersion,
        /** Null when the group's advisories disagree and it cannot be attributed. */
        String cvssVector,
        String fixedVersion,
        Instant publishedAt,
        /** The advisory record; null with no finding. */
        String osvUrl,
        /** NVD; null when the advisory has no CVE counterpart. */
        String cveUrl,
        /**
         * Public registry page. Supplied by the backend rather than built in the browser so
         * the view and the export cannot drift apart — it is the same call the exporter
         * makes.
         */
        String registryUrl) {

    static RowResponse from(FindingRow row) {
        return new RowResponse(
                row.purl(),
                row.coordinates(),
                row.version(),
                row.root(),
                row.scope(),
                row.osvId(),
                row.cveId(),
                row.summary(),
                row.severityScore(),
                row.severityRating(),
                row.cvssVersion(),
                row.cvssVector(),
                row.fixedVersion(),
                row.publishedAt(),
                AdvisoryLinks.osvUrl(row.osvId()),
                AdvisoryLinks.cveUrl(row.cveId()),
                RegistryLinks.forPurl(row.purl()));
    }
}
