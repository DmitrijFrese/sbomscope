package dev.sbomscope.api;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;

import dev.sbomscope.exploit.ExploitSignals;
import dev.sbomscope.exploit.KevEntry;
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
        /** {@code group:name} — still sent, because several views read the whole coordinate. */
        String coordinates,
        /**
         * The two halves, so the table can stack them without splitting the string above.
         *
         * <p>{@code group} is null for an npm package with no scope, and the cell reserves its
         * line anyway: ragged row heights matter more than usual once the column is frozen,
         * because that column is what the eye tracks while scrolling sideways.
         */
        String group,
        String name,
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
         * The artifact's own registry page, version-independent. Supplied by the backend
         * rather than built in the browser so the view and the export cannot drift apart —
         * it is the same call the exporter makes.
         */
        String registryArtifactUrl,
        /**
         * The page for this exact version, which does not exist for every version — a
         * vendor-patched {@code a.b.c.d} build has no page on Central. Null then, and the
         * artifact page above is what the reader is offered instead.
         */
        String registryVersionUrl,
        /**
         * When CISA listed this CVE as actively exploited, or null.
         *
         * <p>Null is <em>not</em> "CISA has cleared this". It covers two states the browser
         * distinguishes with what it already knows: a finding with no CVE cannot be looked up at
         * all, and one with a CVE simply is not listed. The third state — the catalogue was never
         * downloaded — is identical on every row at once, so it is reported once above the table
         * rather than stamped into three hundred cells.
         */
        LocalDate kevListedOn,
        /** CISA has confirmed ransomware use. A positive signal only; false is not a denial. */
        boolean kevRansomware,
        /** Probability of exploitation in the next 30 days, or null where EPSS does not score it. */
        Double epssScore,
        /** Where that score sits among all scored CVEs — what makes 0.033 readable. */
        Double epssPercentile,
        /**
         * CISA's per-CVE page, present only when the flag is set.
         *
         * <p>Derived from the identifier alone, as the NVD link is, so producing it asks nobody
         * anything. Absent on unlisted rows deliberately: a blank cell linking to a search that
         * finds nothing would be a promise the page cannot keep.
         */
        String kevUrl) {

    static RowResponse from(FindingRow row) {
        RegistryLinks.Links links = RegistryLinks.forPurl(row.purl());
        ExploitSignals signals = row.signals();
        return new RowResponse(
                row.purl(),
                row.coordinates(),
                row.group(),
                row.name(),
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
                links.artifactUrl(),
                links.versionUrl(),
                signals.kevDateAdded(),
                signals.kevRansomware(),
                signals.epssScore(),
                signals.epssPercentile(),
                signals.kevListed() ? KevEntry.catalogUrl(row.cveId()) : null);
    }
}
