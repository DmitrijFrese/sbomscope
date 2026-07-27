package dev.sbomscope.scanner;

import java.math.BigDecimal;
import java.time.Instant;

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
 */
public record FindingRow(
        String purl,
        String coordinates,
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
        Instant publishedAt) {

    public boolean hasFinding() {
        return osvId != null;
    }
}
