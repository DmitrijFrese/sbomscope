package dev.sbomscope.scanner;

/**
 * Whether an advisory's {@code affected} entry covers a given version.
 *
 * <p>Its own class because two callers now need it and they must not answer it differently:
 * the report parser, deciding which branch of an advisory a scanned component sits on, and
 * the local matcher, deciding whether a version the user does not have would still be
 * affected. Version-range semantics written twice would drift, and the direction it would
 * drift in is "this upgrade is clean" against "this upgrade is not".
 */
final class AffectedVersions {

    private AffectedVersions() {
    }

    /**
     * The full test: an explicit enumeration if the advisory has one, ranges otherwise.
     *
     * <p>{@code versions[]} is preferred where present — around 90% of the Maven set — since
     * matching it is string equality with none of the ordering guesswork a range needs. A
     * version listed there is affected regardless of what the ranges say.
     */
    static boolean affects(OsvReport.Affected affected, String version) {
        if (affected == null || version == null || version.isBlank()) {
            return false;
        }
        if (affected.versions() != null && affected.versions().contains(version)) {
            return true;
        }
        return coveredByRanges(affected, version);
    }

    /**
     * Ranges only.
     *
     * <p>A range is a sequence of events rather than a pair of bounds, so the bounds are
     * accumulated as the events are read. {@code "0"} is OSV's way of writing "from the
     * beginning", and an entry ending in {@code last_affected} rather than {@code fixed}
     * has no fix at all — an inclusive upper bound instead of an exclusive one.
     */
    static boolean coveredByRanges(OsvReport.Affected affected, String version) {
        if (affected == null || affected.ranges() == null || version == null || version.isBlank()) {
            return false;
        }

        for (OsvReport.Range range : affected.ranges()) {
            if (range.events() == null) {
                continue;
            }
            String introduced = null;
            String upperExclusive = null;
            String upperInclusive = null;

            for (OsvReport.Event event : range.events()) {
                if (event.introduced() != null) {
                    introduced = event.introduced();
                }
                if (event.fixed() != null) {
                    upperExclusive = event.fixed();
                }
                if (event.lastAffected() != null) {
                    upperInclusive = event.lastAffected();
                }
            }

            boolean atOrAfterStart = introduced == null
                    || "0".equals(introduced)
                    || VersionOrder.INSTANCE.compare(version, introduced) >= 0;

            boolean beforeEnd = (upperExclusive == null && upperInclusive == null)
                    || (upperExclusive != null && VersionOrder.INSTANCE.compare(version, upperExclusive) < 0)
                    || (upperInclusive != null && VersionOrder.INSTANCE.compare(version, upperInclusive) <= 0);

            if (atOrAfterStart && beforeEnd) {
                return true;
            }
        }
        return false;
    }
}
