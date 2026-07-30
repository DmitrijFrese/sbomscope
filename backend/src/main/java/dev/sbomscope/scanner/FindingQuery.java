package dev.sbomscope.scanner;

import java.util.Collection;
import java.util.EnumSet;
import java.util.Set;

import dev.sbomscope.sbom.DependencyScope;

/**
 * How a findings list should be selected, ordered and windowed.
 *
 * <p>Carried as one object so the view, the row counts and the export all describe the
 * same query — the export is meant to reproduce what is on screen, and that only holds
 * if there is one description of "what is on screen".
 */
public record FindingQuery(
        SortField sort,
        boolean ascending,
        String filter,
        Set<SeverityBand> severities,
        /**
         * Which dependency scopes to show. Defaults to all three — unlike severity, where the
         * default deliberately hides clean rows, there is no scope a reader is normally not
         * interested in.
         */
        Set<DependencyScope> scopes,
        Integer limit,
        Integer offset) {

    public FindingQuery {
        sort = sort == null ? SortField.SEVERITY : sort;
        severities = severities == null || severities.isEmpty()
                ? vulnerableBands()
                : EnumSet.copyOf(severities);
        scopes = scopes == null || scopes.isEmpty()
                ? EnumSet.allOf(DependencyScope.class)
                : EnumSet.copyOf(scopes);
    }

    /** Default view: vulnerabilities only, most severe first. */
    public static FindingQuery defaults() {
        return new FindingQuery(SortField.SEVERITY, false, null, null, null, null, null);
    }

    /** Every row including clean components — used for whole-inventory exports. */
    public static FindingQuery everything() {
        return new FindingQuery(SortField.SEVERITY, false, null,
                EnumSet.allOf(SeverityBand.class), null, null, null);
    }

    /** Same selection, but every matching row rather than one page. */
    public FindingQuery withoutPaging() {
        return new FindingQuery(sort, ascending, filter, severities, scopes, null, null);
    }

    public boolean selectsEveryScope() {
        return scopes.size() == DependencyScope.values().length;
    }

    /** Parses the scope names a request carries, falling back to all three. */
    public static Set<DependencyScope> parseScopes(Collection<String> values) {
        if (values == null || values.isEmpty()) {
            return EnumSet.allOf(DependencyScope.class);
        }
        Set<DependencyScope> parsed = EnumSet.noneOf(DependencyScope.class);
        for (String value : values) {
            if (value == null || value.isBlank()) {
                continue;
            }
            parsed.add(DependencyScope.valueOf(value.trim().toUpperCase()));
        }
        return parsed.isEmpty() ? EnumSet.allOf(DependencyScope.class) : parsed;
    }

    /**
     * Same ordering and the same severity selection, but no text filter or paging.
     *
     * <p>The severity selection is kept deliberately: someone who has narrowed to
     * critical and high and then exports "all" means all critical and high findings, not
     * a sudden reappearance of everything they filtered out.
     */
    public FindingQuery unfiltered() {
        return new FindingQuery(sort, ascending, null, severities, scopes, null, null);
    }

    public boolean selectsEverySeverity() {
        return severities.size() == SeverityBand.values().length;
    }

    public enum SortField {
        /** By library coordinates. purl orders group-then-artifact, which is what a
         *  reader scanning an alphabetical list expects. */
        COMPONENT,
        /** By numeric CVSS score — the ordering that reflects risk rather than spelling. */
        SEVERITY,
        /**
         * By the version an advisory names as the fix, ordered as a version rather than as a
         * string — {@code 1.9.0} before {@code 1.10.0}, which lexical ordering gets backwards.
         *
         * <p>Rows with no fix sort last in <em>both</em> directions: "no fix" is not a version
         * and must not answer "which fix is furthest away".
         */
        FIXED_VERSION,
        /**
         * By dependency scope, ranked APPLICATION, DIRECT, TRANSITIVE — how directly you can
         * do something about it, which is not the order the words fall in alphabetically by
         * anything more than coincidence.
         */
        SCOPE
    }

    /** Bands with an actual vulnerability behind them, i.e. everything except CLEAN. */
    public static Set<SeverityBand> vulnerableBands() {
        return EnumSet.complementOf(EnumSet.of(SeverityBand.CLEAN));
    }

    /**
     * Standard CVSS qualitative bands, plus two that are not severities at all.
     *
     * <p>{@link #NONE} is a real vulnerability whose advisory carries no CVSS score —
     * unknown severity. {@link #CLEAN} is a component with no known vulnerability. Keeping
     * them apart matters: merging them would let "we don't know how bad this is" read as
     * "this is fine", which is the one mistake a vulnerability tool must not make.
     */
    public enum SeverityBand {
        CRITICAL,
        HIGH,
        MEDIUM,
        LOW,
        /** A vulnerability with no CVSS score. */
        NONE,
        /** A component with no known vulnerability at all. */
        CLEAN;

        public static Set<SeverityBand> parse(Collection<String> values) {
            if (values == null || values.isEmpty()) {
                // Defaults to vulnerabilities only, so opening the view shows what needs
                // attention rather than burying it among clean components.
                return vulnerableBands();
            }
            Set<SeverityBand> bands = EnumSet.noneOf(SeverityBand.class);
            for (String value : values) {
                if (value == null || value.isBlank()) {
                    continue;
                }
                bands.add(SeverityBand.valueOf(value.trim().toUpperCase()));
            }
            return bands.isEmpty() ? vulnerableBands() : bands;
        }
    }
}
