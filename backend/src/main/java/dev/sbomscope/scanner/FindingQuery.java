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
        /**
         * Whether {@link #filter} is a regular expression rather than a literal substring.
         *
         * <p>A mode rather than a guess. A purl is made almost entirely of dots, so reading
         * every filter as a regex would silently widen `spring.core` to also match
         * `springXcore` — and would start rejecting literals containing `(` or `[` in a field
         * people type into casually. Off by default; the reader turns it on.
         *
         * <p>Carried on the query object rather than beside it, because the export has to be
         * able to say which mode produced the workbook.
         */
        boolean regexFilter,
        /**
         * Show the rows the filter does <em>not</em> match.
         *
         * <p>Independent of {@link #regexFilter} on purpose: "hide everything from
         * org.springframework" and "hide everything matching {@code (ABC|DEF)}" are the same
         * question asked at two levels of precision, and tying exclusion to regex would make
         * the simpler one unavailable.
         *
         * <p>Negation applies to the <em>row</em>, not to each column: a row is excluded when
         * <em>any</em> of the searched columns matches, because the positive filter shows a row
         * when any of them does. Anything else would let a row be both shown and hidden by the
         * same pattern.
         */
        boolean negateFilter,
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
        return new FindingQuery(SortField.SEVERITY, false, null, false, false, null, null, null, null);
    }

    /** Every row including clean components — used for whole-inventory exports. */
    public static FindingQuery everything() {
        return new FindingQuery(SortField.SEVERITY, false, null, false, false,
                EnumSet.allOf(SeverityBand.class), null, null, null);
    }

    /** Same selection, but every matching row rather than one page. */
    public FindingQuery withoutPaging() {
        return new FindingQuery(sort, ascending, filter, regexFilter, negateFilter, severities, scopes, null, null);
    }

    /** Whether a text filter is actually present, in either mode. */
    public boolean hasFilter() {
        return filter != null && !filter.isBlank();
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
        return new FindingQuery(sort, ascending, null, false, false, severities, scopes, null, null);
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
        SCOPE,
        /**
         * By when the advisory was published — the one column that answers "what is new since I
         * last looked", and the only honest way to order these rows by age.
         *
         * <p>Sorting by CVE id was considered for the same purpose and rejected: the year in
         * {@code CVE-2020-9547} orders correctly across years, but the sequence number is not
         * zero-padded, so within a year {@code CVE-2020-9547} sorts after {@code
         * CVE-2020-10001}. Half-right ordering presented as chronological is worse than no
         * ordering at all, and this column is right all the way down.
         *
         * <p>Nulls last in both directions, as {@code FIXED_VERSION} does: an advisory with no
         * publication date has no place on a time axis.
         */
        PUBLISHED,
        /**
         * By GitHub's own severity word — CRITICAL, HIGH, MODERATE, LOW — ranked explicitly.
         *
         * <p><b>Not a duplicate of {@link #SEVERITY}.</b> That one orders by the numeric CVSS
         * score; this orders by the rating the advisory database assigned, and the two
         * genuinely disagree — which is the entire reason the column exists beside the score
         * rather than instead of it.
         *
         * <p>Note the scale is GitHub's, so the middle band is {@code MODERATE} and not
         * {@code MEDIUM}. Ranked by a stated {@code CASE} rather than alphabetically, which
         * would put CRITICAL, HIGH, LOW, MODERATE — an order with no meaning at all.
         */
        GHSA_RATING,
        /**
         * By whether CISA lists the CVE as actively exploited, most recently listed first.
         *
         * <p>This is the whole interaction for KEV: a filter was considered and deliberately
         * not built, because with 4 of 212 rows listed one click on the header produces the
         * same set with no state to persist, revive or record on the About sheet.
         *
         * <p>Ordered by {@code date_added} rather than by a boolean, so descending brings the
         * most recently listed to the top rather than an arbitrary order within one group —
         * and listed-four-years-ago against listed-last-week is a real difference in how far
         * behind you are. Rows CISA does not list sort last in both directions: "not listed"
         * is not a position on this axis.
         *
         * <p><b>Consequence worth knowing:</b> "exploited, worst first" needs two criteria at
         * once and is therefore unavailable until secondary sort (B10) lands.
         */
        KEV,
        /**
         * By EPSS probability, highest first when descending.
         *
         * <p>Nulls last in both directions, as {@code FIXED_VERSION} and {@code PUBLISHED} are:
         * a CVE EPSS does not score has no probability, and letting those lead an ascending
         * sort would answer "least likely to be exploited" with "the ones nobody scored".
         */
        EPSS
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
