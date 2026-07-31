package dev.sbomscope.scanner;

import java.sql.Connection;
import java.sql.Statement;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.UUID;

import javax.sql.DataSource;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The text filter read as a regular expression, against the real Flyway-built schema.
 *
 * <p>Run through {@code VulnerabilityRepository} rather than against H2 directly, because the
 * claim being protected is not "H2 has REGEXP_LIKE" but "the filter the view uses, the count
 * beside it and the export all read one pattern the same way". A regex that selected different
 * rows in the count than in the page would reproduce, in a new mode, the exact drift the shared
 * {@code FindingQuery} exists to prevent.
 */
@SpringBootTest
class FindingRegexFilterTest {

    @Autowired
    private VulnerabilityRepository repository;

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private DataSource dataSource;

    private final UUID sbomId = UUID.randomUUID();

    /** Unique per run: findings are keyed by purl and shared across every SBOM. */
    private final String tag = UUID.randomUUID().toString().substring(0, 8);

    @BeforeEach
    void seed() {
        jdbc.update("INSERT INTO sbom (id, filename, uploaded_at, spec_version, component_count)"
                        + " VALUES (?, ?, ?, ?, ?)",
                sbomId, "regex.cdx.json", OffsetDateTime.now(ZoneOffset.UTC), "1.6", 0);

        // The pair the whole toggle is about: a literal dot, and a character where the dot is.
        component("org.springframework", "spring.core");
        component("org.springframework", "springXcore");
        component("com.fasterxml.jackson.core", "jackson-databind");
        component("io.netty", "netty-all");
    }

    /** A scanned component carrying one advisory, so it survives the default severity bands. */
    private void component(String group, String name) {
        String purl = "pkg:maven/%s/%s@1.0.0-%s".formatted(group, name, tag);
        jdbc.update("INSERT INTO component (id, sbom_id, bom_ref, group_name, name, version, purl,"
                        + " dependency_scope) VALUES (?, ?, ?, ?, ?, ?, ?, 'DIRECT')",
                UUID.randomUUID(), sbomId, purl, group, name, "1.0.0", purl);
        jdbc.update("INSERT INTO vulnerability_scan (purl, scanned_at, scanner_version)"
                        + " VALUES (?, ?, ?)",
                purl, OffsetDateTime.now(ZoneOffset.UTC), "test");
        jdbc.update("INSERT INTO vulnerability_finding (id, purl, osv_id, cve_id, severity_score)"
                        + " VALUES (?, ?, ?, ?, ?)",
                UUID.randomUUID(), purl, "GHSA-" + name, "CVE-2026-1000", new java.math.BigDecimal("7.5"));
    }

    private FindingQuery query(String filter, boolean regex) {
        return query(filter, regex, false);
    }

    private FindingQuery query(String filter, boolean regex, boolean negate) {
        return new FindingQuery(FindingQuery.SortField.COMPONENT, true, filter, regex, negate,
                EnumSet.allOf(FindingQuery.SeverityBand.class), null, null, null);
    }

    private List<String> namesExcluding(String filter, boolean regex) {
        List<String> names = new ArrayList<>();
        for (FindingRow row : repository.rowsForSbom(sbomId, query(filter, regex, true))) {
            names.add(row.coordinates());
        }
        return names;
    }

    private List<String> namesMatching(String filter, boolean regex) {
        List<String> names = new ArrayList<>();
        for (FindingRow row : repository.rowsForSbom(sbomId, query(filter, regex))) {
            names.add(row.coordinates());
        }
        return names;
    }

    @Test
    void aDotIsLiteralWithTheToggleOffAndAnyCharacterWithItOn() {
        // The behaviour change the toggle exists to keep opt-in, stated as a test rather than
        // as a worry: the same six characters select one row or two depending on the mode.
        assertThat(namesMatching("spring.core", false))
                .containsExactly("org.springframework:spring.core");

        assertThat(namesMatching("spring.core", true))
                .containsExactlyInAnyOrder(
                        "org.springframework:spring.core",
                        "org.springframework:springXcore");
    }

    @Test
    void supportsTheJavaOnlyConstructsTheItemAskedFor() {
        // Lookahead, lookbehind, a named backreference and an atomic group. These are what
        // distinguish java.util.regex from a simpler engine, so they are what proves H2 is
        // running Java's own — the claim the whole SQL-side approach rests on.
        assertThat(namesMatching("^pkg:maven/(?!com\\.).*netty.*$", true))
                .containsExactly("io.netty:netty-all");
        assertThat(namesMatching("(?<=springframework/)spring\\.core", true))
                .containsExactly("org.springframework:spring.core");
        assertThat(namesMatching("(?<w>jackson)-databind@1\\.0\\.0", true))
                .containsExactly("com.fasterxml.jackson.core:jackson-databind");
        assertThat(namesMatching("(?>netty)-all", true))
                .containsExactly("io.netty:netty-all");
    }

    @Test
    void matchesCaseInsensitivelyLikeTheLiteralFilterDoes() {
        // Turning one toggle must change one thing. The literal filter lower-cases both sides,
        // so a regex that suddenly cared about case would be a second, unannounced change.
        assertThat(namesMatching("NETTY-ALL", true)).containsExactly("io.netty:netty-all");
    }

    @Test
    void letsAPatternAskForCaseSensitivityBack() {
        // Which is what stops the default above from being a dead end.
        assertThat(namesMatching("(?-i)NETTY-ALL", true)).isEmpty();
        assertThat(namesMatching("(?-i)netty-all", true)).containsExactly("io.netty:netty-all");
    }

    @Test
    void theCountAgreesWithTheRowsItIsCounting() {
        // The property the shared query path exists for, now in a second mode. A count that
        // disagreed with the page would put a wrong number on the export button.
        FindingQuery regex = query("spring.core", true);
        assertThat(repository.countRows(sbomId, regex))
                .isEqualTo(repository.rowsForSbom(sbomId, regex).size())
                .isEqualTo(2);
    }

    @Test
    void whitespaceIsSignificantInAPatternAndNotInALiteral() {
        // "netty " and "netty" are different regexes; as a substring the trailing space is a
        // typing artefact. Same field, two honest readings.
        assertThat(namesMatching(" netty-all ", false)).containsExactly("io.netty:netty-all");
        assertThat(namesMatching("netty-all ", true)).isEmpty();
    }

    @Test
    void anInvalidPatternIsRejectedBeforeItReachesTheDatabase() {
        // A half-written pattern is the common case, not the exceptional one. It has to carry
        // Java's own description, which names where the problem is.
        assertThatThrownBy(() -> repository.rowsForSbom(sbomId, ScanService.validated(query("spring(", true))))
                .isInstanceOf(InvalidFilterPatternException.class)
                .hasMessageContaining("Unclosed group")
                .hasMessageContaining("position");

        assertThatThrownBy(() -> ScanService.validated(query("[a-", true)))
                .isInstanceOf(InvalidFilterPatternException.class);
    }

    @Test
    void negationHidesExactlyWhatTheSameFilterWouldHaveShown() {
        // The property that makes the toggle trustworthy: shown and excluded must partition the
        // table. If they overlap, one filter both shows and hides a row; if they leave a gap, a
        // row is invisible under both polarities and nothing on screen says so.
        List<String> all = namesMatching("", false);
        List<String> shown = namesMatching("netty", false);
        List<String> hidden = namesExcluding("netty", false);

        assertThat(shown).isNotEmpty();
        assertThat(hidden).isNotEmpty();
        assertThat(shown).doesNotContainAnyElementsOf(hidden);
        assertThat(shown.size() + hidden.size()).isEqualTo(all.size());
    }

    @Test
    void negationWorksWithARegexAsWellAsALiteral() {
        // The maintainer's own example: (ABC|DEF) with both toggles on removes everything
        // matching either alternative, rather than the two being mutually exclusive modes.
        assertThat(namesExcluding("(netty|jackson)", true))
                .isNotEmpty()
                .noneSatisfy(name -> assertThat(name).containsIgnoringCase("netty"))
                .noneSatisfy(name -> assertThat(name).containsIgnoringCase("jackson"));
    }

    @Test
    void negationIsOfTheRowNotOfEachColumn() {
        // A row is excluded when *any* searched column matches, because the positive form shows
        // it when any of them does. Excluding by CVE id must therefore drop the row entirely,
        // not keep it on the grounds that its purl did not match.
        assertThat(namesMatching("CVE-2026-1000", false)).isNotEmpty();
        assertThat(namesExcluding("CVE-2026-1000", false)).isEmpty();
    }

    @Test
    void aComponentWithNoPurlSurvivesAnExclusion() {
        // The NULL trap this needed COALESCE for. Positively, LOWER(NULL) LIKE '%x%' is NULL —
        // not TRUE — so the row simply does not match. Negated, NOT(NULL) is also NULL, so
        // without the coalesce the row would vanish from a search for everything *not*
        // containing "x", despite plainly not containing it.
        String bomRef = "no-purl-" + tag;
        jdbc.update("INSERT INTO component (id, sbom_id, bom_ref, group_name, name, version, purl,"
                        + " dependency_scope) VALUES (?, ?, ?, ?, ?, ?, NULL, 'DIRECT')",
                UUID.randomUUID(), sbomId, bomRef, "dev.sbomscope.test", "no-purl", "1.0.0");

        assertThat(namesExcluding("netty", false)).contains("dev.sbomscope.test:no-purl");
    }

    @Test
    void anInvalidPatternIsHarmlessWhileTheToggleIsOff() {
        // The same text with regex off is an ordinary substring nobody has, not an error.
        assertThat(namesMatching("spring(", false)).isEmpty();
    }

    @Test
    void h2ScopesAQueryTimeoutToTheSessionRatherThanTheStatement() throws Exception {
        // Pinned because the repository's `bounded` is built entirely around it. If a future
        // H2 made setQueryTimeout statement-scoped, the reset dance there becomes dead weight
        // and this test is what says so.
        try (Connection connection = dataSource.getConnection()) {
            try (Statement first = connection.createStatement()) {
                first.setQueryTimeout(7);
            }
            try (Statement second = connection.createStatement()) {
                assertThat(second.getQueryTimeout())
                        .as("a fresh statement on the same connection inherits it")
                        .isEqualTo(7);
            }
            try (Statement reset = connection.createStatement()) {
                reset.setQueryTimeout(0);
            }
        }
    }

    @Test
    void aRegexQueryLeavesNoTimeoutBehindOnThePooledConnection() throws Exception {
        // The consequence of the test above: without the reset, one regex filter would put a
        // ceiling on whatever borrowed that connection next — a scan write, an export — with
        // nothing to connect the eventual failure to the filter that caused it.
        repository.rowsForSbom(sbomId, query("spring.*core", true));

        List<Connection> borrowed = new ArrayList<>();
        try {
            // Drain rather than sample: the pool decides which connection comes back, so
            // checking one proves nothing about the one that ran the query.
            for (int i = 0; i < 8; i++) {
                Connection connection = dataSource.getConnection();
                borrowed.add(connection);
                try (Statement statement = connection.createStatement()) {
                    assertThat(statement.getQueryTimeout())
                            .as("connection %d still carries a query timeout", i)
                            .isZero();
                }
            }
        } finally {
            for (Connection connection : borrowed) {
                connection.close();
            }
        }
    }
}
