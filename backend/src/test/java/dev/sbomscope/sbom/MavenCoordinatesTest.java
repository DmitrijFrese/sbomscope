package dev.sbomscope.sbom;

import java.io.InputStream;
import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import dev.sbomscope.sbom.ParsedSbom.ParsedComponent;
import dev.sbomscope.scanner.FindingQuery;
import dev.sbomscope.scanner.FindingRow;
import dev.sbomscope.scanner.VulnerabilityRepository;

import static org.assertj.core.api.Assertions.assertThat;

/** Maven qualifier storage and the query/display behaviour built on it. */
@SpringBootTest
@Transactional
class MavenCoordinatesTest {

    @Autowired
    private CycloneDxParser parser;

    @Autowired
    private SbomRepository sboms;

    @Autowired
    private VulnerabilityRepository findings;

    @Autowired
    private JdbcTemplate jdbc;

    private InputStream fixture(String name) {
        InputStream stream = getClass().getResourceAsStream("/sboms/" + name);
        assertThat(stream).as("fixture %s should exist", name).isNotNull();
        return stream;
    }

    private ParsedSbom classifierFixture() {
        return parser.parse(fixture("maven-classifiers.cdx.json"));
    }

    private ParsedComponent component(ParsedSbom parsed, String purlPart) {
        return parsed.components().stream()
                .filter(candidate -> candidate.purl() != null && candidate.purl().contains(purlPart))
                .findFirst()
                .orElseThrow();
    }

    private UUID store(ParsedSbom parsed) {
        UUID id = UUID.randomUUID();
        sboms.insertSbom(new StoredSbom(
                id, "maven-classifiers.cdx.json", Instant.now(), null,
                parsed.specVersion(), parsed.components().size()));
        sboms.insertComponents(id, parsed.components());
        return id;
    }

    private StoredComponent stored(ParsedComponent component) {
        return new StoredComponent(
                UUID.randomUUID(), component.bomRef(), component.group(), component.name(),
                component.version(), component.purl(), component.type(), component.mavenType(),
                component.mavenClassifier(), component.root(), component.scope());
    }

    private FindingQuery query(String filter, boolean regex, boolean negate, boolean ascending) {
        return new FindingQuery(
                FindingQuery.SortField.COMPONENT,
                ascending,
                filter,
                regex,
                negate,
                EnumSet.allOf(FindingQuery.SeverityBand.class),
                null,
                false,
                false,
                null,
                null);
    }

    @Test
    void importStoresDeclaredMavenQualifiersAndLeavesNpmNull() {
        ParsedSbom maven = classifierFixture();
        ParsedComponent sources = component(maven, "classifier=sources");
        ParsedComponent ordinary = component(maven, "jackson-databind@3.1.4?type=jar");

        assertThat(sources.mavenType()).isEqualTo("jar");
        assertThat(sources.mavenClassifier()).isEqualTo("sources");
        assertThat(ordinary.mavenType()).isEqualTo("jar");
        assertThat(ordinary.mavenClassifier()).isNull();

        UUID mavenId = store(maven);
        assertThat(jdbc.queryForMap(
                        "SELECT maven_type, maven_classifier FROM component"
                                + " WHERE sbom_id = ? AND purl = ?",
                        mavenId, sources.purl()))
                .containsEntry("MAVEN_TYPE", "jar")
                .containsEntry("MAVEN_CLASSIFIER", "sources");

        ParsedSbom npm = parser.parse(fixture("npm-frontend.cdx.json"));
        assertThat(npm.components())
                .allSatisfy(component -> {
                    assertThat(component.mavenType()).isNull();
                    assertThat(component.mavenClassifier()).isNull();
                });
        UUID npmId = store(npm);
        assertThat(jdbc.queryForObject(
                "SELECT COUNT(*) FROM component WHERE sbom_id = ?"
                        + " AND (maven_type IS NOT NULL OR maven_classifier IS NOT NULL)",
                Integer.class, npmId)).isZero();
    }

    @Test
    void aRealMavenPurlWithNoQualifiersLeavesBothValuesNull() throws Exception {
        JsonNode report = new ObjectMapper().readTree(fixture("osv-report-maven.json"));
        // findValuesAsString, not findValuesAsText: Jackson 3 renamed it, and the old name
        // still compiles nowhere — see the Jackson 3 note in AGENTS.md.
        String purl = report.findValuesAsString("purl").stream()
                .filter(candidate -> candidate.startsWith("pkg:maven/") && !candidate.contains("?"))
                .findFirst()
                .orElseThrow();

        PurlQualifierParser.MavenQualifiers qualifiers =
                PurlQualifierParser.mavenQualifiers(purl);

        assertThat(qualifiers.type()).isNull();
        assertThat(qualifiers.classifier()).isNull();
    }

    @Test
    void displayIncludesOnlyNonDefaultMavenPartsAndLeavesNpmUnchanged() {
        ParsedSbom maven = classifierFixture();

        assertThat(stored(component(maven, "jackson-databind@3.1.4?type=jar")).displayCoordinates())
                .isEqualTo("tools.jackson.core:jackson-databind");
        assertThat(stored(component(maven, "classifier=sources")).displayCoordinates())
                .isEqualTo("tools.jackson.core:jackson-databind:sources");
        assertThat(stored(component(maven, "spring-boot-dependencies")).displayCoordinates())
                .isEqualTo("org.springframework.boot:spring-boot-dependencies:pom");
        assertThat(stored(component(maven, "commons-lang3")).displayCoordinates())
                .isEqualTo("org.apache.commons:commons-lang3:test-jar:tests");

        ParsedComponent npm = parser.parse(fixture("npm-frontend.cdx.json")).components().getFirst();
        String existingForm = npm.group() == null || npm.group().isBlank()
                ? npm.name()
                : npm.group() + ":" + npm.name();
        assertThat(stored(npm).displayCoordinates()).isEqualTo(existingForm);
    }

    @Test
    void convenienceFindingRowSplitsBeforeExtendedParts() {
        FindingRow row = new FindingRow(
                "pkg:maven/g/a@1?classifier=tests&type=jar",
                "g:a:tests",
                "1",
                false,
                DependencyScope.DIRECT,
                null, null, null, null, null, null, null, null, null);

        assertThat(row.group()).isEqualTo("g");
        assertThat(row.name()).isEqualTo("a");
    }

    @Test
    void backfillPopulatesPreV12RowsOnce() {
        ParsedComponent component = component(classifierFixture(), "commons-lang3");
        UUID sbomId = UUID.randomUUID();
        UUID componentId = UUID.randomUUID();
        sboms.insertSbom(new StoredSbom(
                sbomId, "pre-v12.cdx.json", Instant.now(), null, "1.6", 1));
        jdbc.update("""
                INSERT INTO component
                    (id, sbom_id, bom_ref, group_name, name, version, purl, component_type,
                     is_root, dependency_scope)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                componentId, sbomId, component.bomRef(), component.group(), component.name(),
                component.version(), component.purl(), component.type(), component.root(),
                component.scope().name());

        new MavenCoordinateBackfill(sboms).backfill();

        assertThat(jdbc.queryForMap(
                        "SELECT maven_type, maven_classifier FROM component WHERE id = ?",
                        componentId))
                .containsEntry("MAVEN_TYPE", "test-jar")
                .containsEntry("MAVEN_CLASSIFIER", "tests");
        assertThat(sboms.backfillMavenCoordinates()).isZero();
    }

    @Test
    void componentSortingUsesClassifierAfterGroupArtifactAndType() {
        UUID sbomId = store(classifierFixture());

        List<String> ascending = findings.rowsForSbom(sbomId, query(null, false, false, true)).stream()
                .filter(row -> row.name().equals("jackson-databind"))
                .map(FindingRow::coordinates)
                .toList();
        List<String> descending = findings.rowsForSbom(sbomId, query(null, false, false, false)).stream()
                .filter(row -> row.name().equals("jackson-databind"))
                .map(FindingRow::coordinates)
                .toList();

        assertThat(ascending).containsExactly(
                "tools.jackson.core:jackson-databind",
                "tools.jackson.core:jackson-databind:sources");
        assertThat(descending).containsExactly(
                "tools.jackson.core:jackson-databind:sources",
                "tools.jackson.core:jackson-databind");
    }

    @Test
    void filtersClassifierLiterallyAsARegexAndByNegation() {
        UUID sbomId = store(classifierFixture());

        assertThat(findings.rowsForSbom(sbomId, query("sources", false, false, true)))
                .extracting(FindingRow::coordinates)
                .containsExactly("tools.jackson.core:jackson-databind:sources");
        assertThat(findings.rowsForSbom(sbomId, query("^sources$", true, false, true)))
                .extracting(FindingRow::coordinates)
                .containsExactly("tools.jackson.core:jackson-databind:sources");
        assertThat(findings.rowsForSbom(sbomId, query("sources", false, true, true)))
                .extracting(FindingRow::coordinates)
                .doesNotContain("tools.jackson.core:jackson-databind:sources");
    }
}
