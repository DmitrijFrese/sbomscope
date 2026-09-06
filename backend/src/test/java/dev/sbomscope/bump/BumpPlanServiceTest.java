package dev.sbomscope.bump;

import java.io.IOException;
import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import dev.sbomscope.probe.DependencyResolver;
import dev.sbomscope.scanner.FindingRow;
import dev.sbomscope.scanner.ScanService;
import dev.sbomscope.scanner.UpgradeAdvice;
import dev.sbomscope.scanner.UpgradeAdviceService;
import dev.sbomscope.sbom.ComponentGraph;
import dev.sbomscope.sbom.DependencyGraphService;
import dev.sbomscope.sbom.DependencyScope;
import dev.sbomscope.sbom.SbomService;
import dev.sbomscope.sbom.StoredComponent;
import dev.sbomscope.sbom.StoredSbom;
import dev.sbomscope.settings.MavenToolSettings;
import dev.sbomscope.settings.SettingsService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class BumpPlanServiceTest {

    @Test
    void classifiesAllFiveKindsAndBuildsTargets(@TempDir Path temp) throws IOException {
        Path workspace = copyWorkspace(temp);
        UUID id = UUID.randomUUID();
        StoredSbom stored = new StoredSbom(id, "fixture.cdx.json", Instant.now(),
                workspace.toString(), "1.6", 6);
        List<StoredComponent> components = List.of(
                component("direct", "1.2.3"),
                component("managed", "3.0.0"),
                component("property-one", "2.0.0"),
                component("property-two", "2.0.0"),
                component("bom-provided", "5.0.0"),
                component("undeclared", "6.0.0"));

        SbomService sboms = mock(SbomService.class);
        ScanService scans = mock(ScanService.class);
        DependencyGraphService graphs = mock(DependencyGraphService.class);
        UpgradeAdviceService advice = mock(UpgradeAdviceService.class);
        DependencyResolver resolver = mock(DependencyResolver.class);
        SettingsService settings = mock(SettingsService.class);
        when(sboms.findComponents(id)).thenReturn(components);
        when(scans.vulnerablePurls(id)).thenReturn(components.stream()
                .map(StoredComponent::purl).collect(java.util.stream.Collectors.toSet()));
        when(scans.rowsForComponent(any(), any())).thenAnswer(invocation ->
                List.of(finding(invocation.getArgument(1))));
        when(scans.evaluatorFor(any())).thenReturn(UpgradeAdviceService.TargetEvaluator.unavailable());
        when(graphs.graphFor(any(), any(), any())).thenReturn(mock(ComponentGraph.class));
        when(advice.adviseFor(any(), any(), any(), any())).thenReturn(new UpgradeAdvice(
                "1", DependencyScope.DIRECT, "4.0.0", List.of(), List.of(), List.of(),
                null, false, List.of()));
        when(settings.mavenSettings()).thenReturn(new MavenToolSettings(true, "mvn", 20, 8,
                null, null, null));
        when(resolver.knownVersions(any(), any())).thenReturn(List.of("9.0.0", "10.0.0"));

        BumpPlan plan = new BumpPlanService(sboms, scans, graphs, advice, resolver, settings,
                temp.resolve("probe-repo").toString(), new PomWorkspace()).plan(stored);

        assertThat(plan.rows()).extracting(row -> row.site().kind()).contains(
                SiteKind.DIRECT, SiteKind.MANAGED, SiteKind.PROPERTY,
                SiteKind.IMPORTED_BOM, SiteKind.UNDECLARED);
        assertThat(plan.rows().stream().filter(row -> "direct".equals(row.site().artifactId())))
                .extracting(row -> row.site().kind()).containsExactlyInAnyOrder(
                        SiteKind.DIRECT, SiteKind.MANAGED);
        assertThat(plan.rows()).allSatisfy(row -> {
            assertThat(row.minimalTarget()).isEqualTo("4.0.0");
            assertThat(row.latestTarget()).isEqualTo("10.0.0");
            assertThat(row.advisories()).singleElement().satisfies(advisory -> {
                assertThat(advisory.osvId()).isEqualTo("OSV-1");
                assertThat(advisory.osvUrl()).isEqualTo("https://osv.dev/vulnerability/OSV-1");
            });
            assertThat(row.highestSeverity()).isEqualTo("High");
        });
        BumpRow direct = plan.rows().stream()
                .filter(row -> "direct".equals(row.site().artifactId())).findFirst().orElseThrow();
        assertThat(direct.artifactUrl())
                .isEqualTo("https://central.sonatype.com/artifact/fixture/direct");
        assertThat(direct.currentVersionUrl())
                .isEqualTo("https://central.sonatype.com/artifact/fixture/direct/1.2.3");
        assertThat(direct.minimalTargetUrl())
                .isEqualTo("https://central.sonatype.com/artifact/fixture/direct/4.0.0");
        BumpRow propertyOne = plan.rows().stream()
                .filter(row -> "property-one".equals(row.site().artifactId())).findFirst().orElseThrow();
        BumpRow propertyTwo = plan.rows().stream()
                .filter(row -> "property-two".equals(row.site().artifactId())).findFirst().orElseThrow();
        assertThat(propertyOne.site().sharedWith()).containsExactly("fixture:property-two");
        assertThat(propertyTwo.site().sharedWith()).containsExactly("fixture:property-one");
        assertThat(propertyOne.site().id()).isEqualTo(propertyTwo.site().id());
        assertThat(plan.rows().stream().filter(row -> row.site().kind() == SiteKind.IMPORTED_BOM)
                .findFirst().orElseThrow().site().versionRange()).isNull();
        assertThat(plan.rows().stream().filter(row -> row.site().kind() == SiteKind.UNDECLARED)
                .findFirst().orElseThrow().site().insertionPoint()).isNotNull();
    }

    @Test
    void reportsAnOutsideParentAsReadOnly(@TempDir Path temp) throws IOException {
        Path workspace = Files.createDirectories(temp.resolve("workspace"));
        Files.writeString(temp.resolve("parent.pom.txt"), """
                <project><modelVersion>4.0.0</modelVersion><artifactId>parent</artifactId></project>
                """);
        Files.writeString(workspace.resolve("pom.xml"), """
                <project><modelVersion>4.0.0</modelVersion>
                  <parent><groupId>x</groupId><artifactId>parent</artifactId><version>1</version>
                    <relativePath>../parent.pom.txt</relativePath></parent>
                  <artifactId>child</artifactId>
                </project>
                """);

        PomWorkspace.WorkspaceScan scan = new PomWorkspace().discover(workspace);

        assertThat(scan.files()).hasSize(2);
        // Asserted on the filtered element rather than inside an anySatisfy: a conditional
        // assertion there passes whenever any *other* file fails the condition, so it would
        // hold just as well if the outside parent came back editable.
        assertThat(scan.files())
                .filteredOn(file -> file.path().endsWith("parent.pom.txt"))
                .singleElement()
                .satisfies(file -> assertThat(file.editable()).isFalse());
        assertThat(scan.files())
                .filteredOn(file -> file.path().equals("pom.xml"))
                .singleElement()
                .satisfies(file -> assertThat(file.editable()).isTrue());
        assertThat(scan.notes()).anyMatch(note -> note.contains("outside the workspace"));
    }

    private Path copyWorkspace(Path temp) throws IOException {
        Path root = Files.createDirectories(temp.resolve("workspace"));
        copy("root.pom.txt", root.resolve("pom.xml"));
        copy("module-a.pom.txt", Files.createDirectories(root.resolve("module-a")).resolve("pom.xml"));
        copy("module-b.pom.txt", Files.createDirectories(root.resolve("module-b")).resolve("pom.xml"));
        return root;
    }

    private void copy(String resource, Path target) throws IOException {
        try (var stream = getClass().getResourceAsStream("/bump/" + resource)) {
            Files.copy(stream, target);
        }
    }

    private StoredComponent component(String artifact, String version) {
        return new StoredComponent(UUID.randomUUID(), artifact, "fixture", artifact, version,
                "pkg:maven/fixture/" + artifact + "@" + version, "library", null, null,
                false, DependencyScope.DIRECT);
    }

    private FindingRow finding(String purl) {
        String artifact = purl.substring(purl.lastIndexOf('/') + 1, purl.indexOf('@'));
        return new FindingRow(purl, "fixture:" + artifact, "1", false, DependencyScope.DIRECT,
                "OSV-1", null, "finding", new BigDecimal("8.0"), "HIGH", null, null,
                "4.0.0", Instant.now());
    }
}
