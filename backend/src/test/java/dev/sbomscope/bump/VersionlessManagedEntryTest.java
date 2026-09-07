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

/**
 * A {@code <dependencyManagement>} entry that carries no {@code <version>}.
 *
 * <p>Perfectly ordinary Maven, and common in exactly the projects this tool is aimed at: when a BOM
 * already supplies the version, a management entry is how a project adds an {@code <exclusion>},
 * pins a {@code <scope>}, or sets a {@code <type>} without restating the version. The scanner
 * records such an entry with a null {@code versionRange}, because it only captures a range when it
 * sees a {@code <version>} element.
 *
 * <p>Reported from live use against a workspace whose BOM carries supplier artifacts, as an NPE on
 * {@code TextRange.start()}.
 */
class VersionlessManagedEntryTest {

    @Test
    void aManagedEntryWithNoVersionDoesNotBreakThePlan(@TempDir Path temp) throws IOException {
        Path workspace = Files.createDirectories(temp.resolve("workspace"));
        Files.writeString(workspace.resolve("pom.xml"), """
                <?xml version="1.0" encoding="UTF-8"?>
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>fixture</groupId>
                  <artifactId>root</artifactId>
                  <version>1.0.0</version>
                  <packaging>pom</packaging>
                  <dependencyManagement>
                    <dependencies>
                      <dependency>
                        <groupId>com.acme</groupId>
                        <artifactId>platform-bom</artifactId>
                        <version>2.0.0</version>
                        <type>pom</type>
                        <scope>import</scope>
                      </dependency>
                      <!-- The version comes from the BOM above; this entry only drops a
                           transitive. Legal Maven, and it carries no version range. -->
                      <dependency>
                        <groupId>fixture</groupId>
                        <artifactId>managed-by-bom</artifactId>
                        <exclusions>
                          <exclusion>
                            <groupId>commons-logging</groupId>
                            <artifactId>commons-logging</artifactId>
                          </exclusion>
                        </exclusions>
                      </dependency>
                    </dependencies>
                  </dependencyManagement>
                  <dependencies>
                    <dependency>
                      <groupId>fixture</groupId>
                      <artifactId>managed-by-bom</artifactId>
                    </dependency>
                  </dependencies>
                </project>
                """);

        UUID id = UUID.randomUUID();
        StoredSbom stored = new StoredSbom(id, "fixture.cdx.json", Instant.now(),
                workspace.toString(), "1.6", 1);
        List<StoredComponent> components = List.of(component("managed-by-bom", "1.0.0"));

        SbomService sboms = mock(SbomService.class);
        ScanService scans = mock(ScanService.class);
        DependencyGraphService graphs = mock(DependencyGraphService.class);
        UpgradeAdviceService advice = mock(UpgradeAdviceService.class);
        DependencyResolver resolver = mock(DependencyResolver.class);
        SettingsService settings = mock(SettingsService.class);
        when(sboms.findById(id)).thenReturn(java.util.Optional.of(stored));
        when(sboms.findComponents(id)).thenReturn(components);
        when(scans.vulnerablePurls(id)).thenReturn(Set.of(components.get(0).purl()));
        when(scans.rowsForComponent(any(), any())).thenAnswer(invocation ->
                List.of(finding(invocation.getArgument(1))));
        when(scans.evaluatorFor(any())).thenReturn(UpgradeAdviceService.TargetEvaluator.unavailable());
        when(graphs.graphFor(any(), any(), any())).thenReturn(mock(ComponentGraph.class));
        when(advice.adviseFor(any(), any(), any(), any())).thenReturn(new UpgradeAdvice(
                "1", DependencyScope.DIRECT, "2.0.0", List.of(), List.of(), List.of(),
                null, false, List.of()));
        when(settings.mavenSettings()).thenReturn(new MavenToolSettings(false, null, 20, 8,
                null, null, null));
        when(resolver.knownVersions(any(), any())).thenReturn(List.of());

        BumpPlan plan = new BumpPlanService(sboms, scans, graphs, advice, resolver, settings,
                temp.resolve("probe-repo").toString(), new PomWorkspace()).plan(stored);

        // The row must exist and must be a structural remedy: there is no version written
        // anywhere in this pom to replace, so the fix is an entry that is not there yet.
        assertThat(plan.rows()).isNotEmpty();
        assertThat(plan.rows()).allSatisfy(row ->
                assertThat(row.site().versionRange() != null || row.site().insertionPoint() != null)
                        .as("a site must say where to write, by range or by insertion point")
                        .isTrue());
        // The specific remedy, not just the absence of a crash: the version lives in the BOM, so
        // the fix is a new managed entry, and the row must not point at the versionless one as
        // though a version could be written over it.
        assertThat(plan.rows()).extracting(row -> row.site().kind())
                .containsOnly(SiteKind.IMPORTED_BOM);
        assertThat(plan.rows()).allSatisfy(row ->
                assertThat(row.site().insertionPoint()).isNotNull());
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
                "2.0.0", Instant.now());
    }
}
