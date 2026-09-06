package dev.sbomscope.bump;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
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

class NpmPlanTest {

    @Test
    void transitiveWithPackageLockProducesAnEditableUndeclaredRow(@TempDir Path temp)
            throws IOException {
        BumpPlan plan = plan(temp);
        DeclarationSite site = row(plan, "transitive").site();

        assertThat(site.kind()).isEqualTo(SiteKind.UNDECLARED);
        assertThat(site.ecosystem()).isEqualTo(Ecosystem.NPM);
        assertThat(site.versionRange()).isNull();
        assertThat(site.insertionPoint()).isNotNull();
        assertThat(site.file()).isEqualTo("package.json");
        assertThat(plan.lockfileNotes()).anySatisfy(note -> {
            assertThat(note).contains("Try npm update parent first")
                    .contains("cannot verify offline")
                    .contains("offered exact override")
                    .contains("parent's stated constraint")
                    .contains("requires exact version 7.18.1");
        });
    }

    @Test
    void installedParentRangeAdmittingFixProducesNoEditAndNpmInstallAdvice(@TempDir Path temp)
            throws IOException {
        BumpPlan plan = plan(temp, "npm-admits-fix.lock.txt");
        DeclarationSite site = row(plan, "transitive").site();

        assertThat(site.versionRange()).isNull();
        assertThat(site.insertionPoint()).isNull();
        assertThat(plan.lockfileNotes()).anySatisfy(note -> assertThat(note)
                .contains("already permits transitive@7.18.2")
                .contains("no manifest edit").contains("npm install"));
    }

    @Test
    void lockfileV1ProducesANonEditableDiagnosis(@TempDir Path temp) throws IOException {
        BumpPlan plan = plan(temp, "npm-v1.lock.txt");

        assertThat(row(plan, "transitive").site().insertionPoint()).isNull();
        assertThat(plan.lockfileNotes()).anySatisfy(note -> assertThat(note)
                .contains("Cannot determine an npm remedy")
                .contains("versions 2 and 3"));
    }

    @Test
    void authoredOverrideUsesTheExactFixWithoutARangeOperator(@TempDir Path temp)
            throws IOException {
        BumpPlan plan = plan(temp);
        BumpRow transitive = row(plan, "transitive");
        PomFile file = plan.files().stream().filter(value -> value.path().equals("package.json"))
                .findFirst().orElseThrow();

        PreviewFile preview = new PomPatcher().patch(file,
                List.of(new PomPatcher.PlannedEdit(transitive.site(), "7.18.2", true)));

        assertThat(preview.patched()).contains("\"transitive\": \"7.18.2\"")
                .doesNotContain("\"transitive\": \"^7.18.2\"");
    }

    @Test
    void transitiveWithYarnLockIsDiagnosedButNotEditable(@TempDir Path temp)
            throws IOException {
        BumpPlan plan = plan(temp, true, "yarn.lock", false);
        DeclarationSite site = row(plan, "transitive").site();

        assertThat(site.insertionPoint()).isNull();
        assertThat(plan.notes()).anyMatch(note -> note.contains("transitive")
                && note.contains("yarn.lock") && note.contains("parent"));
    }

    @Test
    void transitiveWithoutALockfileIsDiagnosedButNotEditable(@TempDir Path temp)
            throws IOException {
        BumpPlan plan = plan(temp, true, null, false);
        DeclarationSite site = row(plan, "transitive").site();

        assertThat(site.insertionPoint()).isNull();
        assertThat(plan.notes()).anyMatch(note -> note.contains("transitive")
                && note.contains("lockfile found: none") && note.contains("parent"));
    }

    @Test
    void unsupportedLiteralProducesANonEditableRowAndNote(@TempDir Path temp) throws IOException {
        BumpPlan plan = plan(temp);
        BumpRow row = row(plan, "unsupported");

        assertThat(row.site().versionRange()).isNull();
        assertThat(row.site().rangeAdmitsFix()).isFalse();
        assertThat(plan.notes()).anyMatch(note -> note.contains("unsupported")
                && note.contains("workspace:*"));
    }

    @Test
    void scopedPackageKeepsScopeAndNameSeparate(@TempDir Path temp) throws IOException {
        DeclarationSite site = row(plan(temp), "name").site();

        assertThat(site.groupId()).isEqualTo("@scope");
        assertThat(site.artifactId()).isEqualTo("name");
    }

    @Test
    void npmRowsUseNoMavenLatestTarget(@TempDir Path temp) throws IOException {
        assertThat(plan(temp).rows()).allSatisfy(row -> assertThat(row.latestTarget()).isNull());
    }

    @Test
    void rangeThatAlreadyAdmitsFixNeedsNoManifestEdit(@TempDir Path temp) throws IOException {
        DeclarationSite site = row(plan(temp), "lodash").site();

        assertThat(site.rangeAdmitsFix()).isTrue();
        assertThat(site.versionLiteral()).isEqualTo("^4.17.20");
    }

    @Test
    void lockfileNoteAppearsWhenItsManifestHasAnEditableBump(@TempDir Path temp)
            throws IOException {
        BumpPlan plan = plan(temp);

        assertThat(plan.lockfileNotes()).anySatisfy(note -> assertThat(note)
                .contains("package.json").contains("npm install"));
    }

    @Test
    void nestedManifestLockfileNoteNamesThatManifest(@TempDir Path temp) throws IOException {
        BumpPlan plan = plan(temp, true, false, true);

        assertThat(plan.lockfileNotes()).singleElement()
                .asString().contains("packages/child/package.json").contains("npm install");
    }

    @Test
    void discoversDependenciesInAWorkspaceManifest(@TempDir Path temp) throws IOException {
        BumpRow child = row(plan(temp), "child-only");

        assertThat(child.site().file()).isEqualTo("packages/child/package.json");
        assertThat(child.site().module()).isEqualTo("@fixture/child");
    }

    @Test
    void discoversANestedManifestWithoutARootManifest(@TempDir Path temp) throws IOException {
        BumpRow child = row(plan(temp, false, false, false), "child-only");

        assertThat(child.site().file()).isEqualTo("packages/child/package.json");
    }

    @Test
    void npmRowCarriesTheSharedContractFields(@TempDir Path temp) throws IOException {
        DeclarationSite site = row(plan(temp), "exact").site();

        assertThat(site.kind()).isEqualTo(SiteKind.NPM_DIRECT);
        assertThat(site.ecosystem()).isEqualTo(Ecosystem.NPM);
        assertThat(site.currentVersion()).isEqualTo("1.0.0");
        assertThat(site.versionLiteral()).isEqualTo("1.0.0");
    }

    @Test
    void previewPreservesTheNpmRangeOperator(@TempDir Path temp) throws IOException {
        BumpPlan plan = plan(temp);
        BumpRow scoped = row(plan, "name");
        PomFile file = plan.files().stream().filter(value -> value.path().equals("package.json"))
                .findFirst().orElseThrow();

        PreviewFile preview = new PomPatcher().patch(file,
                List.of(new PomPatcher.PlannedEdit(scoped.site(), "1.3.0", false)));

        assertThat(preview.patched()).contains("\"@scope/name\": \"~1.3.0\"");
    }

    @Test
    void workspaceOutsideTheRootIsReadOnlyAndReported(@TempDir Path temp) throws IOException {
        Path workspace = Files.createDirectories(temp.resolve("workspace"));
        Files.writeString(workspace.resolve("package.json"),
                "{\"name\":\"root\",\"workspaces\":[\"../outside\"]}");
        Path outside = Files.createDirectories(temp.resolve("outside"));
        Files.writeString(outside.resolve("package.json"), "{\"name\":\"outside\"}");

        NpmWorkspace.WorkspaceScan scan = new NpmWorkspace().discover(workspace);

        assertThat(scan.files()).filteredOn(file -> file.path().endsWith("outside/package.json"))
                .singleElement().satisfies(file -> assertThat(file.editable()).isFalse());
        assertThat(scan.notes()).anyMatch(note -> note.contains("outside the workspace"));
    }

    @Test
    void workspaceDiscoveryStopsBelowDepthTwelve(@TempDir Path temp) throws IOException {
        Path workspace = Files.createDirectories(temp.resolve("workspace"));
        Path directory = workspace;
        for (int depth = 1; depth <= 13; depth++) {
            directory = Files.createDirectories(directory.resolve("d" + depth));
            if (depth == 12 || depth == 13) {
                Files.writeString(directory.resolve("package.json"),
                        "{\"name\":\"depth-" + depth + "\"}");
            }
        }

        NpmWorkspace.WorkspaceScan scan = new NpmWorkspace().discover(workspace);

        assertThat(scan.packages()).extracting(value -> value.scan().name())
                .contains("depth-12").doesNotContain("depth-13");
    }

    @Test
    void skipsPackageJsonUnderNodeModulesAtAnyDepth(@TempDir Path temp) throws IOException {
        Path workspace = Files.createDirectories(temp.resolve("workspace"));
        copy("npm-child.package.txt", Files.createDirectories(workspace.resolve("frontend"))
                .resolve("package.json"));
        copy("npm-root.package.txt", Files.createDirectories(workspace
                .resolve("packages/child/node_modules/example")).resolve("package.json"));

        NpmWorkspace.WorkspaceScan scan = new NpmWorkspace().discover(workspace);

        assertThat(scan.packages()).extracting(value -> value.file().path())
                .containsExactly("frontend/package.json");
    }

    @Test
    void discoversRootAndNestedManifests(@TempDir Path temp) throws IOException {
        Path workspace = Files.createDirectories(temp.resolve("workspace"));
        copy("npm-root.package.txt", workspace.resolve("package.json"));
        copy("npm-child.package.txt", Files.createDirectories(workspace.resolve("frontend"))
                .resolve("package.json"));

        NpmWorkspace.WorkspaceScan scan = new NpmWorkspace().discover(workspace);

        assertThat(scan.packages()).extracting(value -> value.file().path())
                .containsExactly("frontend/package.json", "package.json");
    }

    private BumpPlan plan(Path temp) throws IOException {
        return plan(temp, true, true, false);
    }

    private BumpPlan plan(Path temp, String rootLockResource) throws IOException {
        return plan(temp, true, rootLockResource, false);
    }

    private BumpPlan plan(Path temp, boolean rootManifest, boolean rootLockfile,
                          boolean childLockfile) throws IOException {
        return plan(temp, rootManifest, rootLockfile ? "npm-pinned.lock.txt" : null, childLockfile);
    }

    private BumpPlan plan(Path temp, boolean rootManifest, String rootLockfile,
                          boolean childLockfile) throws IOException {
        Path workspace = Files.createDirectories(temp.resolve("workspace"));
        if (rootManifest) {
            copy("npm-root.package.txt", workspace.resolve("package.json"));
        }
        if (rootLockfile != null) {
            if (rootLockfile.endsWith(".lock.txt")) {
                copy(rootLockfile, workspace.resolve("package-lock.json"));
            } else {
                Files.writeString(workspace.resolve(rootLockfile), "{}");
            }
        }
        Path child = Files.createDirectories(workspace.resolve("packages/child"));
        copy("npm-child.package.txt", child.resolve("package.json"));
        if (childLockfile) {
            Files.writeString(child.resolve("package-lock.json"), "{}");
        }

        List<StoredComponent> components = List.of(
                component("", "lodash", "4.17.20"),
                component("@scope", "name", "1.2.3"),
                component("", "unsupported", "1.0.0"),
                component("", "exact", "1.0.0"),
                component("", "dev-only", "2.0.0"),
                component("", "child-only", "3.0.0"),
                component("", "transitive", "7.18.1"));
        Map<String, String> targets = Map.of(
                "lodash", "4.17.21",
                "name", "1.3.0",
                "unsupported", "1.0.1",
                "exact", "1.0.1",
                "dev-only", "2.0.1",
                "child-only", "3.1.0",
                "transitive", "7.18.2");
        UUID id = UUID.randomUUID();
        StoredSbom stored = new StoredSbom(id, "fixture.cdx.json", Instant.now(),
                workspace.toString(), "1.6", components.size());

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
        when(advice.adviseFor(any(), any(), any(), any())).thenAnswer(invocation -> {
            StoredComponent component = invocation.getArgument(0);
            List<String> declaredBy = "transitive".equals(component.name())
                    ? List.of("parent") : List.of();
            return new UpgradeAdvice(component.version(), DependencyScope.DIRECT,
                    targets.get(component.name()), List.of(), declaredBy, List.of(), null,
                    false, List.of());
        });
        when(settings.mavenSettings()).thenReturn(new MavenToolSettings(false, null, 20, 8,
                null, null, null));

        return new BumpPlanService(sboms, scans, graphs, advice, resolver, settings,
                temp.resolve("probe-repo").toString(), new PomWorkspace(), new NpmWorkspace())
                .plan(stored);
    }

    private BumpRow row(BumpPlan plan, String artifact) {
        return plan.rows().stream().filter(value -> artifact.equals(value.site().artifactId()))
                .findFirst().orElseThrow();
    }

    private StoredComponent component(String group, String name, String version) {
        String packageName = group.isBlank() ? name : group + "/" + name;
        String purlName = packageName.replace("@", "%40");
        return new StoredComponent(UUID.randomUUID(), packageName, group, name, version,
                "pkg:npm/" + purlName + "@" + version, "library", false,
                DependencyScope.DIRECT);
    }

    private FindingRow finding(String purl) {
        return new FindingRow(purl, "fixture", "1", false, DependencyScope.DIRECT,
                "OSV-1", null, "finding", new BigDecimal("8.0"), "HIGH", null, null,
                "9.0.0", Instant.now());
    }

    private void copy(String resource, Path target) throws IOException {
        try (var stream = getClass().getResourceAsStream("/bump/" + resource)) {
            Files.copy(stream, target);
        }
    }
}
