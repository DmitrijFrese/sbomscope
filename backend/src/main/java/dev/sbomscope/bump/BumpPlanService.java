package dev.sbomscope.bump;

import java.nio.file.Path;
import java.nio.file.Files;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import dev.sbomscope.bump.PomScanner.PomScan;
import dev.sbomscope.bump.PomScanner.PropertyDefinition;
import dev.sbomscope.bump.PomScanner.RawDependency;
import dev.sbomscope.bump.PomWorkspace.ScannedPom;
import dev.sbomscope.bump.NpmWorkspace.ScannedPackage;
import dev.sbomscope.bump.PackageJsonScanner.RawNpmDependency;
import dev.sbomscope.export.AdvisoryLinks;
import dev.sbomscope.export.RegistryLinks;
import dev.sbomscope.probe.DependencyResolver;
import dev.sbomscope.probe.MavenArtifact;
import dev.sbomscope.probe.ProbeContext;
import dev.sbomscope.scanner.FindingQuery.SeverityBand;
import dev.sbomscope.scanner.FindingRow;
import dev.sbomscope.scanner.ScanService;
import dev.sbomscope.scanner.UpgradeAdviceService;
import dev.sbomscope.scanner.UpgradeAdvice;
import dev.sbomscope.scanner.VersionOrder;
import dev.sbomscope.sbom.DependencyGraphService;
import dev.sbomscope.sbom.SbomService;
import dev.sbomscope.sbom.StoredComponent;
import dev.sbomscope.sbom.StoredSbom;
import dev.sbomscope.settings.MavenToolSettings;
import dev.sbomscope.settings.SettingsService;

/** Joins on-disk Maven and npm declarations to vulnerable components already held locally. */
@Service
public class BumpPlanService {

    private static final Duration METADATA_READ_TIMEOUT = Duration.ofSeconds(60);

    private final SbomService sboms;
    private final ScanService scans;
    private final DependencyGraphService graphs;
    private final UpgradeAdviceService advice;
    private final DependencyResolver resolver;
    private final SettingsService settings;
    private final String probeRepository;
    private final PomWorkspace workspaces;
    private final NpmWorkspace npmWorkspaces;
    private final NpmLockfileReader npmLockfiles = new NpmLockfileReader();

    @Autowired
    BumpPlanService(SbomService sboms, ScanService scans, DependencyGraphService graphs,
                    UpgradeAdviceService advice, DependencyResolver resolver,
                    SettingsService settings,
                    @Value("${sbomscope.probe-repository}") String probeRepository) {
        this(sboms, scans, graphs, advice, resolver, settings, probeRepository,
                new PomWorkspace(), new NpmWorkspace());
    }

    BumpPlanService(SbomService sboms, ScanService scans, DependencyGraphService graphs,
                    UpgradeAdviceService advice, DependencyResolver resolver,
                    SettingsService settings, String probeRepository, PomWorkspace workspaces) {
        this(sboms, scans, graphs, advice, resolver, settings, probeRepository, workspaces,
                new NpmWorkspace());
    }

    BumpPlanService(SbomService sboms, ScanService scans, DependencyGraphService graphs,
                    UpgradeAdviceService advice, DependencyResolver resolver,
                    SettingsService settings, String probeRepository, PomWorkspace workspaces,
                    NpmWorkspace npmWorkspaces) {
        this.sboms = sboms;
        this.scans = scans;
        this.graphs = graphs;
        this.advice = advice;
        this.resolver = resolver;
        this.settings = settings;
        this.probeRepository = probeRepository;
        this.workspaces = workspaces;
        this.npmWorkspaces = npmWorkspaces;
    }

    public BumpPlan plan(StoredSbom sbom) {
        Path root = Path.of(sbom.workspacePath()).toAbsolutePath().normalize();
        PomWorkspace.WorkspaceScan workspace = java.nio.file.Files.isRegularFile(root.resolve("pom.xml"))
                ? workspaces.discover(root) : null;
        NpmWorkspace.WorkspaceScan npmWorkspace = npmWorkspaces.discover(root);
        if (workspace == null && npmWorkspace.packages().isEmpty()) {
            throw new IllegalArgumentException("The workspace holds no pom.xml or package.json");
        }
        Set<String> vulnerablePurls = scans.vulnerablePurls(sbom.id());
        List<PendingRow> pending = new ArrayList<>();
        List<String> notes = new ArrayList<>();
        List<String> lockfileNotes = new ArrayList<>();
        List<PomFile> files = new ArrayList<>();
        List<ScannedPom> poms = workspace == null ? List.of() : workspace.poms();
        List<ScannedPackage> packages = npmWorkspace.packages();
        if (workspace != null) {
            notes.addAll(workspace.notes());
            files.addAll(workspace.files());
        }
        notes.addAll(npmWorkspace.notes());
        files.addAll(npmWorkspace.files());
        Map<String, Set<String>> propertyUsers = propertyUsers(poms);
        MavenToolSettings maven = settings.mavenSettings();
        ProbeContext probe = maven.hasExecutable()
                ? new ProbeContext(maven.executablePath(), probeRepository, null,
                        METADATA_READ_TIMEOUT, maven.profiles(), maven.dependencyTreeGoal())
                : null;

        for (StoredComponent component : sboms.findComponents(sbom.id())) {
            if (component.purl() == null || !vulnerablePurls.contains(component.purl())) {
                continue;
            }
            boolean mavenComponent = component.purl().startsWith("pkg:maven/");
            boolean npmComponent = component.purl().startsWith("pkg:npm/");
            if (!mavenComponent && !npmComponent || mavenComponent && workspace == null
                    || npmComponent && packages.isEmpty()) {
                continue;
            }
            List<FindingRow> findings = scans.rowsForComponent(sbom.id(), component.purl());
            UpgradeAdvice upgradeAdvice = advice.adviseFor(component, findings,
                    graphs.graphFor(sbom.id(), component.purl(), vulnerablePurls),
                    scans.evaluatorFor(component));
            String minimal = upgradeAdvice.pinTarget();
            String latest = mavenComponent ? latest(component, probe) : null;
            List<BumpAdvisory> advisories = findings.stream().filter(FindingRow::hasFinding)
                    .filter(row -> row.osvId() != null)
                    .map(row -> new BumpAdvisory(row.osvId(), row.cveId(),
                            AdvisoryLinks.osvUrl(row.osvId()), AdvisoryLinks.cveUrl(row.cveId())))
                    .distinct().sorted(Comparator.comparing(BumpAdvisory::osvId)).toList();
            String severity = highestSeverity(findings);
            RegistryLinks.Links currentLinks = RegistryLinks.forPurl(component.purl());
            String minimalUrl = versionUrl(component.purl(), minimal);
            String latestUrl = versionUrl(component.purl(), latest);

            List<SiteCandidate> sites = mavenComponent
                    ? sitesFor(component, poms, propertyUsers)
                    : npmSitesFor(component, packages, minimal, upgradeAdvice.declaredBy(), notes,
                            lockfileNotes);
            for (SiteCandidate site : sites) {
                pending.add(new PendingRow(site, minimal, latest, advisories, severity,
                        currentLinks.artifactUrl(), currentLinks.versionUrl(), minimalUrl, latestUrl));
            }
        }

        packages.stream().filter(ScannedPackage::hasLockfile)
                .filter(manifest -> pending.stream().anyMatch(row -> npmEditIn(row, manifest)))
                // "Stale" undersold this and the maintainer hit the consequence: `npm ci` refuses
                // outright when the manifest and the lock disagree, so a project whose build uses
                // it — as this one's does — stops building until `npm install` has run. Saying so
                // here turns a confusing build failure ten minutes later into an expected step.
                .map(manifest -> manifest.file().path()
                        + ": run npm install afterwards. Until you do, package-lock.json disagrees"
                        + " with this manifest and npm ci refuses, so any build using it will fail.")
                .forEach(lockfileNotes::add);
        return new BumpPlan(sbom.id(), root.toString(), List.copyOf(files),
                assignIds(pending), List.copyOf(notes), List.copyOf(lockfileNotes));
    }

    private List<SiteCandidate> npmSitesFor(StoredComponent component,
                                            List<ScannedPackage> packages, String minimal,
                                            List<String> declaredBy,
                                            List<String> notes, List<String> lockfileNotes) {
        List<SiteCandidate> sites = new ArrayList<>();
        String packageName = npmPackageName(component);
        for (ScannedPackage manifest : packages) {
            for (RawNpmDependency dependency : manifest.scan().dependencies()) {
                if (!dependency.name().equals(packageName)) {
                    continue;
                }
                boolean supported = NpmRange.isSupported(dependency.versionLiteral());
                boolean admits = minimal != null
                        && NpmRange.admits(dependency.versionLiteral(), minimal);
                String[] coordinate = npmCoordinate(dependency.name());
                DeclarationSite site = new DeclarationSite("", manifest.file().path(),
                        npmModule(manifest), SiteKind.NPM_DIRECT, coordinate[0], coordinate[1],
                        "", "", component.version(), null, List.of(), List.of(),
                        supported ? dependency.literalRange() : null, null,
                        Ecosystem.NPM, dependency.versionLiteral(), admits);
                int position = dependency.literalRange().start();
                sites.add(new SiteCandidate(site, position, keyFor(site, position)));
                if (!supported) {
                    notes.add("Cannot safely edit npm dependency " + dependency.name()
                            + " with unsupported range '" + dependency.versionLiteral()
                            + "' in " + manifest.file().path());
                }
            }
        }
        if (sites.isEmpty()) {
            sites.add(undeclaredNpmSite(component, packages, minimal, declaredBy, notes,
                    lockfileNotes));
        }
        return sites;
    }

    private SiteCandidate undeclaredNpmSite(StoredComponent component,
                                            List<ScannedPackage> packages,
                                            String minimal, List<String> declaredBy,
                                            List<String> notes, List<String> lockfileNotes) {
        Set<String> parentNames = declaredBy.stream().map(this::npmNameFromCoordinate)
                .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));
        List<ScannedPackage> hosts = packages.stream().filter(manifest -> manifest.scan().dependencies()
                .stream().anyMatch(dependency -> parentNames.contains(dependency.name()))).toList();
        boolean fallback = hosts.size() != 1;
        ScannedPackage manifest = fallback ? rootPackage(packages) : hosts.getFirst();
        List<String> lockfiles = lockfilesBeside(manifest);
        boolean npm = lockfiles.contains("package-lock.json");
        String[] coordinate = npmCoordinate(npmPackageName(component));
        TextRange insertion = npm ? manifest.scan().overridesInsertionPoint() : null;
        if (npm) {
            NpmLockfileReader.Result lock = npmLockfiles.requirements(
                    manifest.absolutePath().resolveSibling("package-lock.json"),
                    List.copyOf(parentNames), npmPackageName(component));
            if (!lock.recognized()) {
                insertion = null;
                lockfileNotes.add("Cannot determine an npm remedy for " + npmPackageName(component)
                        + " in " + manifest.file().path() + ": " + lock.problem() + ".");
            } else if (minimal != null && lock.requirements().values().stream()
                    .allMatch(requirement -> NpmRange.admits(requirement, minimal))) {
                insertion = null;
                lockfileNotes.add(manifest.file().path() + ": the installed parent constraint"
                        + (lock.requirements().size() == 1 ? " already permits " : "s already permit ")
                        + npmPackageName(component) + "@" + minimal
                        + "; no manifest edit is needed. Run npm install to refresh the lockfile.");
            } else {
                addOverrideAdvice(component, minimal, manifest, lock.requirements(), lockfileNotes);
            }
        }
        DeclarationSite site = new DeclarationSite("", manifest.file().path(), npmModule(manifest),
                SiteKind.UNDECLARED, coordinate[0], coordinate[1], "", "", component.version(),
                null, List.of(), List.of(), null, insertion, Ecosystem.NPM, component.version(), false);

        String parents = declaredBy.isEmpty() ? "none" : String.join(", ", declaredBy);
        String found = lockfiles.isEmpty() ? "none" : String.join(", ", lockfiles);
        if (!npm) {
            notes.add("Cannot add npm override for " + npmPackageName(component) + " in "
                    + manifest.file().path() + ": lockfile found: " + found
                    + "; declared dependency: " + parents);
        }
        if (fallback) {
            notes.add("Placed " + npmPackageName(component) + " at root-most manifest "
                    + manifest.file().path() + " because its declared dependency was "
                    + (declaredBy.isEmpty() ? "not available" : "ambiguous: " + parents));
        }
        int position = insertion == null ? Integer.MAX_VALUE : insertion.start();
        return new SiteCandidate(site, position, keyFor(site, position));
    }

    private void addOverrideAdvice(StoredComponent component, String minimal,
                                   ScannedPackage manifest, Map<String, String> requirements,
                                   List<String> lockfileNotes) {
        String child = npmPackageName(component);
        List<String> updateFirst = manifest.scan().dependencies().stream()
                .filter(dependency -> requirements.containsKey(dependency.name()))
                .filter(dependency -> permitsNewerParent(dependency.versionLiteral()))
                .map(RawNpmDependency::name).distinct().toList();
        StringBuilder note = new StringBuilder(manifest.file().path()).append(": ");
        if (!updateFirst.isEmpty()) {
            note.append("Try npm update ").append(String.join(" ", updateFirst))
                    .append(" first because the manifest permits a newer parent; SBOMscope cannot "
                            + "verify offline whether a newer parent carries a fixed ").append(child)
                    .append(". If it does not, ");
        }
        note.append("the offered exact override ").append(child).append("@").append(minimal)
                .append(" overrides ");
        note.append(requirements.entrySet().stream()
                .map(entry -> entry.getValue().equals(component.version())
                        ? entry.getKey() + "'s stated constraint, which requires exact version "
                                + entry.getValue()
                        : entry.getKey() + "'s stated constraint '" + entry.getValue() + "'")
                .collect(java.util.stream.Collectors.joining(" and "))).append('.');
        lockfileNotes.add(note.toString());
    }

    private boolean permitsNewerParent(String literal) {
        return literal != null && (literal.startsWith("^") || literal.startsWith("~")
                || literal.startsWith(">="));
    }

    private String versionUrl(String purl, String version) {
        if (purl == null || version == null) {
            return null;
        }
        int query = purl.indexOf('?');
        int end = query < 0 ? purl.length() : query;
        int at = purl.lastIndexOf('@', end - 1);
        if (at < 0) {
            return null;
        }
        String versioned = purl.substring(0, at + 1) + version + purl.substring(end);
        return RegistryLinks.forPurl(versioned).versionUrl();
    }

    private ScannedPackage rootPackage(List<ScannedPackage> packages) {
        return packages.stream().min(Comparator
                .comparing((ScannedPackage manifest) -> !"package.json".equals(manifest.file().path()))
                .thenComparing(manifest -> !manifest.contained())
                .thenComparingInt(manifest -> manifest.file().path().split("/", -1).length)
                .thenComparing(manifest -> manifest.file().path())).orElseThrow();
    }

    private List<String> lockfilesBeside(ScannedPackage manifest) {
        return List.of("package-lock.json", "yarn.lock", "pnpm-lock.yaml").stream()
                .filter(name -> Files.isRegularFile(manifest.absolutePath().resolveSibling(name)))
                .toList();
    }

    private String npmNameFromCoordinate(String coordinate) {
        if (coordinate != null && coordinate.startsWith("@")) {
            int separator = coordinate.indexOf(':');
            if (separator > 1) {
                return coordinate.substring(0, separator) + "/" + coordinate.substring(separator + 1);
            }
        }
        return coordinate;
    }

    private boolean npmEditIn(PendingRow row, ScannedPackage manifest) {
        DeclarationSite site = row.site().site();
        return site.ecosystem() == Ecosystem.NPM && site.file().equals(manifest.file().path())
                && row.minimal() != null
                && (site.versionRange() != null || site.insertionPoint() != null)
                && !site.rangeAdmitsFix();
    }

    private String npmPackageName(StoredComponent component) {
        return component.group() == null || component.group().isBlank()
                ? component.name() : component.group() + "/" + component.name();
    }

    private String[] npmCoordinate(String packageName) {
        if (packageName.startsWith("@") && packageName.indexOf('/') > 1) {
            int slash = packageName.indexOf('/');
            return new String[] {packageName.substring(0, slash), packageName.substring(slash + 1)};
        }
        return new String[] {"", packageName};
    }

    private String npmModule(ScannedPackage manifest) {
        return "package.json".equals(manifest.file().path()) ? "" : manifest.scan().name();
    }

    private List<SiteCandidate> sitesFor(StoredComponent component, List<ScannedPom> poms,
                                         Map<String, Set<String>> propertyUsers) {
        List<SiteCandidate> sites = new ArrayList<>();
        List<DependencyRef> declarations = dependenciesMatching(component, poms, false);
        List<DependencyRef> allManaged = dependenciesMatching(component, poms, true);
        List<DependencyRef> managed = declarations.isEmpty() ? allManaged : allManaged.stream()
                .filter(entry -> declarations.stream()
                        .anyMatch(declaration -> visibleFrom(entry.pom(), declaration.pom(), poms)))
                .toList();

        if (!declarations.isEmpty()) {
            for (DependencyRef declaration : declarations) {
                RawDependency raw = declaration.raw();
                if (raw.versionLiteral() != null) {
                    sites.add(replacementSite(component, declaration, SiteKind.DIRECT,
                            propertyUsers, poms));
                } else if (!managed.isEmpty()) {
                    for (DependencyRef entry : managed) {
                        addOnce(sites, replacementSite(component, entry, SiteKind.MANAGED,
                                propertyUsers, poms));
                    }
                } else if (hasImportedBom(declaration.pom(), poms)) {
                    sites.add(structuralSite(component, declaration.pom(), SiteKind.IMPORTED_BOM));
                } else {
                    sites.add(structuralSite(component, declaration.pom(), SiteKind.UNDECLARED));
                }
            }
            // A literal declaration and a management entry are two distinct places the reader
            // may need to reconcile. A versionless declaration is not: its manager is the one
            // place the version is actually written.
            if (declarations.stream().anyMatch(ref -> ref.raw().versionLiteral() != null)) {
                for (DependencyRef entry : managed) {
                    addOnce(sites, replacementSite(component, entry, SiteKind.MANAGED,
                            propertyUsers, poms));
                }
            }
        } else if (!managed.isEmpty()) {
            for (DependencyRef entry : managed) {
                addOnce(sites, replacementSite(component, entry, SiteKind.MANAGED,
                        propertyUsers, poms));
            }
        } else {
            sites.add(structuralSite(component, rootPom(poms), SiteKind.UNDECLARED));
        }
        return sites;
    }

    private SiteCandidate replacementSite(StoredComponent component, DependencyRef ref,
                                          SiteKind literalKind,
                                          Map<String, Set<String>> propertyUsers,
                                          List<ScannedPom> poms) {
        RawDependency raw = ref.raw();
        String property = propertyName(raw.versionLiteral());
        PropertyRef definition = property == null ? null : property(ref.pom(), property, poms);
        SiteKind kind = definition == null ? literalKind : SiteKind.PROPERTY;
        ScannedPom file = definition == null ? ref.pom() : definition.pom();
        TextRange range = definition == null ? raw.versionRange() : definition.definition().valueRange();
        String current = definition == null ? raw.versionLiteral()
                : resolvedPropertyValue(definition.pom(), property, poms, new LinkedHashSet<>());
        List<String> shared = definition == null ? List.of()
                : propertyUsers.getOrDefault(property, Set.of()).stream()
                        .filter(coordinate -> !coordinate.equals(component.coordinates())).sorted().toList();
        DeclarationSite site = new DeclarationSite("", file.file().path(), moduleName(file), kind,
                component.group(), component.name(), typeOf(component), classifierOf(component),
                current, definition == null ? null : property, shared, raw.exclusions(), range, null,
                Ecosystem.MAVEN, current, false);
        return new SiteCandidate(site, range.start(), keyFor(site));
    }

    private SiteCandidate structuralSite(StoredComponent component, ScannedPom pom, SiteKind kind) {
        TextRange insertion = pom.scan().managementInsertionPoint();
        DeclarationSite site = new DeclarationSite("", pom.file().path(), moduleName(pom), kind,
                component.group(), component.name(), typeOf(component), classifierOf(component),
                component.version(), null, List.of(), List.of(), null, insertion,
                Ecosystem.MAVEN, component.version(), false);
        return new SiteCandidate(site, insertion.start(), keyFor(site));
    }

    private List<DependencyRef> dependenciesMatching(StoredComponent component,
                                                      List<ScannedPom> poms, boolean managed) {
        List<DependencyRef> matches = new ArrayList<>();
        for (ScannedPom pom : poms) {
            if (!pom.contained()) {
                continue;
            }
            List<RawDependency> candidates = managed ? pom.scan().managed() : pom.scan().dependencies();
            for (RawDependency raw : candidates) {
                if (!raw.bomImport() && sameArtifact(component, raw)) {
                    matches.add(new DependencyRef(pom, raw));
                }
            }
        }
        return matches;
    }

    private boolean sameArtifact(StoredComponent component, RawDependency raw) {
        return Objects.equals(component.group(), raw.groupId())
                && Objects.equals(component.name(), raw.artifactId())
                && Objects.equals(normalType(typeOf(component)), normalType(raw.type()))
                && Objects.equals(blankToNull(classifierOf(component)), blankToNull(raw.classifier()));
    }

    private String typeOf(StoredComponent component) {
        return component.mavenType() == null ? "jar" : component.mavenType();
    }

    private String classifierOf(StoredComponent component) {
        return component.mavenClassifier() == null ? "" : component.mavenClassifier();
    }

    private String normalType(String type) {
        return type == null || type.isBlank() ? "jar" : type;
    }

    private String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    private boolean hasImportedBom(ScannedPom declaring, List<ScannedPom> poms) {
        return poms.stream().filter(ScannedPom::contained)
                .filter(pom -> visibleFrom(pom, declaring, poms))
                .flatMap(pom -> pom.scan().managed().stream()).anyMatch(RawDependency::bomImport);
    }

    private boolean visibleFrom(ScannedPom possibleAncestor, ScannedPom declaring,
                                List<ScannedPom> poms) {
        Map<Path, ScannedPom> byPath = poms.stream().collect(java.util.stream.Collectors.toMap(
                ScannedPom::absolutePath, pom -> pom));
        ScannedPom current = declaring;
        Set<Path> visited = new LinkedHashSet<>();
        while (current != null && visited.add(current.absolutePath())) {
            if (current.absolutePath().equals(possibleAncestor.absolutePath())) {
                return true;
            }
            String parent = current.scan().parentRelativePath();
            if (parent == null || parent.isBlank()) {
                return false;
            }
            current = byPath.get(current.absolutePath().getParent().resolve(parent)
                    .toAbsolutePath().normalize());
        }
        return false;
    }

    private ScannedPom rootPom(List<ScannedPom> poms) {
        return poms.stream().filter(pom -> "pom.xml".equals(pom.file().path())).findFirst()
                .orElseThrow();
    }

    private PropertyRef property(ScannedPom declaring, String name, List<ScannedPom> poms) {
        Map<Path, ScannedPom> byPath = poms.stream().collect(java.util.stream.Collectors.toMap(
                ScannedPom::absolutePath, pom -> pom));
        ScannedPom current = declaring;
        Set<Path> visited = new LinkedHashSet<>();
        while (current != null && visited.add(current.absolutePath())) {
            PropertyDefinition definition = current.scan().properties().get(name);
            if (definition != null && current.contained()) {
                return new PropertyRef(current, definition);
            }
            String relativeParent = current.scan().parentRelativePath();
            if (relativeParent == null || relativeParent.isBlank()) {
                break;
            }
            Path parent = current.absolutePath().getParent().resolve(relativeParent)
                    .toAbsolutePath().normalize();
            current = byPath.get(parent);
        }
        return null;
    }

    private Map<String, Set<String>> propertyUsers(List<ScannedPom> poms) {
        Map<String, Set<String>> users = new HashMap<>();
        for (ScannedPom pom : poms) {
            if (!pom.contained()) {
                continue;
            }
            for (RawDependency raw : concat(pom.scan().dependencies(), pom.scan().managed())) {
                String property = propertyName(raw.versionLiteral());
                if (property != null && raw.groupId() != null && raw.artifactId() != null) {
                    users.computeIfAbsent(property, ignored -> new LinkedHashSet<>())
                            .add(raw.groupId() + ":" + raw.artifactId());
                }
            }
        }
        return users;
    }

    private String resolvedPropertyValue(ScannedPom declaring, String name, List<ScannedPom> poms,
                                         Set<String> visited) {
        if (!visited.add(name)) {
            return property(declaring, name, poms).definition().value();
        }
        PropertyRef definition = property(declaring, name, poms);
        String value = definition.definition().value();
        String nested = propertyName(value);
        if (nested == null || property(definition.pom(), nested, poms) == null) {
            return value;
        }
        return resolvedPropertyValue(definition.pom(), nested, poms, visited);
    }

    private List<RawDependency> concat(List<RawDependency> first, List<RawDependency> second) {
        List<RawDependency> result = new ArrayList<>(first);
        result.addAll(second);
        return result;
    }

    private String propertyName(String literal) {
        if (literal == null || literal.length() < 4 || !literal.startsWith("${")
                || !literal.endsWith("}")) {
            return null;
        }
        return literal.substring(2, literal.length() - 1);
    }

    private String latest(StoredComponent component, ProbeContext context) {
        if (context == null) {
            return null;
        }
        return resolver.knownVersions(new MavenArtifact(component.group(), component.name()), context)
                .stream().max(VersionOrder.INSTANCE).orElse(null);
    }

    private String highestSeverity(List<FindingRow> findings) {
        return findings.stream().filter(FindingRow::hasFinding)
                .map(row -> SeverityBand.of(true, row.severityScore()))
                .min(Comparator.comparingInt(Enum::ordinal)).map(SeverityBand::label).orElse(null);
    }

    private List<BumpRow> assignIds(List<PendingRow> pending) {
        Map<String, List<SiteCandidate>> byFile = new LinkedHashMap<>();
        for (PendingRow row : pending) {
            byFile.computeIfAbsent(row.site().site().file(), ignored -> new ArrayList<>()).add(row.site());
        }
        Map<String, String> ids = new HashMap<>();
        for (Map.Entry<String, List<SiteCandidate>> entry : byFile.entrySet()) {
            List<SiteCandidate> sites = entry.getValue().stream()
                    .collect(java.util.stream.Collectors.toMap(SiteCandidate::key, value -> value,
                            (left, right) -> left, LinkedHashMap::new)).values().stream()
                    .sorted(Comparator.comparingInt(SiteCandidate::position)
                            .thenComparing(SiteCandidate::key)).toList();
            for (int ordinal = 0; ordinal < sites.size(); ordinal++) {
                ids.put(sites.get(ordinal).key(), entry.getKey() + "#" + ordinal);
            }
        }
        return pending.stream().map(row -> {
            DeclarationSite site = row.site().site();
            DeclarationSite identified = new DeclarationSite(ids.get(row.site().key()), site.file(),
                    site.module(), site.kind(), site.groupId(), site.artifactId(), site.type(),
                    site.classifier(), site.currentVersion(), site.propertyName(), site.sharedWith(),
                    site.exclusions(), site.versionRange(), site.insertionPoint(), site.ecosystem(),
                    site.versionLiteral(), site.rangeAdmitsFix());
            return new BumpRow(identified, row.minimal(), row.latest(), row.advisories(),
                    row.severity(), row.artifactUrl(), row.currentVersionUrl(),
                    row.minimalTargetUrl(), row.latestTargetUrl());
        }).toList();
    }

    private String keyFor(DeclarationSite site) {
        String position = site.versionRange() != null
                ? Integer.toString(site.versionRange().start())
                : Integer.toString(site.insertionPoint().start());
        return keyFor(site, Integer.parseInt(position));
    }

    private String keyFor(DeclarationSite site, int position) {
        String coordinate = site.kind() == SiteKind.PROPERTY ? site.propertyName()
                : site.groupId() + ":" + site.artifactId();
        return site.file() + "|" + position + "|" + site.kind() + "|" + coordinate;
    }

    private String moduleName(ScannedPom pom) {
        return "pom.xml".equals(pom.file().path()) ? "" : pom.scan().moduleArtifactId();
    }

    private void addOnce(List<SiteCandidate> sites, SiteCandidate candidate) {
        if (sites.stream().noneMatch(existing -> existing.key().equals(candidate.key()))) {
            sites.add(candidate);
        }
    }

    private record DependencyRef(ScannedPom pom, RawDependency raw) {}
    private record PropertyRef(ScannedPom pom, PropertyDefinition definition) {}
    private record SiteCandidate(DeclarationSite site, int position, String key) {}
    private record PendingRow(SiteCandidate site, String minimal, String latest,
                              List<BumpAdvisory> advisories, String severity,
                              String artifactUrl, String currentVersionUrl,
                              String minimalTargetUrl, String latestTargetUrl) {}
}
