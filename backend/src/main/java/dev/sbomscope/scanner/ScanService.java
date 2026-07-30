package dev.sbomscope.scanner;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import dev.sbomscope.logging.ActivityLogger;
import dev.sbomscope.sbom.SbomFileStore;
import dev.sbomscope.sbom.SbomService;
import dev.sbomscope.sbom.StoredComponent;
import dev.sbomscope.settings.ScannerSettings;
import dev.sbomscope.settings.SettingsService;

/** Runs a vulnerability scan for one SBOM and stores the result. */
@Service
public class ScanService {

    private static final Logger log = LoggerFactory.getLogger(ScanService.class);

    private final SettingsService settings;
    private final OsvScannerRunner runner;
    private final OsvReportParser parser;
    private final VulnerabilityRepository repository;
    private final SbomService sboms;
    private final SbomFileStore files;
    private final OsvDatabaseService databases;
    private final OsvArchiveMatcher archives;
    private final ActivityLogger activityLog;

    private final Duration staleAfter;

    ScanService(SettingsService settings, OsvScannerRunner runner, OsvReportParser parser,
                VulnerabilityRepository repository, SbomService sboms, SbomFileStore files,
                OsvDatabaseService databases, OsvArchiveMatcher archives, ActivityLogger activityLog,
                @Value("${sbomscope.scan.stale-after-days:7}") int staleAfterDays) {
        this.settings = settings;
        this.runner = runner;
        this.parser = parser;
        this.repository = repository;
        this.sboms = sboms;
        this.files = files;
        this.databases = databases;
        this.archives = archives;
        this.activityLog = activityLog;
        this.staleAfter = Duration.ofDays(staleAfterDays);
    }

    public long staleAfterDays() {
        return staleAfter.toDays();
    }

    /**
     * Whether results are old enough to warrant a refresh.
     *
     * <p>Never-scanned counts as stale: the absence of findings must never read as
     * "clean" when nothing has actually been checked.
     */
    public boolean isStale(UUID sbomId) {
        return lastScannedAt(sbomId)
                .map(scannedAt -> scannedAt.isBefore(Instant.now().minus(staleAfter)))
                .orElse(true);
    }

    /**
     * @param componentsScanned every component the scan covered, vulnerable or not
     * @param findings          how many vulnerabilities were recorded
     */
    public record ScanResult(int componentsScanned, int findings, Instant scannedAt, String scannerVersion) {}

    /**
     * Whether a scan could actually run right now, and if not, what is missing.
     *
     * <p>Exists because "scanning is switched on" is a much weaker statement than "scanning
     * would work": the configured binary may have been moved, and the OSV archive for this
     * SBOM's ecosystem may never have been downloaded. Both used to surface only as an
     * error after pressing the button, which is the wrong moment to learn it.
     *
     * @param reason a stable code the UI turns into a message and a link; {@code READY}
     *               when nothing is wrong
     * @param detail the specifics — which path, which ecosystems — kept out of the code so
     *               the UI is not parsing prose
     */
    public record ScanReadiness(boolean ready, String reason, String detail) {

        /** Named {@code ok} rather than {@code ready}: that is the accessor's name. */
        static ScanReadiness ok() {
            return new ScanReadiness(true, "READY", null);
        }

        static ScanReadiness blocked(String reason, String detail) {
            return new ScanReadiness(false, reason, detail);
        }
    }

    /**
     * Checked per SBOM rather than globally, because the databases needed depend on what is
     * actually in the document: telling someone with a Maven-only SBOM to download npm's
     * 200 MB archive would be wrong as well as annoying.
     *
     * <p>Filesystem checks only. Confirming the binary really is osv-scanner means running
     * it, which belongs behind the deliberate "Test scanner" action in Settings, not on
     * every poll of the findings view.
     */
    public ScanReadiness readiness(UUID sbomId) {
        ScannerSettings scanner = settings.scannerSettings();

        if (!scanner.enabled()) {
            return ScanReadiness.blocked("SCANNING_DISABLED", null);
        }
        if (!scanner.hasExecutable()) {
            return ScanReadiness.blocked("NO_EXECUTABLE", null);
        }
        if (!Files.isRegularFile(Path.of(scanner.executablePath()))) {
            return ScanReadiness.blocked("EXECUTABLE_MISSING", scanner.executablePath());
        }

        List<String> missing = missingDatabases(sbomId, scanner.databaseDirectory());
        if (!missing.isEmpty()) {
            return ScanReadiness.blocked("NO_DATABASE", String.join(", ", missing));
        }
        return ScanReadiness.ok();
    }

    /** Ecosystems this SBOM contains that have no downloaded archive behind them. */
    private List<String> missingDatabases(UUID sbomId, String databaseDirectory) {
        Set<String> required = sboms.findComponents(sbomId).stream()
                .map(this::ecosystemOf)
                .filter(ecosystem -> !ecosystem.isEmpty())
                .collect(Collectors.toCollection(LinkedHashSet::new));

        Set<String> present = databases.status(databaseDirectory).stream()
                .filter(OsvDatabaseService.EcosystemStatus::present)
                .map(OsvDatabaseService.EcosystemStatus::ecosystem)
                .collect(Collectors.toSet());

        return required.stream().filter(ecosystem -> !present.contains(ecosystem)).toList();
    }

    @Transactional
    public ScanResult scan(UUID sbomId) {
        ScannerSettings scanner = settings.scannerSettings();
        if (!scanner.enabled()) {
            throw new OsvScannerException(
                    "Scanning is switched off. Enable it in Settings to check this SBOM.");
        }
        if (!scanner.hasExecutable()) {
            throw new OsvScannerException(
                    "No scanner configured. Set the path to osv-scanner in Settings.");
        }
        if (!files.exists(sbomId)) {
            throw new OsvScannerException(
                    "The uploaded document for this SBOM is no longer on disk, so it cannot be "
                            + "re-scanned. Upload it again.");
        }

        List<StoredComponent> components = sboms.findComponents(sbomId);
        if (components.isEmpty()) {
            throw new OsvScannerException("This SBOM has no components to scan.");
        }

        String version = runner.version(scanner.executablePath());
        Path document = files.pathFor(sbomId);
        String report = runner.scan(document, scanner);

        // The report identifies packages by ecosystem/name/version and carries no purl,
        // so results are tied back to the components we already hold.
        Map<OsvReportParser.PackageKey, String> byKey = indexComponents(components);
        List<VulnerabilityFinding> findings =
                parser.parse(report, key -> Optional.ofNullable(byKey.get(key)));

        List<String> scannedPurls = components.stream()
                .map(StoredComponent::purl)
                .filter(purl -> purl != null && !purl.isBlank())
                .distinct()
                .toList();

        Instant scannedAt = Instant.now();
        repository.recordScan(scannedPurls, findings, version, scannedAt);

        log.info("Scanned SBOM {}: {} components, {} findings", sbomId, scannedPurls.size(), findings.size());
        activityLog.record(ActivityLogger.Category.DATA, "SCAN", "SUCCESS",
                "SBOM %s: %d components, %d findings".formatted(sbomId, scannedPurls.size(), findings.size()));
        return new ScanResult(scannedPurls.size(), findings.size(), scannedAt, version);
    }

    /** Every finding, most severe first — the default view ordering. */
    public List<VulnerabilityFinding> findings(UUID sbomId) {
        return repository.findingsForSbom(sbomId, FindingQuery.defaults());
    }

    /** View rows: components joined to their vulnerabilities, including clean ones. */
    public List<FindingRow> rows(UUID sbomId, FindingQuery query) {
        return repository.rowsForSbom(sbomId, query);
    }

    public int countRows(UUID sbomId, FindingQuery query) {
        return repository.countRows(sbomId, query);
    }

    /** One component's rows, in the same shape and order the table would show them. */
    public List<FindingRow> rowsForComponent(UUID sbomId, String purl) {
        return repository.rowsForComponent(sbomId, purl);
    }

    /** When this purl was last checked; absent means never, which is not "clean". */
    public Optional<Instant> scannedAtForPurl(String purl) {
        return repository.scannedAtForPurl(purl);
    }

    /** Which of an SBOM's purls carry findings — for marking nodes in the dependency graph. */
    public Set<String> vulnerablePurls(UUID sbomId) {
        return repository.vulnerablePurls(sbomId);
    }

    /** Vulnerabilities only, for counts that describe risk rather than inventory size. */
    public int countFindings(UUID sbomId, FindingQuery query) {
        return repository.countFindings(sbomId, query);
    }

    /**
     * The headline count broken down by band, unfiltered — so the summary describes the
     * SBOM rather than whatever the table is currently narrowed to.
     */
    public Map<FindingQuery.SeverityBand, Integer> countsByBand(UUID sbomId) {
        return repository.countsByBand(sbomId);
    }

    /**
     * The risk summary for one SBOM, as the list shows it.
     *
     * <p>Assembled from the two existing per-SBOM counts rather than a query of its own, so
     * a card and the findings page cannot report different numbers for the same document.
     */
    public SbomSeverity severityFor(UUID sbomId) {
        return new SbomSeverity(repository.scannedComponentCount(sbomId), repository.countsByBand(sbomId));
    }

    /** The same summary for every SBOM at once, so listing them costs two queries, not 2n. */
    public Map<UUID, SbomSeverity> severityBySbom() {
        return repository.severityBySbom();
    }

    public Optional<Instant> lastScannedAt(UUID sbomId) {
        return repository.lastScannedAt(sbomId);
    }

    public int scannedComponentCount(UUID sbomId) {
        return repository.scannedComponentCount(sbomId);
    }

    /**
     * Every name the scanner might use for a component, mapped back to its purl.
     *
     * <p>Keys normalise their own casing, so both sides of the lookup are comparable.
     *
     * <p>More than one key per component on purpose. A scoped npm package can reach us as
     * either {@code name: "@angular/common"} with no group — which is what {@code npm sbom}
     * emits — or split into {@code group: "@angular"}, {@code name: "common"}, which other
     * generators do. The second form renders through {@code coordinates()} as
     * {@code @angular:common}, using the Maven separator, while osv-scanner always reports
     * {@code @angular/common}. The lookup then missed and the finding was dropped with
     * nothing but a log line to show for it.
     *
     * <p>Registering both spellings is cheaper and more robust than trying to decide which
     * generator produced the document. Collisions are harmless: the forms only coincide when
     * they denote the same package.
     */
    private Map<OsvReportParser.PackageKey, String> indexComponents(List<StoredComponent> components) {
        Map<OsvReportParser.PackageKey, String> byKey = new LinkedHashMap<>();

        for (StoredComponent component : components) {
            if (component.purl() == null || component.purl().isBlank()) {
                continue;
            }
            String ecosystem = ecosystemOf(component);
            for (String name : scannerNamesFor(component, ecosystem)) {
                var key = new OsvReportParser.PackageKey(ecosystem, name, component.version());
                String alreadyClaimed = byKey.putIfAbsent(key, component.purl());

                // Same ecosystem, name and version, but two different purls — Maven
                // qualifiers such as a classifier can produce that. The first still wins,
                // since reporting the advisory against one of the two beats dropping it,
                // but nothing else would ever show that a choice was made here.
                if (alreadyClaimed != null && !alreadyClaimed.equals(component.purl())) {
                    log.debug("{} is claimed by both {} and {}; keeping the first",
                            key, alreadyClaimed, component.purl());
                }
            }
        }
        return byKey;
    }

    /**
     * The spellings a scanner report might use for this component's name.
     *
     * <p><b>Never the bare name when the component has a group.</b> It used to be added
     * unconditionally, which meant every Maven component also claimed its artifactId alone:
     * {@code com.foo:core} and {@code com.bar:core} both claimed {@code core}, and whichever
     * was indexed first took it for both — a finding attributed to a library that does not
     * have it. That is the one error mode worse than dropping a finding, because it looks
     * like an answer.
     *
     * <p>It bought nothing in exchange. osv-scanner names Maven packages
     * {@code group:artifact}, so the bare form never matched; and an unscoped npm package
     * already arrives through {@code coordinates()}, which <em>is</em> the plain name when
     * there is no group. For a scoped npm package it was actively wrong — {@code common} is
     * a real package, and not the one {@code @angular/common} refers to.
     */
    static Set<String> scannerNamesFor(StoredComponent component, String ecosystem) {
        Set<String> names = new LinkedHashSet<>();
        names.add(component.coordinates());

        if ("npm".equals(ecosystem) && component.group() != null && !component.group().isBlank()) {
            // The scope and the package, joined the way npm and osv-scanner write it.
            names.add(component.group() + "/" + component.name());
        }
        return names;
    }

    /**
     * Checks a candidate version for one component against the downloaded archives.
     *
     * <p>Assembled here because this is where the scanner settings live. Every spelling the
     * component might be filed under is tried and the results merged by advisory id — the
     * same many-names problem the report lookup has, for the same reason.
     */
    public UpgradeAdviceService.TargetEvaluator evaluatorFor(StoredComponent component) {
        String ecosystem = ecosystemOf(component);
        String directory = settings.scannerSettings().databaseDirectory();

        if (ecosystem.isEmpty() || !archives.isIndexed(directory, ecosystem)) {
            return UpgradeAdviceService.TargetEvaluator.unavailable();
        }

        Set<String> names = scannerNamesFor(component, ecosystem);
        return version -> {
            Map<String, OsvArchiveMatcher.AdvisoryHit> byId = new LinkedHashMap<>();
            for (String name : names) {
                for (OsvArchiveMatcher.AdvisoryHit hit :
                        archives.advisoriesFor(directory, ecosystem, name, version)) {
                    byId.putIfAbsent(hit.osvId(), hit);
                }
            }
            return Optional.of(List.copyOf(byId.values()));
        };
    }

    /** Derived from the purl, which is the only place the ecosystem is recorded. */
    private String ecosystemOf(StoredComponent component) {
        String purl = component.purl();
        if (purl != null && purl.startsWith("pkg:maven/")) {
            return "Maven";
        }
        if (purl != null && purl.startsWith("pkg:npm/")) {
            return "npm";
        }
        return "";
    }
}
