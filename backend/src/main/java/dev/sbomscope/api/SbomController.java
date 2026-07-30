package dev.sbomscope.api;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import dev.sbomscope.export.RegistryLinks;
import dev.sbomscope.probe.BumpProbeService;
import dev.sbomscope.probe.BumpProgress;
import dev.sbomscope.probe.BumpRequest;
import dev.sbomscope.sbom.ComponentGraph;
import dev.sbomscope.sbom.DependencyGraphService;
import dev.sbomscope.sbom.DependencyScope;
import dev.sbomscope.sbom.GraphNode;
import dev.sbomscope.sbom.InvalidSbomException;
import dev.sbomscope.sbom.SbomService;
import dev.sbomscope.sbom.StoredComponent;
import dev.sbomscope.sbom.StoredSbom;
import dev.sbomscope.scanner.FindingQuery;
import dev.sbomscope.scanner.SbomSeverity;
import dev.sbomscope.scanner.ScanService;
import dev.sbomscope.scanner.UpgradeAdvice;
import dev.sbomscope.scanner.UpgradeAdviceService;
import dev.sbomscope.settings.SettingsService;

@RestController
@RequestMapping("/api/sboms")
class SbomController {

    private final SbomService service;
    private final ScanService scans;
    private final DependencyGraphService graphs;
    private final UpgradeAdviceService advice;
    private final BumpProbeService bumpProbes;
    private final SettingsService settings;

    SbomController(SbomService service, ScanService scans, DependencyGraphService graphs,
                   UpgradeAdviceService advice, BumpProbeService bumpProbes, SettingsService settings) {
        this.service = service;
        this.scans = scans;
        this.graphs = graphs;
        this.advice = advice;
        this.bumpProbes = bumpProbes;
        this.settings = settings;
    }

    record SbomResponse(
            UUID id,
            String filename,
            Instant uploadedAt,
            String workspacePath,
            String specVersion,
            int componentCount,
            /**
             * How many of this SBOM's components carry a scan record. Zero means the scanner
             * has never reached it, and {@code severityCounts} then describes nothing —
             * without this the list could not tell "checked, clean" from "never checked",
             * which is the ambiguity the whole schema is arranged to avoid.
             *
             * <p>May be non-zero for an SBOM that was never scanned itself: findings are
             * cached per purl and shared, so a new upload of familiar libraries arrives
             * already covered. That is the cache working, not a mistake.
             */
            int scannedComponents,
            /** Rows per band across the whole SBOM, unfiltered. Every band is present. */
            Map<FindingQuery.SeverityBand, Integer> severityCounts) {

        static SbomResponse from(StoredSbom sbom, SbomSeverity severity) {
            SbomSeverity risk = severity == null ? SbomSeverity.notScanned() : severity;
            return new SbomResponse(
                    sbom.id(),
                    sbom.filename(),
                    sbom.uploadedAt(),
                    sbom.workspacePath(),
                    sbom.specVersion(),
                    sbom.componentCount(),
                    risk.scannedComponents(),
                    risk.counts());
        }
    }

    record ComponentResponse(
            UUID id,
            String coordinates,
            String group,
            String name,
            String version,
            String purl,
            String type,
            boolean root,
            /** APPLICATION, DIRECT or TRANSITIVE. */
            DependencyScope scope,
            /** Public registry page, or null for ecosystems we cannot link. */
            String registryUrl) {

        static ComponentResponse from(StoredComponent component) {
            return new ComponentResponse(
                    component.id(),
                    component.coordinates(),
                    component.group(),
                    component.name(),
                    component.version(),
                    component.purl(),
                    component.type(),
                    component.root(),
                    component.scope(),
                    RegistryLinks.forPurl(component.purl()));
        }
    }

    @PostMapping
    ResponseEntity<SbomResponse> upload(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "workspacePath", required = false) String workspacePath) {

        if (file.isEmpty()) {
            throw new InvalidSbomException("The uploaded file is empty.");
        }

        try (var content = file.getInputStream()) {
            StoredSbom stored = service.importSbom(
                    originalFilename(file), workspacePath, content);
            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(SbomResponse.from(stored, scans.severityFor(stored.id())));
        } catch (IOException e) {
            throw new InvalidSbomException("The uploaded file could not be read.", e);
        }
    }

    @GetMapping
    List<SbomResponse> list() {
        // One lookup for the whole list rather than one per entry: this is what the sidebar
        // renders, and it re-renders on every upload, deletion and scan.
        Map<UUID, SbomSeverity> risk = scans.severityBySbom();
        return service.findAll().stream()
                .map(sbom -> SbomResponse.from(sbom, risk.get(sbom.id())))
                .toList();
    }

    @GetMapping("/{id}")
    SbomResponse get(@PathVariable UUID id) {
        return service.findById(id)
                .map(sbom -> SbomResponse.from(sbom, scans.severityFor(id)))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "No such SBOM"));
    }

    @GetMapping("/{id}/components")
    List<ComponentResponse> components(@PathVariable UUID id) {
        if (service.findById(id).isEmpty()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "No such SBOM");
        }
        return service.findComponents(id).stream().map(ComponentResponse::from).toList();
    }

    /**
     * Everything the Component Inspector needs about one component.
     *
     * @param scannedAt when this component's purl was last checked. <b>Null means never</b>,
     *                  and {@code findings} then says nothing — an empty finding list from an
     *                  unscanned component looks exactly like a clean bill of health, which
     *                  is the one thing this application must never imply
     * @param findings  the same rows the findings table would show for this component, from
     *                  the same query and mapper. A single row with a null {@code osvId}
     *                  means checked and nothing found
     */
    record ComponentDetailResponse(
            ComponentResponse component,
            Instant scannedAt,
            List<RowResponse> findings) {}

    /**
     * Keyed by purl rather than by component row id.
     *
     * <p>The findings table is purl-keyed — its query selects DISTINCT over the purl
     * precisely so a library listed twice in one document produces one row — so linking a
     * row to a component row id would have meant putting that id back into the row and
     * losing that collapse. The Inspector's unit has to be the table's unit, or the action
     * on a row would open something the row was not describing.
     *
     * <p>Passed as a query parameter rather than a path segment: a purl contains slashes,
     * and an encoded slash in a path is rejected outright by some servlet containers.
     */
    @GetMapping("/{id}/component")
    ComponentDetailResponse component(@PathVariable UUID id, @RequestParam("purl") String purl) {
        if (service.findById(id).isEmpty()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "No such SBOM");
        }

        StoredComponent component = service.findComponentByPurl(id, purl)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "That component is not in this SBOM"));

        return new ComponentDetailResponse(
                ComponentResponse.from(component),
                scans.scannedAtForPurl(purl).orElse(null),
                scans.rowsForComponent(id, purl).stream().map(RowResponse::from).toList());
    }

    @DeleteMapping("/{id}")
    ResponseEntity<Void> delete(@PathVariable UUID id) {
        if (!service.delete(id)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "No such SBOM");
        }
        return ResponseEntity.noContent().build();
    }

    /**
     * Where this component sits in the SBOM's own dependency graph.
     *
     * <p>Separate from {@code /component} rather than folded into it: the graph walks the
     * whole document, while the header and findings are a lookup, and the panel that needs
     * it is one tab among several. A reader who never opens that tab should not pay for it.
     */
    @GetMapping("/{id}/component/graph")
    ComponentGraph graph(@PathVariable UUID id, @RequestParam("purl") String purl) {
        if (service.findById(id).isEmpty()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "No such SBOM");
        }
        return graphs.graphFor(id, purl, scans.vulnerablePurls(id));
    }

    /**
     * What to change about this component, and where.
     *
     * <p>Offline by construction: it reads the advisories' own fix versions and the
     * dependency graph, both already held. Nothing here reaches the network, which is the
     * whole reason this tier could be built before the outbound-lookup settings exist.
     */
    @GetMapping("/{id}/component/upgrade")
    UpgradeAdvice upgrade(@PathVariable UUID id, @RequestParam("purl") String purl) {
        if (service.findById(id).isEmpty()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "No such SBOM");
        }
        StoredComponent component = service.findComponentByPurl(id, purl)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "That component is not in this SBOM"));

        return advice.adviseFor(
                component,
                scans.rowsForComponent(id, purl),
                graphs.graphFor(id, purl, scans.vulnerablePurls(id)),
                scans.evaluatorFor(component));
    }

    /**
     * Starts (or returns the already-running or cached) Maven probe for this component's
     * {@code BUMP_ANCESTOR} remedy.
     *
     * <p>Deliberately separate from {@code /component/upgrade}: Tier 1 above answers instantly
     * from data already held, while this drives a real external process and can take real
     * wall-clock time — exactly why it is started and polled rather than returned inline.
     */
    @PostMapping("/{id}/component/bump")
    BumpProgress startBump(@PathVariable UUID id, @RequestParam("purl") String purl) {
        return bumpProbes.start(bumpRequestFor(id, purl), settings.mavenSettings());
    }

    @GetMapping("/{id}/component/bump")
    BumpProgress bumpProgress(@PathVariable UUID id, @RequestParam("purl") String purl) {
        if (service.findById(id).isEmpty()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "No such SBOM");
        }
        StoredComponent component = service.findComponentByPurl(id, purl)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "That component is not in this SBOM"));
        return bumpProbes.progress(component, graphs.graphFor(id, purl, scans.vulnerablePurls(id)));
    }

    private BumpRequest bumpRequestFor(UUID id, String purl) {
        StoredSbom sbom = service.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "No such SBOM"));
        StoredComponent component = service.findComponentByPurl(id, purl)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "That component is not in this SBOM"));

        ComponentGraph graph = graphs.graphFor(id, purl, scans.vulnerablePurls(id));

        // The most-affected module first, matching how the graph itself is already ordered —
        // its full direct set, not just the one route reaching this component, since Maven's
        // nearest-wins resolution needs every competing declaration to decide correctly.
        List<GraphNode> moduleDependencies = graph.reachedFrom().isEmpty()
                ? List.of()
                : graphs.directDependencies(id, graph.reachedFrom().getFirst().module().bomRef());

        return new BumpRequest(
                id,
                component,
                graph,
                moduleDependencies,
                UpgradeAdviceService.advisoriesFrom(scans.rowsForComponent(id, purl)),
                sbom.workspacePath(),
                scans.evaluatorFor(component));
    }

    /**
     * Multipart filenames arrive from the browser and are shown back to the user, so
     * only the bare name is kept — never a path the client happened to include.
     */
    private String originalFilename(MultipartFile file) {
        String name = file.getOriginalFilename();
        if (name == null || name.isBlank()) {
            return "sbom.json";
        }
        int lastSeparator = Math.max(name.lastIndexOf('/'), name.lastIndexOf('\\'));
        String bare = lastSeparator >= 0 ? name.substring(lastSeparator + 1) : name;
        return bare.isBlank() ? "sbom.json" : bare;
    }
}
