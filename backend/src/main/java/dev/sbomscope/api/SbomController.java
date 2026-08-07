package dev.sbomscope.api;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
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
import dev.sbomscope.sbom.FolderService;
import dev.sbomscope.sbom.GraphNode;
import dev.sbomscope.sbom.InvalidSbomException;
import dev.sbomscope.sbom.SbomFileStore;
import dev.sbomscope.sbom.SbomService;
import dev.sbomscope.sbom.StoredComponent;
import dev.sbomscope.sbom.StoredSbom;
import dev.sbomscope.scanner.AutomaticScanner;
import dev.sbomscope.scanner.FindingQuery;
import dev.sbomscope.scanner.SbomSeverity;
import dev.sbomscope.scanner.ScanService;
import dev.sbomscope.scanner.UpgradeAdvice;
import dev.sbomscope.scanner.UpgradeAdviceService;
import dev.sbomscope.settings.SettingsService;
import dev.sbomscope.reachability.WorkspaceComponentAnalysis;
import dev.sbomscope.reachability.WorkspaceReachabilityService;

@RestController
@RequestMapping("/api/sboms")
class SbomController {

    private final SbomService service;
    private final ScanService scans;
    private final AutomaticScanner autoScans;
    private final SbomFileStore files;
    private final DependencyGraphService graphs;
    private final UpgradeAdviceService advice;
    private final BumpProbeService bumpProbes;
    private final SettingsService settings;
    private final WorkspaceReachabilityService workspaceReachability;
    private final FolderService folders;

    SbomController(SbomService service, ScanService scans, AutomaticScanner autoScans,
                   SbomFileStore files, DependencyGraphService graphs, UpgradeAdviceService advice,
                   BumpProbeService bumpProbes, SettingsService settings,
                   WorkspaceReachabilityService workspaceReachability, FolderService folders) {
        this.service = service;
        this.scans = scans;
        this.autoScans = autoScans;
        this.files = files;
        this.graphs = graphs;
        this.advice = advice;
        this.bumpProbes = bumpProbes;
        this.settings = settings;
        this.workspaceReachability = workspaceReachability;
        this.folders = folders;
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
            Map<FindingQuery.SeverityBand, Integer> severityCounts,
            /**
             * An automatic scan is queued or running for this SBOM right now.
             *
             * <p>Carried on the list itself rather than on an endpoint of its own, because
             * the counts beside it are what change when the scan finishes — one poll of this
             * list both clears the marker and updates the numbers, and two sources could
             * disagree about which of the two had happened.
             */
            boolean scanning,
            /** The project or folder this is filed under, or null when it sits outside them all. */
            UUID folderId) {

        static SbomResponse from(StoredSbom sbom, SbomSeverity severity, boolean scanning) {
            SbomSeverity risk = severity == null ? SbomSeverity.notScanned() : severity;
            return new SbomResponse(
                    sbom.id(),
                    sbom.filename(),
                    sbom.uploadedAt(),
                    sbom.workspacePath(),
                    sbom.specVersion(),
                    sbom.componentCount(),
                    risk.scannedComponents(),
                    risk.counts(),
                    scanning,
                    sbom.folderId());
        }
    }

    /**
     * Sets, changes or clears the attached workspace (B20).
     *
     * <p>A null or blank path clears it, which is a real operation rather than a malformed
     * request: a workspace that has moved is worse than none, because analysis then answers
     * confidently about a directory that is no longer the project.
     */
    record WorkspaceRequest(String workspacePath) {}

    /** @param folderId null files the document outside every project */
    record FolderRequest(UUID folderId) {}

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
            /** The artifact's own registry page, or null where we have nothing safe to link. */
            String registryArtifactUrl,
            /** This exact version's page, or null where that version has none. */
            String registryVersionUrl,
            /**
             * The worst band standing against this component, or <b>null for never scanned</b>.
             *
             * <p>Null is not "clean" and must not be rendered as it. {@code CLEAN} means checked
             * with nothing found; null means nobody has looked, which in a security tool is the
             * one ambiguity worth spending a distinct visual state on.
             */
            FindingQuery.SeverityBand severity) {

        static ComponentResponse from(StoredComponent component) {
            return from(component, null);
        }

        static ComponentResponse from(StoredComponent component, FindingQuery.SeverityBand severity) {
            RegistryLinks.Links links = RegistryLinks.forPurl(component.purl());
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
                    links.artifactUrl(),
                    links.versionUrl(),
                    severity);
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

            // Queued, never awaited: importing a document must not take as long as scanning
            // it. The response already carries `scanning`, so the card can say so on arrival
            // rather than only on the next poll.
            autoScans.scanLater(stored.id(), AutomaticScanner.Trigger.UPLOAD);

            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(SbomResponse.from(stored, scans.severityFor(stored.id()),
                            autoScans.isInFlight(stored.id())));
        } catch (IOException e) {
            throw new InvalidSbomException("The uploaded file could not be read.", e);
        }
    }

    @GetMapping
    List<SbomResponse> list() {
        // One lookup for the whole list rather than one per entry: this is what the sidebar
        // renders, and it re-renders on every upload, deletion and scan.
        Map<UUID, SbomSeverity> risk = scans.severityBySbom();
        Set<UUID> scanning = autoScans.inFlight();
        return service.findAll().stream()
                .map(sbom -> SbomResponse.from(sbom, risk.get(sbom.id()), scanning.contains(sbom.id())))
                .toList();
    }

    @GetMapping("/{id}")
    SbomResponse get(@PathVariable UUID id) {
        return service.findById(id)
                .map(sbom -> SbomResponse.from(sbom, scans.severityFor(id), autoScans.isInFlight(id)))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "No such SBOM"));
    }

    /**
     * The document exactly as it was uploaded.
     *
     * <p>The stored bytes, not a re-serialisation of our parse: this is the file osv-scanner
     * reads, so it is also the one worth handing to somebody else — and anything reconstructed
     * here would quietly launder a parsing mistake into what the reader believes they were
     * given.
     *
     * <p>404 where the document has been swept. The SBOM row can outlive its file (the sweeper
     * is deliberately one-directional, and a schema reset leaves the disk untouched), and that
     * is the same state a re-scan already reports as "upload it again".
     */
    @GetMapping("/{id}/document")
    ResponseEntity<Resource> document(@PathVariable UUID id) {
        StoredSbom sbom = service.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "No such SBOM"));

        if (!files.exists(id)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND,
                    "The uploaded document for this SBOM is no longer on disk.");
        }

        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_JSON)
                // The name it arrived under, not the <uuid>.cdx.json it is stored as — that
                // filename is an implementation detail of the scanner's parser selection.
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.attachment().filename(sbom.filename()).build().toString())
                .body(new FileSystemResource(files.pathFor(id)));
    }

    /**
     * The SBOM's components, each carrying the worst band standing against it.
     *
     * <p>The severity rides on this response rather than arriving from a call of its own: the
     * finder renders one list, and two sources would let its colours describe a different set of
     * components than its rows. One extra query per call, against a list already being read.
     */
    @GetMapping("/{id}/components")
    List<ComponentResponse> components(@PathVariable UUID id) {
        if (service.findById(id).isEmpty()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "No such SBOM");
        }
        Map<String, FindingQuery.SeverityBand> worst = scans.worstBandByPurl(id);
        return service.findComponents(id).stream()
                // Absent from the map means no scan row at all, and null carries that through
                // to the client as "never checked" rather than collapsing it into CLEAN.
                .map(component -> ComponentResponse.from(component, worst.get(component.purl())))
                .toList();
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
     * Attaches, changes or clears this document's workspace (B20).
     *
     * <p>An absolute path in a text field, deliberately, and not a directory picker: B11 was
     * dropped on 2026-08-02 because a backend-rendered browser turns the local server into a
     * filesystem browser and a native dialog fails headless. That reasoning is untouched here,
     * and this endpoint must not become the excuse to reintroduce one.
     */
    @PatchMapping("/{id}/workspace")
    SbomResponse attachWorkspace(@PathVariable UUID id, @RequestBody WorkspaceRequest request) {
        StoredSbom updated = service.attachWorkspace(id, request.workspacePath())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "No such SBOM"));
        return SbomResponse.from(updated, scans.severityFor(id), autoScans.isInFlight(id));
    }

    /** Files this document into a project or folder, or out of every one of them (B19). */
    @PatchMapping("/{id}/folder")
    ResponseEntity<Void> moveToFolder(@PathVariable UUID id, @RequestBody FolderRequest request) {
        folders.moveSbom(id, request.folderId());
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

    @GetMapping("/{id}/component/graph/routes")
    ComponentGraph.RoutePage graphRoutes(
            @PathVariable UUID id,
            @RequestParam("purl") String purl,
            @RequestParam("module") String moduleBomRef,
            @RequestParam(value = "offset", defaultValue = "0") int offset,
            @RequestParam(value = "limit", defaultValue = "100") int limit) {
        if (service.findById(id).isEmpty()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "No such SBOM");
        }
        if (offset < 0 || limit < 1 || limit > DependencyGraphService.ROUTE_PAGE_SIZE
                || (long) offset + limit > DependencyGraphService.MAX_ROUTE_PREFIX) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Route pages must contain at most 100 routes within the first 10,000.");
        }
        return graphs.routePageFor(id, purl, moduleBomRef, offset, limit, scans.vulnerablePurls(id));
    }

    /**
     * Bytecode-use evidence for this component, requested only when the Inspector's Workspace
     * usage tab is opened. It may enqueue an offline analysis of already-built classes, but it
     * never builds the workspace, invokes Maven, or reads SBOMscope's probe repository.
     */
    @GetMapping("/{id}/component/workspace")
    WorkspaceComponentAnalysis workspaceUsage(@PathVariable UUID id, @RequestParam("purl") String purl) {
        if (service.findById(id).isEmpty()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "No such SBOM");
        }
        service.findComponentByPurl(id, purl)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "That component is not in this SBOM"));
        return workspaceReachability.inspect(id, purl);
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

    /**
     * Extends a finished run that the budget cut short, rather than re-running it whole.
     * Separate from {@code POST /bump} because that one deliberately refuses to re-run a
     * completed probe; this is the sanctioned way to ask for more of the same search.
     */
    @PostMapping("/{id}/component/bump/continue")
    BumpProgress continueBump(@PathVariable UUID id, @RequestParam("purl") String purl) {
        return bumpProbes.continueRun(bumpRequestFor(id, purl), settings.mavenSettings());
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
        List<GraphNode> moduleDependencies = graph.primaryTransitiveOwner()
                .map(owner -> graphs.directDependencies(id, owner.module().bomRef()))
                .orElse(List.of());

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
