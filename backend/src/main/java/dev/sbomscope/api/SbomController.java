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
import dev.sbomscope.sbom.DependencyScope;
import dev.sbomscope.sbom.InvalidSbomException;
import dev.sbomscope.sbom.SbomService;
import dev.sbomscope.sbom.StoredComponent;
import dev.sbomscope.sbom.StoredSbom;
import dev.sbomscope.scanner.FindingQuery;
import dev.sbomscope.scanner.SbomSeverity;
import dev.sbomscope.scanner.ScanService;

@RestController
@RequestMapping("/api/sboms")
class SbomController {

    private final SbomService service;
    private final ScanService scans;

    SbomController(SbomService service, ScanService scans) {
        this.service = service;
        this.scans = scans;
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

    @DeleteMapping("/{id}")
    ResponseEntity<Void> delete(@PathVariable UUID id) {
        if (!service.delete(id)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "No such SBOM");
        }
        return ResponseEntity.noContent().build();
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
