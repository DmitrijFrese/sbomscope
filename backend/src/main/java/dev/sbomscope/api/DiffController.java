package dev.sbomscope.api;

import java.io.IOException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import dev.sbomscope.diff.DiffService;
import dev.sbomscope.diff.DiffService.DiffSort;
import dev.sbomscope.export.DiffExcelExporter;
import dev.sbomscope.sbom.SbomService;
import dev.sbomscope.sbom.StoredSbom;
import dev.sbomscope.scanner.ScanService;

@RestController
@RequestMapping("/api/diff")
class DiffController {

    private final DiffService diffs;
    private final SbomService sboms;
    private final ScanService scans;
    private final DiffExcelExporter exporter;

    DiffController(DiffService diffs, SbomService sboms, ScanService scans,
                   DiffExcelExporter exporter) {
        this.diffs = diffs;
        this.sboms = sboms;
        this.scans = scans;
        this.exporter = exporter;
    }

    @GetMapping
    DiffService.DiffResult compare(
            @RequestParam UUID left,
            @RequestParam UUID right,
            @RequestParam(value = "sort", defaultValue = "COORDINATES") DiffSort sort,
            @RequestParam(value = "direction", defaultValue = "asc") String direction,
            @RequestParam(value = "filter", required = false) String filter,
            @RequestParam(value = "regex", defaultValue = "false") boolean regex,
            @RequestParam(value = "negate", defaultValue = "false") boolean negate) {
        requireSbom(left);
        requireSbom(right);
        return diffs.compare(left, right, filter, regex, negate, sort, isAscending(direction));
    }

    @GetMapping("/export.xlsx")
    ResponseEntity<byte[]> export(
            @RequestParam UUID left,
            @RequestParam UUID right,
            @RequestParam(value = "sort", defaultValue = "COORDINATES") DiffSort sort,
            @RequestParam(value = "direction", defaultValue = "asc") String direction,
            @RequestParam(value = "filter", required = false) String filter,
            @RequestParam(value = "regex", defaultValue = "false") boolean regex,
            @RequestParam(value = "negate", defaultValue = "false") boolean negate,
            @RequestParam(value = "scope", defaultValue = "all") String scope) throws IOException {
        StoredSbom leftSbom = requireSbom(left);
        StoredSbom rightSbom = requireSbom(right);
        boolean visibleScope = "visible".equalsIgnoreCase(scope);

        // The service computes the summary before filtering. For a visible export that keeps
        // the headline document-wide while narrowing the rows; all deliberately drops the text
        // filter as well as restoring unchanged rows.
        DiffService.DiffResult comparison = visibleScope
                ? diffs.compare(left, right, filter, regex, negate, sort, isAscending(direction))
                : diffs.compare(left, right, null, false, false, sort, isAscending(direction));
        // Each document's own totals, read the same way the sidebar cards read them, so the
        // workbook's summary block and the screen's cannot disagree.
        byte[] workbook = exporter.export(leftSbom, rightSbom,
                scans.severityFor(left), scans.severityFor(right),
                comparison, visibleScope, filter, regex, negate, sort, isAscending(direction));

        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"))
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.attachment().filename(exportFilename(leftSbom, rightSbom))
                                .build().toString())
                .body(workbook);
    }

    private StoredSbom requireSbom(UUID id) {
        return sboms.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "No such SBOM"));
    }

    private String exportFilename(StoredSbom left, StoredSbom right) {
        return "%s-vs-%s-diff-%s.xlsx".formatted(
                filenameBase(left), filenameBase(right), FILE_TIMESTAMP.format(Instant.now()));
    }

    private String filenameBase(StoredSbom sbom) {
        return sbom.filename().replaceAll("\\.(cdx\\.)?json$", "")
                .replaceAll("[^A-Za-z0-9._-]", "_");
    }

    private boolean isAscending(String direction) {
        return "asc".equalsIgnoreCase(direction);
    }

    private static final DateTimeFormatter FILE_TIMESTAMP =
            DateTimeFormatter.ofPattern("yyyy-MM-dd_HHmmss").withZone(ZoneId.systemDefault());
}
