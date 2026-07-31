package dev.sbomscope.api;

import java.io.IOException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import dev.sbomscope.export.ExportColumn;
import dev.sbomscope.export.ExportDescription;
import dev.sbomscope.export.FindingsExcelExporter;
import dev.sbomscope.sbom.SbomService;
import dev.sbomscope.sbom.StoredSbom;
import dev.sbomscope.scanner.ScanService;
import dev.sbomscope.scanner.FindingQuery;
import dev.sbomscope.settings.SettingsService;

@RestController
@RequestMapping("/api/sboms/{id}")
class ScanController {

    private final ScanService scans;
    private final SbomService sboms;
    private final SettingsService settings;
    private final FindingsExcelExporter exporter;

    ScanController(ScanService scans, SbomService sboms, SettingsService settings,
                   FindingsExcelExporter exporter) {
        this.scans = scans;
        this.sboms = sboms;
        this.settings = settings;
        this.exporter = exporter;
    }

    /**
     * @param scannedComponents  how many of the SBOM's components carry a scan record;
     *                           zero means never scanned, which is not the same as clean
     * @param totalComponents    everything in the SBOM, so a partial scan is visible
     * @param stale              results are old enough to be worth refreshing. Also true
     *                           when nothing has ever been scanned, because "no findings"
     *                           must never be mistaken for "no vulnerabilities"
     * @param scanningEnabled    false when the scanner is switched off, which is why a
     *                           findings list may legitimately be empty
     */
    record ScanStatusResponse(
            Instant lastScannedAt,
            int scannedComponents,
            int totalComponents,
            boolean stale,
            /**
             * <em>Why</em> it is stale, so the notice can say which of two different things
             * happened. {@code ARCHIVE_REFRESHED} is a fact about this machine — a newer
             * archive is on disk than these results were produced against — where
             * {@code AGED} is only the seven-day clock. Offering the second sentence for the
             * first situation sends the reader to look at the wrong thing.
             */
            ScanService.StaleReason staleReason,
            long staleAfterDays,
            boolean scanningEnabled,
            /**
             * Whether a scan could actually run, which is a stronger statement than
             * {@code scanningEnabled}: the binary may have moved and the OSV archive for
             * this SBOM's ecosystems may be absent. Lets the UI explain the obstacle
             * instead of offering a button that fails.
             */
            ScanService.ScanReadiness readiness,
            /** Vulnerabilities across the whole SBOM, ignoring every filter. */
            int findingCount,
            /**
             * The same total broken down by band, so the parts add up to {@code findingCount}.
             * Also unfiltered — a summary that moved with the filter would describe the view
             * rather than the SBOM, which is the opposite of what a headline is for.
             */
            Map<FindingQuery.SeverityBand, Integer> severityCounts,
            /** Rows matching the current filter — the size an unpaged export would have. */
            int filteredCount,
            /** The requested page only. */
            List<RowResponse> rows) {}

    record ScanRunResponse(int componentsScanned, int findings, Instant scannedAt, String scannerVersion) {}

    private void requireSbom(UUID id) {
        if (sboms.findById(id).isEmpty()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "No such SBOM");
        }
    }

    @PostMapping("/scan")
    ScanRunResponse scan(@PathVariable UUID id) {
        requireSbom(id);
        ScanService.ScanResult result = scans.scan(id);
        return new ScanRunResponse(
                result.componentsScanned(), result.findings(), result.scannedAt(), result.scannerVersion());
    }

    /**
     * Exports findings as a real .xlsx.
     *
     * <p>The ordering is carried over from the view rather than re-decided here, and both
     * come from the same query, so the spreadsheet cannot be sorted differently from the
     * screen it was produced from.
     *
     * @param scope {@code visible} exports exactly the rows on screen — same filter, same
     *              page. {@code all} exports every finding, still in the view's order.
     *              The UI labels both with their row counts, because silently dropping
     *              rows from a vulnerability report would be the worst possible default.
     */
    @GetMapping("/export.xlsx")
    ResponseEntity<byte[]> export(
            @PathVariable UUID id,
            @RequestParam(value = "sort", defaultValue = "SEVERITY") FindingQuery.SortField sort,
            @RequestParam(value = "direction", defaultValue = "desc") String direction,
            @RequestParam(value = "scope", defaultValue = "all") String scope,
            @RequestParam(value = "filter", required = false) String filter,
            @RequestParam(value = "regex", defaultValue = "false") boolean regex,
            @RequestParam(value = "negate", defaultValue = "false") boolean negate,
            @RequestParam(value = "severity", required = false) List<String> severity,
            @RequestParam(value = "scope_filter", required = false) List<String> scopeFilter,
            @RequestParam(value = "column", required = false) List<String> column,
            @RequestParam(value = "limit", required = false) Integer limit,
            @RequestParam(value = "offset", required = false) Integer offset) throws IOException {

        StoredSbom sbom = sboms.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "No such SBOM"));

        // Named scope_filter, not scope: `scope` is already this endpoint's visible/all
        // selector, and two meanings on one parameter name is how an export silently
        // stops matching the screen it came from.
        FindingQuery onScreen = new FindingQuery(sort, isAscending(direction), filter, regex, negate,
                FindingQuery.SeverityBand.parse(severity),
                FindingQuery.parseScopes(scopeFilter), limit, offset);

        // "visible" reproduces the screen exactly; "all" keeps the ordering and the
        // severity selection but drops the text filter and paging.
        boolean visibleScope = "visible".equalsIgnoreCase(scope);
        FindingQuery query = visibleScope ? onScreen : onScreen.unfiltered();

        // The browser always sends the columns it is showing; whether they narrow the
        // workbook is a setting, so the choice lives in one place rather than being decided
        // differently by each caller. Default is every column: a spreadsheet has no width
        // pressure, and a recipient cannot recover a column dropped before they got it.
        List<ExportColumn> columns = settings.exportSettings().visibleColumnsOnly()
                ? ExportColumn.parse(column)
                : ExportColumn.all();

        byte[] workbook = exporter.export(
                sbom, scans.rows(id, query), scans.lastScannedAt(id).orElse(null),
                columns, ExportDescription.of(visibleScope, query, columns));

        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"))
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.attachment().filename(exportFilename(sbom)).build().toString())
                .body(workbook);
    }

    /**
     * Derived from the SBOM name and stamped to the second.
     *
     * <p>A date alone collided as soon as you exported twice in one day — which is the
     * normal case when narrowing a filter — leaving the browser to append "(1)", "(2)" and
     * no way to tell which was which. Colons are illegal in Windows filenames, so the time
     * is written without them; the format still sorts chronologically.
     */
    private String exportFilename(StoredSbom sbom) {
        String base = sbom.filename().replaceAll("\\.(cdx\\.)?json$", "").replaceAll("[^A-Za-z0-9._-]", "_");
        return "%s-findings-%s.xlsx".formatted(base, FILE_TIMESTAMP.format(Instant.now()));
    }

    private static final DateTimeFormatter FILE_TIMESTAMP =
            DateTimeFormatter.ofPattern("yyyy-MM-dd_HHmmss").withZone(ZoneId.systemDefault());

    @GetMapping("/findings")
    ScanStatusResponse findings(
            @PathVariable UUID id,
            @RequestParam(value = "sort", defaultValue = "SEVERITY") FindingQuery.SortField sort,
            @RequestParam(value = "direction", defaultValue = "desc") String direction,
            @RequestParam(value = "filter", required = false) String filter,
            /** Whether {@code filter} is a regular expression. Off unless the reader says so. */
            @RequestParam(value = "regex", defaultValue = "false") boolean regex,
            @RequestParam(value = "negate", defaultValue = "false") boolean negate,
            @RequestParam(value = "severity", required = false) List<String> severity,
            @RequestParam(value = "scope", required = false) List<String> scope,
            @RequestParam(value = "limit", required = false) Integer limit,
            @RequestParam(value = "offset", required = false) Integer offset) {

        requireSbom(id);

        FindingQuery query = new FindingQuery(sort, isAscending(direction), filter, regex, negate,
                FindingQuery.SeverityBand.parse(severity),
                FindingQuery.parseScopes(scope), limit, offset);

        // One call, then both fields derived from it: asking isStale() separately would query
        // the same thing twice and let the flag and the reason disagree mid-request.
        ScanService.StaleReason staleReason = scans.staleReason(id);

        return new ScanStatusResponse(
                scans.lastScannedAt(id).orElse(null),
                scans.scannedComponentCount(id),
                sboms.findComponents(id).size(),
                staleReason != ScanService.StaleReason.NONE,
                staleReason,
                scans.staleAfterDays(),
                settings.scannerSettings().enabled(),
                scans.readiness(id),
                // Vulnerability count ignores the filter entirely, so the headline
                // "n of m components affected" stays true whatever is being viewed.
                scans.countFindings(id, FindingQuery.defaults()),
                scans.countsByBand(id),
                scans.countRows(id, query.withoutPaging()),
                scans.rows(id, query).stream().map(RowResponse::from).toList());
    }

    private boolean isAscending(String direction) {
        return "asc".equalsIgnoreCase(direction);
    }
}
