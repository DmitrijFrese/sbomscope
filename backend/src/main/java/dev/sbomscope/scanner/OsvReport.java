package dev.sbomscope.scanner;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Wire-format mapping for osv-scanner's {@code --format json} report.
 *
 * <p>Only the fields SBOMscope reads are modelled; the advisory objects carry a great
 * deal more that is ignored rather than mapped.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
record OsvReport(List<Result> results) {

    @JsonIgnoreProperties(ignoreUnknown = true)
    record Result(Source source, List<PackageResult> packages) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    record Source(String path, String type) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    record PackageResult(
            @JsonProperty("package") Package pkg,
            List<Vulnerability> vulnerabilities,
            List<Group> groups) {}

    /** Note: carries no purl — identity here is ecosystem plus name plus version. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    record Package(String name, String version, String ecosystem) {}

    /**
     * Advisories that alias one another, collapsed into a single finding.
     *
     * @param ids         every id in the group; the first is treated as primary
     * @param aliases     ids and their aliases combined, which is where the CVE appears
     * @param maxSeverity numeric CVSS score already computed by the scanner, as a string
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    record Group(
            List<String> ids,
            List<String> aliases,
            @JsonProperty("max_severity") String maxSeverity) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    record Vulnerability(
            String id,
            List<String> aliases,
            String summary,
            String published,
            List<Severity> severity,
            List<Affected> affected,
            @JsonProperty("database_specific") DatabaseSpecific databaseSpecific) {}

    /** {@code score} is a CVSS vector string, never a number. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    record Severity(String type, String score) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    record DatabaseSpecific(String severity) {}

    /**
     * @param versions explicit enumeration of affected versions. Present on around 90% of
     *                 the Maven set and rarely on npm, where ranges do the work instead.
     *                 Preferred when available: matching it is string equality, with none of
     *                 the version-ordering guesswork a range needs.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    record Affected(
            @JsonProperty("package") Package pkg,
            List<Range> ranges,
            List<String> versions) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    record Range(String type, List<Event> events) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    record Event(
            String introduced,
            String fixed,
            @JsonProperty("last_affected") String lastAffected) {}
}
