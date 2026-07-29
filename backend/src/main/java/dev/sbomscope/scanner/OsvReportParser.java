package dev.sbomscope.scanner;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

/**
 * Turns an osv-scanner JSON report into {@link VulnerabilityFinding}s.
 *
 * <p>Findings are built from the report's {@code groups}, not its raw
 * {@code vulnerabilities}: the scanner collapses advisories that alias one another, so a
 * GHSA and the CVE it maps to become one finding rather than two rows describing the same
 * problem.
 */
@Component
public class OsvReportParser {

    private static final Logger log = LoggerFactory.getLogger(OsvReportParser.class);

    private final ObjectMapper objectMapper;

    public OsvReportParser(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * @param purlResolver maps the scanner's ecosystem/name/version identity back to the
     *                     purl of the component we already hold. The report itself does
     *                     not carry purls at the package level.
     * @return findings in report order, at most one per {@link VulnerabilityFinding.Key}
     */
    public List<VulnerabilityFinding> parse(String json, Function<PackageKey, Optional<String>> purlResolver) {
        OsvReport report;
        try {
            report = objectMapper.readValue(json, OsvReport.class);
        } catch (JacksonException e) {
            throw new OsvScannerException("Could not read the scanner's JSON report.", e);
        }

        if (report == null || report.results() == null) {
            return List.of();
        }

        // Keyed rather than appended, because resolving a report package to a purl is
        // many-to-one and the caller stores the result under UNIQUE (purl, osv_id).
        // See collapse() for the two ways the same pair arrives twice.
        Map<VulnerabilityFinding.Key, VulnerabilityFinding> findings = new LinkedHashMap<>();
        for (OsvReport.Result result : report.results()) {
            if (result.packages() == null) {
                continue;
            }
            for (OsvReport.PackageResult packageResult : result.packages()) {
                collapse(findings, findingsFor(packageResult, purlResolver));
            }
        }
        return List.copyOf(findings.values());
    }

    /**
     * Keeps one finding per (purl, advisory), which is what the caller can store.
     *
     * <p>Two independent routes produce the same pair twice, and both are working as
     * intended rather than faults to remove upstream:
     *
     * <ul>
     *   <li><b>One purl, several components.</b> {@code component} is unique on
     *       (sbom_id, bom_ref), not on purl, so one document can legitimately carry the
     *       same library at the same version more than once — npm installs a package at
     *       several paths, and an aggregate Maven BOM covers several modules. The scanner
     *       reads that document and reports the package once per entry.</li>
     *   <li><b>One component, several names.</b> A component is deliberately indexed under
     *       every spelling a generator might use for it — {@code @angular/common} and
     *       {@code @angular:common} both resolve to one purl. That mapping exists because
     *       the alternative was silently discarding real findings.</li>
     * </ul>
     *
     * <p>So the duplication is not a defect in the lookup and cannot be fixed there. It is
     * fixed here, where the pair is assembled, rather than at the call site: {@code parse}
     * returning a list that cannot be stored is this class's problem no matter who consumes
     * it. Storing with a MERGE would also have worked, and was rejected for hiding the
     * condition behind a silent last-one-wins.
     *
     * <p>Colliding findings are normally byte-identical — same advisory, same package, same
     * version. Where they are not, the first is kept and the difference is logged: the
     * descriptive fields depend on the reported package name, so a genuine disagreement
     * means the two spellings resolved to one purl while describing different things, which
     * is worth seeing rather than dropping.
     */
    private void collapse(Map<VulnerabilityFinding.Key, VulnerabilityFinding> collected,
                          List<VulnerabilityFinding> candidates) {

        for (VulnerabilityFinding candidate : candidates) {
            VulnerabilityFinding existing = collected.putIfAbsent(candidate.key(), candidate);
            if (existing != null && !existing.equals(candidate)) {
                log.warn("Two different findings reported for {} {} — keeping the first",
                        candidate.purl(), candidate.osvId());
            }
        }
    }

    /**
     * Identity of a package as the scanner reports it.
     *
     * <p>Normalised on construction so both sides of the lookup agree: the scanner echoes
     * back whatever casing the SBOM declared, and generators are not consistent about it.
     * Doing this in the record rather than at each call site removes the possibility of
     * one side normalising and the other not — which would silently match nothing.
     */
    public record PackageKey(String ecosystem, String name, String version) {

        public PackageKey {
            ecosystem = ecosystem == null ? "" : ecosystem.toLowerCase(java.util.Locale.ROOT);
            name = name == null ? "" : name.toLowerCase(java.util.Locale.ROOT);
            version = version == null ? "" : version;
        }
    }

    private List<VulnerabilityFinding> findingsFor(
            OsvReport.PackageResult packageResult,
            Function<PackageKey, Optional<String>> purlResolver) {

        OsvReport.Package pkg = packageResult.pkg();
        if (pkg == null || packageResult.groups() == null) {
            return List.of();
        }

        Optional<String> purl = purlResolver.apply(
                new PackageKey(pkg.ecosystem(), pkg.name(), pkg.version()));
        if (purl.isEmpty()) {
            // The scanner found something we cannot tie back to a stored component.
            // Dropping it silently would hide a finding, so record it loudly instead.
            log.warn("Scanner reported {} {}:{} which does not match any stored component",
                    pkg.ecosystem(), pkg.name(), pkg.version());
            return List.of();
        }

        Map<String, OsvReport.Vulnerability> byId = indexById(packageResult.vulnerabilities());

        List<VulnerabilityFinding> findings = new ArrayList<>();
        for (OsvReport.Group group : packageResult.groups()) {
            if (group.ids() == null || group.ids().isEmpty()) {
                continue;
            }
            String primaryId = group.ids().getFirst();
            OsvReport.Vulnerability advisory = byId.get(primaryId);

            // Every descriptive field comes from the advisory we actually name, so the row
            // describes one record rather than a blend of several. The score is the
            // exception by design: see attributableSeverity.
            Optional<OsvReport.Severity> severity = attributableSeverity(group, byId);

            findings.add(new VulnerabilityFinding(
                    purl.get(),
                    primaryId,
                    cveFrom(group, advisory),
                    advisory == null ? null : truncate(advisory.summary(), 2000),
                    parseScore(group.maxSeverity()),
                    ratingFrom(advisory),
                    severity.map(OsvReport.Severity::score).orElse(null),
                    severity.map(OsvReport.Severity::type).orElse(null),
                    fixedVersionFor(advisory, pkg),
                    advisory == null ? null : parseInstant(advisory.published())));
        }
        return findings;
    }

    /**
     * The CVSS vector that can honestly be printed beside the group's score, if any.
     *
     * <p>{@code max_severity} is the <em>highest</em> score across every advisory the
     * scanner collapsed into this group, while everything else on the row is read from the
     * one advisory we name. Where the group's members disagree about severity, those two
     * statements come apart: the number is one advisory's, the vector another's, and
     * printing them side by side asserts a relationship that does not hold.
     *
     * <p>Picking the member whose score <em>is</em> the maximum would be the obvious fix,
     * but OSV encodes severity exclusively as CVSS vector strings — only the group carries
     * a number — so identifying it would mean scoring the vectors ourselves. That is a
     * CVSS implementation this project has no reason to own.
     *
     * <p>Instead: the vector is returned only when the group's members agree on it, which
     * makes it unambiguously the vector behind the score. Where they disagree the score
     * still stands — it is the scanner's worst case, which is the safe direction to err in
     * — and the vector is dropped rather than mismatched. Measured against the Maven set
     * (2026-07): 21 of 6,860 advisories sit in a multi-member group at all, and 11 of those
     * pairs disagree on the vector.
     */
    private Optional<OsvReport.Severity> attributableSeverity(
            OsvReport.Group group, Map<String, OsvReport.Vulnerability> byId) {

        OsvReport.Severity agreed = null;
        for (String id : group.ids()) {
            Optional<OsvReport.Severity> candidate = severityOf(byId.get(id));
            if (candidate.isEmpty()) {
                continue;
            }
            if (agreed == null) {
                agreed = candidate.get();
            } else if (!agreed.equals(candidate.get())) {
                return Optional.empty();
            }
        }
        return Optional.ofNullable(agreed);
    }

    private Map<String, OsvReport.Vulnerability> indexById(List<OsvReport.Vulnerability> vulnerabilities) {
        Map<String, OsvReport.Vulnerability> byId = new LinkedHashMap<>();
        if (vulnerabilities != null) {
            for (OsvReport.Vulnerability vulnerability : vulnerabilities) {
                if (vulnerability.id() != null) {
                    byId.put(vulnerability.id(), vulnerability);
                }
            }
        }
        return byId;
    }

    /** Prefers the group's aliases, which already merge the advisory's own alias list. */
    private String cveFrom(OsvReport.Group group, OsvReport.Vulnerability advisory) {
        String fromGroup = firstCve(group.aliases());
        if (fromGroup != null) {
            return fromGroup;
        }
        return advisory == null ? null : firstCve(advisory.aliases());
    }

    private String firstCve(List<String> candidates) {
        if (candidates == null) {
            return null;
        }
        return candidates.stream()
                .filter(id -> id != null && id.startsWith("CVE-"))
                .findFirst()
                .orElse(null);
    }

    private Optional<OsvReport.Severity> severityOf(OsvReport.Vulnerability advisory) {
        if (advisory == null || advisory.severity() == null || advisory.severity().isEmpty()) {
            return Optional.empty();
        }
        return Optional.ofNullable(advisory.severity().getFirst());
    }

    private String ratingFrom(OsvReport.Vulnerability advisory) {
        if (advisory == null || advisory.databaseSpecific() == null) {
            return null;
        }
        return advisory.databaseSpecific().severity();
    }

    private BigDecimal parseScore(String maxSeverity) {
        if (maxSeverity == null || maxSeverity.isBlank()) {
            return null;
        }
        try {
            return new BigDecimal(maxSeverity.trim());
        } catch (NumberFormatException e) {
            log.debug("Unparseable max_severity '{}'", maxSeverity);
            return null;
        }
    }

    /**
     * The fix on <em>this</em> component's own release branch.
     *
     * <p>An advisory routinely covers several coordinates and several parallel branches. Two
     * different mistakes are possible, and both have been made here:
     *
     * <ul>
     *   <li>Taking a fix belonging to a <em>different package</em> — the Jackson advisory
     *       lists fixes for {@code com.fasterxml.jackson.core} and {@code tools.jackson.core}
     *       alike, and offering the wrong one names a version that does not exist for the
     *       library in use.</li>
     *   <li>Taking a fix belonging to a <em>different branch of the same package</em> — the
     *       Angular advisory lists fixes on 22.x, 21.x and 20.x plus a 19.x line with no fix
     *       at all. Reading them in order told someone on 19.2.17 to upgrade to 22.0.1,
     *       crossing three majors to a branch their advisory never mentions.</li>
     * </ul>
     *
     * <p>So the branch is chosen first, then its fix is read. Where the branch says only
     * {@code last_affected}, there genuinely is no fix on it, and null is the honest answer —
     * that is a real finding about the version in use, not a gap in the data.
     */
    private String fixedVersionFor(OsvReport.Vulnerability advisory, OsvReport.Package pkg) {
        if (advisory == null || advisory.affected() == null) {
            return null;
        }

        List<OsvReport.Affected> candidates = advisory.affected().stream()
                .filter(affected -> affected.pkg() != null && matches(affected.pkg(), pkg))
                .toList();

        if (candidates.isEmpty()) {
            return null;
        }
        // One branch for this package: nothing to disambiguate.
        if (candidates.size() == 1) {
            return firstFixIn(candidates.getFirst());
        }

        // An explicit enumeration settles it by string equality, with no ordering guesswork.
        for (OsvReport.Affected affected : candidates) {
            if (affected.versions() != null && affected.versions().contains(pkg.version())) {
                return firstFixIn(affected);
            }
        }

        for (OsvReport.Affected affected : candidates) {
            if (covers(affected, pkg.version())) {
                return firstFixIn(affected);
            }
        }

        // Several branches, none of which we can place this version in. Naming one of their
        // fixes would be a guess, and a confident-looking wrong upgrade target is worse than
        // saying nothing.
        log.debug("No affected branch of {} covers {} {}", advisory.id(), pkg.name(), pkg.version());
        return null;
    }

    /**
     * Whether an affected entry's ranges contain the given version.
     *
     * <p>Delegated to {@link AffectedVersions}, which the local matcher reads too. Two
     * statements of version-range semantics would drift, and the direction they would drift
     * in is "this upgrade is clean" against "this upgrade is not".
     */
    private boolean covers(OsvReport.Affected affected, String version) {
        return AffectedVersions.coveredByRanges(affected, version);
    }

    private String firstFixIn(OsvReport.Affected affected) {
        if (affected.ranges() == null) {
            return null;
        }
        for (OsvReport.Range range : affected.ranges()) {
            if (range.events() == null) {
                continue;
            }
            for (OsvReport.Event event : range.events()) {
                if (event.fixed() != null && !event.fixed().isBlank()) {
                    return event.fixed();
                }
            }
        }
        return null;
    }

    private boolean matches(OsvReport.Package affected, OsvReport.Package scanned) {
        return affected.name() != null
                && affected.name().equalsIgnoreCase(scanned.name())
                && (affected.ecosystem() == null
                    || scanned.ecosystem() == null
                    || affected.ecosystem().equalsIgnoreCase(scanned.ecosystem()));
    }

    private Instant parseInstant(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException e) {
            log.debug("Unparseable timestamp '{}'", value);
            return null;
        }
    }

    private String truncate(String value, int max) {
        if (value == null) {
            return null;
        }
        return value.length() <= max ? value : value.substring(0, max);
    }
}
