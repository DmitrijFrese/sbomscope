package dev.sbomscope.scanner;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Evaluating a version the user does not have, against the downloaded archives.
 *
 * <p>Built over a purpose-made archive rather than the real 10 MB one, because the cases
 * worth pinning are the two ways OSV describes an affected version — an explicit
 * enumeration and a range — and a real export cannot be asked to contain a chosen pair of
 * them. The document shape is copied from a real entry: flat {@code <id>.json} members in
 * OSV schema 1.7.3.
 *
 * <p>The property that matters most is the negative one. An empty result is what a caller
 * reads as "this upgrade is clean", so a matcher that silently found nothing — wrong path,
 * unparsed entries, mismatched casing — would be indistinguishable from good news.
 */
@SpringBootTest
@Transactional
class OsvArchiveMatcherTest {

    @TempDir
    Path databaseDirectory;

    @Autowired
    private OsvArchiveMatcher matcher;

    private static final String RANGE_ADVISORY = """
            {"schema_version":"1.7.3","id":"GHSA-by-range","aliases":["CVE-2026-1111"],
             "database_specific":{"severity":"HIGH"},
             "affected":[{"package":{"ecosystem":"Maven","name":"com.example:lib"},
               "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}""";

    private static final String VERSIONS_ADVISORY = """
            {"schema_version":"1.7.3","id":"GHSA-by-versions","aliases":["CVE-2026-2222"],
             "database_specific":{"severity":"MODERATE"},
             "affected":[{"package":{"ecosystem":"Maven","name":"com.example:lib"},
               "versions":["1.5.0"]}]}""";

    /** A second package, so a hit has to be attributable rather than merely present. */
    private static final String OTHER_PACKAGE_ADVISORY = """
            {"schema_version":"1.7.3","id":"GHSA-elsewhere","aliases":["CVE-2026-3333"],
             "database_specific":{"severity":"CRITICAL"},
             "affected":[{"package":{"ecosystem":"Maven","name":"com.example:other"},
               "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}""";

    @BeforeEach
    void writeArchiveAndIndexIt() throws Exception {
        Path archive = databaseDirectory.resolve(Path.of("osv-scanner", "Maven", "all.zip"));
        Files.createDirectories(archive.getParent());

        Map<String, String> entries = Map.of(
                "GHSA-by-range.json", RANGE_ADVISORY,
                "GHSA-by-versions.json", VERSIONS_ADVISORY,
                "GHSA-elsewhere.json", OTHER_PACKAGE_ADVISORY);

        try (OutputStream out = Files.newOutputStream(archive);
             ZipOutputStream zip = new ZipOutputStream(out)) {
            for (Map.Entry<String, String> entry : entries.entrySet()) {
                zip.putNextEntry(new ZipEntry(entry.getKey()));
                zip.write(entry.getValue().getBytes(StandardCharsets.UTF_8));
                zip.closeEntry();
            }
        }

        matcher.buildIndex(databaseDirectory.toString(), "Maven", advisories -> { });
    }

    private List<String> idsFor(String version) {
        return matcher.advisoriesFor(databaseDirectory.toString(), "Maven", "com.example:lib", version)
                .stream()
                .map(OsvArchiveMatcher.AdvisoryHit::osvId)
                .toList();
    }

    @Test
    void findsAnAdvisoryWhoseRangeCoversTheVersion() {
        assertThat(idsFor("1.0.0")).containsExactly("GHSA-by-range");
    }

    @Test
    void findsAnAdvisoryThatEnumeratesTheVersionExplicitly() {
        // Both apply at 1.5.0: the range still covers it and the enumeration names it.
        assertThat(idsFor("1.5.0")).containsExactlyInAnyOrder("GHSA-by-range", "GHSA-by-versions");
    }

    @Test
    void aFixedVersionIsNotAffected() {
        // The question the whole matcher exists to answer, and the answer a caller acts on.
        assertThat(idsFor("2.0.0")).isEmpty();
    }

    @Test
    void doesNotAttributeAnotherPackagesAdvisory() {
        // An advisory in the same archive against a different coordinate must not leak in —
        // the mistake fixedVersionFor was written to avoid, one layer down.
        assertThat(idsFor("1.0.0")).doesNotContain("GHSA-elsewhere");
    }

    @Test
    void carriesTheAdvisorysOwnRatingAndCve() {
        // A GHSA rating, never a CVSS score: OSV stores severity as vector strings, and the
        // numbers elsewhere came from the scanner, which only ran on what is installed.
        OsvArchiveMatcher.AdvisoryHit hit = matcher
                .advisoriesFor(databaseDirectory.toString(), "Maven", "com.example:lib", "1.0.0")
                .getFirst();

        assertThat(hit.cveId()).isEqualTo("CVE-2026-1111");
        assertThat(hit.rating()).isEqualTo("HIGH");
    }

    @Test
    void matchesTheNameWhateverCasingTheArchiveUsed() {
        assertThat(matcher.advisoriesFor(
                databaseDirectory.toString(), "Maven", "COM.Example:Lib", "1.0.0")).hasSize(1);
    }

    @Test
    void reportsThatItCannotEvaluateWithoutAnIndex() {
        // The distinction every caller depends on: "not indexed" must not read as "clean".
        assertThat(matcher.isIndexed(databaseDirectory.toString(), "Maven")).isTrue();
        assertThat(matcher.isIndexed(databaseDirectory.toString(), "npm")).isFalse();
        assertThat(matcher.advisoriesFor(databaseDirectory.toString(), "npm", "left-pad", "1.0.0"))
                .isEmpty();
    }

    @Test
    void aReplacedArchiveInvalidatesItsIndexWithoutBeingTold() throws Exception {
        // Identity is size and modification time, so a refreshed download stops the stale
        // index answering for it — nobody has to remember to invalidate, which is exactly
        // the kind of thing nobody remembers.
        assertThat(matcher.isIndexed(databaseDirectory.toString(), "Maven")).isTrue();

        Path archive = databaseDirectory.resolve(Path.of("osv-scanner", "Maven", "all.zip"));
        Files.write(archive, "not a zip any more, and a different size".getBytes(StandardCharsets.UTF_8));

        assertThat(matcher.isIndexed(databaseDirectory.toString(), "Maven")).isFalse();
        assertThat(idsFor("1.0.0")).isEmpty();
    }

    @Test
    void recordsWhatWasIndexedAndFromWhere() {
        assertThat(matcher.indexStatus("Maven")).hasValueSatisfying(source -> {
            assertThat(source.advisories()).isEqualTo(3);
            assertThat(source.packages()).as("two coordinates across three advisories").isEqualTo(3);
            assertThat(source.identity()).contains("all.zip");
        });
    }
}
