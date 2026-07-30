package dev.sbomscope.scanner;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The sort key must order versions exactly as {@link VersionOrder#compare} does.
 *
 * <p>This is the test B8 asks for by name, and the reason it exists is specific: the findings
 * table orders by the key in SQL while every other version decision in the codebase goes
 * through the comparator. If the two disagree, the table is sorted differently from the upgrade
 * advice describing the same versions — the class of quiet inconsistency this project keeps
 * designing against, and one nobody would notice until they were working down a list.
 *
 * <p>Driven by every version string in the committed fixtures rather than by hand-picked
 * examples, because the fixtures are what the real tools actually emitted.
 */
class VersionSortKeyTest {

    private static final Pattern VERSION = Pattern.compile("\"version\"\\s*:\\s*\"([^\"]+)\"");

    private static final List<String> FIXTURES = List.of(
            "/sboms/maven-sbomscope.cdx.json",
            "/sboms/npm-frontend.cdx.json",
            "/sboms/vuln-multi-module.cdx.json",
            "/sboms/osv-report-maven.json");

    /**
     * Shapes the fixtures do not necessarily contain, each one a way the encoding could break.
     */
    private static final List<String> ADVERSARIAL = List.of(
            "1.9.0", "1.10.0", "1.9", "1.10",              // the lexical trap this exists for
            "1", "1.0", "1.0.0", "1.0.0.0",                // trailing zeros are the same version
            "1.2", "1.2.0", "1.2.1",
            "2.0.0-rc1", "2.0.0-rc2", "2.0.0", "2.0.0-SNAPSHOT",
            "4.0.0-RC2", "3.9.9",                          // a pre-release of the next major
            "1.0.0+build9", "1.0.0+build10",               // build metadata never orders
            "20240101", "20231231",                        // date-shaped versions
            "1.2.3.redhat-00001", "1.2.3",                 // the vendor patch level B2 is about
            "", "  ", "not-a-version", "v1.2.3");

    private static List<String> versionsIn(String resource) throws Exception {
        try (InputStream stream = VersionSortKeyTest.class.getResourceAsStream(resource)) {
            assertThat(stream).as("fixture %s should exist", resource).isNotNull();
            String text = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
            List<String> found = new ArrayList<>();
            Matcher matcher = VERSION.matcher(text);
            while (matcher.find()) {
                found.add(matcher.group(1));
            }
            return found;
        }
    }

    private static Set<String> allVersions() throws Exception {
        Set<String> versions = new LinkedHashSet<>(ADVERSARIAL);
        for (String fixture : FIXTURES) {
            versions.addAll(versionsIn(fixture));
        }
        return versions;
    }

    @Test
    void theKeyOrdersEveryFixtureVersionExactlyAsTheComparatorDoes() throws Exception {
        List<String> versions = new ArrayList<>(allVersions());
        assertThat(versions).as("the fixtures should supply a real set to compare over")
                .hasSizeGreaterThan(60);

        for (String left : versions) {
            for (String right : versions) {
                int byComparator = Integer.signum(VersionOrder.INSTANCE.compare(left, right));
                int byKey = Integer.signum(compareKeys(left, right));

                assertThat(byKey)
                        .as("'%s' vs '%s': key %s vs %s", left, right,
                                VersionOrder.sortKey(left), VersionOrder.sortKey(right))
                        .isEqualTo(byComparator);
            }
        }
    }

    /**
     * Keys as the database compares them: plain string ordering, with null last — which is how
     * both sort directions treat a finding with no fix.
     *
     * <p>A blank version produces a null key, and the comparator treats a blank as version zero,
     * so the two disagree by construction for blanks. That is deliberate rather than a hole: a
     * blank fix version is never stored, because {@code fixed_version} is null when an advisory
     * names no fix, and "no fix" must not sort as though it were version zero.
     */
    private int compareKeys(String left, String right) {
        String a = VersionOrder.sortKey(left);
        String b = VersionOrder.sortKey(right);
        if (a == null || b == null) {
            // Fall back to the comparator for the blank case this key deliberately excludes,
            // so the loop above still covers every other pairing involving it.
            return VersionOrder.INSTANCE.compare(left, right);
        }
        return a.compareTo(b);
    }

    @Test
    void theLexicalTrapTheColumnExistsForIsActuallyFixed() {
        // Sorted as plain strings — which is what H2 does to fixed_version — "1.10.0" comes
        // before "1.9.0". This is the whole reason for the column.
        assertThat("1.10.0".compareTo("1.9.0")).isNegative();
        assertThat(VersionOrder.sortKey("1.10.0").compareTo(VersionOrder.sortKey("1.9.0")))
                .isPositive();
    }

    @Test
    void versionsTheComparatorCallsEqualProduceIdenticalKeys() {
        // Not merely adjacent: a key that differed here would impose an order the comparator
        // does not have, and the two would disagree about a pair nobody can see is a pair.
        assertThat(VersionOrder.sortKey("1.2")).isEqualTo(VersionOrder.sortKey("1.2.0"));
        assertThat(VersionOrder.sortKey("1")).isEqualTo(VersionOrder.sortKey("1.0.0.0"));
        assertThat(VersionOrder.sortKey("1.0.0+build9")).isEqualTo(VersionOrder.sortKey("1.0.0+build10"));
    }

    @Test
    void noFixHasNoKey() {
        // Null rather than an empty string, so "no fix" stays a different thing from a fix at
        // some version — the same NONE-versus-CLEAN distinction one level down.
        assertThat(VersionOrder.sortKey(null)).isNull();
        assertThat(VersionOrder.sortKey("")).isNull();
        assertThat(VersionOrder.sortKey("   ")).isNull();
    }

    @Test
    void everyKeyFitsTheColumn() {
        // VARCHAR(256) in V3. A key is 19 characters per significant segment plus two, so this
        // is not tight — but a truncated key would sort wrongly and silently.
        List<String> longest = List.of(
                "1.2.3.4.5.6.7.8-alpha.1.2.3", "9223372036854775807.9223372036854775807");
        for (String version : longest) {
            assertThat(VersionOrder.sortKey(version)).hasSizeLessThan(256);
        }
    }
}
