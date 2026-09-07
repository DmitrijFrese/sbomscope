package dev.sbomscope.probe;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link MavenInvocation.Result}'s reading of a failed Maven run.
 *
 * <p>The fixtures are real output captured on 2026-09-07, not hand-written: the point of both
 * methods is to survive what Maven actually prints, including the four lines of advice it ends
 * every failure with.
 */
class MavenInvocationTest {

    /** Verbatim from a linkage classpath resolution run without the truststore flag. */
    private static final String PKIX_OUTPUT = """
            [INFO] Scanning for projects...
            [INFO] Downloading from central: https://repo.maven.apache.org/maven2/org/apache/maven/plugins/maven-dependency-plugin/3.7.0/maven-dependency-plugin-3.7.0.pom
            [INFO] ------------------------------------------------------------------------
            [INFO] BUILD FAILURE
            [INFO] ------------------------------------------------------------------------
            [ERROR] Plugin org.apache.maven.plugins:maven-dependency-plugin:3.7.0 or one of its dependencies could not be resolved:
            [ERROR] \tThe following artifacts could not be resolved: org.apache.maven.plugins:maven-dependency-plugin:pom:3.7.0 (absent): Could not transfer artifact org.apache.maven.plugins:maven-dependency-plugin:pom:3.7.0 from/to central (https://repo.maven.apache.org/maven2): (certificate_unknown) PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target
            [ERROR] -> [Help 1]
            [ERROR]\s
            [ERROR] To see the full stack trace of the errors, re-run Maven with the -e switch.
            [ERROR] Re-run Maven using the -X switch to enable full debug logging.
            [ERROR]\s
            [ERROR] For more information about the errors and possible solutions, please read the following articles:
            [ERROR] [Help 1] http://cwiki.apache.org/confluence/display/MAVEN/PluginResolutionException
            """;

    private static final String MISSING_ARTIFACT_OUTPUT = """
            [INFO] Scanning for projects...
            [INFO] BUILD FAILURE
            [ERROR] Failed to execute goal on project probe: Could not resolve dependencies: com.example:nope:jar:9.9.9 was not found
            [ERROR] -> [Help 1]
            [ERROR] To see the full stack trace of the errors, re-run Maven with the -e switch.
            """;

    private static MavenInvocation.Result failed(String output) {
        return new MavenInvocation.Result(false, false, 1, output, null);
    }

    @Test
    void leadsWithMavensOwnSummaryRatherThanItsClosingAdvice() {
        assertThat(failed(PKIX_OUTPUT).lastMeaningfulLine())
                .startsWith("[ERROR] Plugin org.apache.maven.plugins:maven-dependency-plugin")
                .doesNotContain("cwiki.apache.org")
                .doesNotContain("-e switch");
    }

    /**
     * The translation this exists for. A TLS trust failure arrives naming Maven Central and an
     * artifact, so it reads as a bad dependency version; nothing about the dependency set fixes
     * it, and a message that only quotes Maven sends the reader to look in the wrong place.
     */
    @Test
    void namesATlsTrustFailureAsOneAndSaysWhereItComesFrom() {
        String summary = failed(PKIX_OUTPUT).failureSummary();

        assertThat(summary)
                .contains("TLS trust failure")
                .contains("not a problem with the dependency versions")
                .contains("MAVEN_OPTS")
                .contains("-Djavax.net.ssl.trustStoreType=Windows-ROOT");
    }

    @Test
    void leavesAnOrdinaryFailureUntranslated() {
        String summary = failed(MISSING_ARTIFACT_OUTPUT).failureSummary();

        assertThat(summary)
                .contains("com.example:nope:jar:9.9.9 was not found")
                .doesNotContain("TLS")
                .doesNotContain("MAVEN_OPTS");
    }

    @Test
    void reportsAStartFailureWithoutInventingOutput() {
        MavenInvocation.Result result =
                new MavenInvocation.Result(true, false, -1, "", "program not found");

        assertThat(result.lastMeaningfulLine()).isEqualTo("program not found");
        assertThat(result.failureSummary()).isEqualTo("program not found");
    }
}
