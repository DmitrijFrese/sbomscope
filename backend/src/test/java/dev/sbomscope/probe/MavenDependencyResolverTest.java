package dev.sbomscope.probe;

import org.junit.jupiter.api.Test;

import dev.sbomscope.logging.ActivityLogger;

import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@code dependency:tree}'s text output is scanned for a specific artifact's line rather than
 * parsed into a tree structure — the generated POM declares exactly one dependency, so the
 * resolved tree is that dependency's whole subtree, and only "is X present, at what version"
 * is ever asked.
 */
class MavenDependencyResolverTest {

    private final MavenDependencyResolver resolver = new MavenDependencyResolver(new ActivityLogger(new ObjectMapper()));

    /** A real shape: the generated root, one direct dependency, and a transitive one below it. */
    private static final String TREE = String.join("\n",
            "dev.sbomscope.probe:probe:pom:0",
            "\\- com.acme:module-a:jar:4.2.0:compile",
            "   \\- com.fasterxml.jackson.core:jackson-databind:jar:3.1.6:compile");

    /**
     * The real output from a machine whose security software inspects HTTPS, abridged.
     *
     * <p>Kept verbatim rather than reduced to the one matching phrase, because the trap it
     * documents is that this text contains <em>both</em> signatures: Maven says "Could not
     * transfer artifact" here exactly as it does for an artifact that genuinely does not exist.
     */
    private static final String PKIX_OUTPUT = String.join("\n",
            "[ERROR] Failed to execute goal on project probe: Could not collect dependencies for "
                    + "project dev.sbomscope.probe:probe:pom:0",
            "[ERROR] Failed to read artifact descriptor for com.h2database:h2:jar:2.4.240",
            "[ERROR] \tCaused by: The following artifacts could not be resolved: "
                    + "com.h2database:h2:pom:2.4.240 (absent): Could not transfer artifact "
                    + "com.h2database:h2:pom:2.4.240 from/to central "
                    + "(https://repo.maven.apache.org/maven2): (certificate_unknown) PKIX path "
                    + "building failed: sun.security.provider.certpath.SunCertPathBuilderException: "
                    + "unable to find valid certification path to requested target",
            "[ERROR] -> [Help 1]");

    private static MavenInvocation.Result failedWith(String output) {
        return new MavenInvocation.Result(false, false, 1, output, null);
    }

    @Test
    void theReportedDetailIsMavensSummaryNotItsClosingWikiLink() {
        // Found in the same live run. The detail read "[ERROR] [Help 1] http://cwiki.apache.org/…",
        // because the line was picked from the end — right for osv-scanner, whose errors do come
        // last, and exactly wrong for Maven, which closes every failure with four lines of advice.
        assertThat(failedWith(PKIX_OUTPUT).lastMeaningfulLine())
                .startsWith("[ERROR] Failed to execute goal on project probe")
                .doesNotContain("cwiki.apache.org");
    }

    @Test
    void fallsBackToTheLastLineWhenMavenPrintedNoErrorAtAll() {
        // A goal can fail with output that carries no [ERROR] marker; a wrong-but-present line
        // still beats an empty message.
        assertThat(failedWith("something went sideways").lastMeaningfulLine())
                .isEqualTo("something went sideways");
    }

    @Test
    void anUntrustedCertificateIsNotAMissingArtifact() {
        // Found live. The panel reported "Not found in any configured repository" for an
        // artifact sitting in Central, because the PKIX failure's own wording matches the
        // absence test — which sent the reader to add a repository when the fix is a truststore.
        assertThat(resolver.classifyFailure(failedWith(PKIX_OUTPUT)).failureReason())
                .isEqualTo(ProbeFailureReason.REPOSITORY_UNREACHABLE);
    }

    @Test
    void anArtifactThatGenuinelyDoesNotExistIsStillNotFound() {
        // The other half: the reordering must not swallow the case NOT_FOUND exists for.
        String absent = "[ERROR] Failed to execute goal on project probe: Could not resolve "
                + "dependencies for project dev.sbomscope.probe:probe:pom:0: Could not find "
                + "artifact com.acme:module-a:jar:9.9.9 in central";
        assertThat(resolver.classifyFailure(failedWith(absent)).failureReason())
                .isEqualTo(ProbeFailureReason.NOT_FOUND);
    }

    @Test
    void aPluginItCannotObtainStillOutranksBoth() {
        // Ordering runs plugin, then unreachable, then absent. A machine with no route to any
        // repository produces plugin-resolution text *and* transfer text in one run, and the
        // plugin problem is the one that has to be reported: nothing else could have happened.
        String pluginFailure = "[ERROR] Plugin org.apache.maven.plugins:maven-dependency-plugin:3.6.1 "
                + "or one of its dependencies could not be resolved: Could not transfer artifact "
                + "... PKIX path building failed";
        assertThat(resolver.classifyFailure(failedWith(pluginFailure)).failureReason())
                .isEqualTo(ProbeFailureReason.PLUGIN_UNAVAILABLE);
    }

    @Test
    void aHostThatCannotBeReachedIsNotAMissingArtifactEither() {
        String refused = "[ERROR] Could not transfer artifact com.acme:module-a:pom:1.0 from/to "
                + "central (https://repo.maven.apache.org/maven2): Connection refused: connect";
        assertThat(resolver.classifyFailure(failedWith(refused)).failureReason())
                .isEqualTo(ProbeFailureReason.REPOSITORY_UNREACHABLE);
    }

    @Test
    void findsTheDirectDependencysResolvedVersion() {
        assertThat(resolver.findVersion(TREE, new MavenArtifact("com.acme", "module-a"))).isEqualTo("4.2.0");
    }

    @Test
    void findsATransitiveDependencyNestedBelowIt() {
        assertThat(resolver.findVersion(TREE, new MavenArtifact("com.fasterxml.jackson.core", "jackson-databind")))
                .isEqualTo("3.1.6");
    }

    @Test
    void returnsNullWhenTheArtifactIsAbsentFromTheTree() {
        assertThat(resolver.findVersion(TREE, new MavenArtifact("org.nowhere", "nothing"))).isNull();
    }

    @Test
    void doesNotMatchAnArtifactIdThatIsOnlyAPrefix() {
        // com.acme:module-a must not match a line for com.acme:module-ab.
        String tree = String.join("\n",
                "dev.sbomscope.probe:probe:pom:0",
                "\\- com.acme:module-ab:jar:1.0.0:compile");

        assertThat(resolver.findVersion(tree, new MavenArtifact("com.acme", "module-a"))).isNull();
    }

    /**
     * The whole-module POM declares several direct dependencies and more than one can reach the
     * same component. Which one Maven resolved it through is the only thing that decides whether
     * bumping does anything — and it is already written in the indentation.
     */
    private static final String DIAMOND = String.join("\n",
            "dev.sbomscope.probe:probe:pom:0",
            "+- org.keycloak:keycloak-core:jar:4.8.3.Final:compile",
            "|  +- com.fasterxml.jackson.core:jackson-databind:jar:2.9.5:compile",
            "|  |  \\- com.fasterxml.jackson.core:jackson-annotations:jar:2.9.0:compile",
            "|  \\- org.bouncycastle:bcprov-jdk15on:jar:1.60:compile",
            "\\- org.springframework.boot:spring-boot-starter-web:jar:2.1.0.RELEASE:compile",
            "   \\- org.springframework.boot:spring-boot-starter-json:jar:2.1.0.RELEASE:compile");

    @Test
    void namesTheDirectDependencyTheTargetActuallyHangsUnder() {
        assertThat(resolver.declaringDependencyOf(
                DIAMOND, new MavenArtifact("com.fasterxml.jackson.core", "jackson-databind")))
                .isEqualTo("org.keycloak:keycloak-core");
    }

    @Test
    void walksPastIntermediateDepthsToReachTheDirectDependency() {
        // Three levels down, under keycloak-core rather than under its own immediate parent.
        assertThat(resolver.declaringDependencyOf(
                DIAMOND, new MavenArtifact("com.fasterxml.jackson.core", "jackson-annotations")))
                .isEqualTo("org.keycloak:keycloak-core");
    }

    @Test
    void reportsNothingForAnArtifactThatIsItselfADirectDependency() {
        // Nothing declares it on the reader's behalf, so there is no ancestor to bump.
        assertThat(resolver.declaringDependencyOf(DIAMOND, new MavenArtifact("org.keycloak", "keycloak-core")))
                .isNull();
    }

    @Test
    void reportsNothingWhenTheTargetIsAbsent() {
        assertThat(resolver.declaringDependencyOf(DIAMOND, new MavenArtifact("org.nowhere", "nothing"))).isNull();
    }
}
