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
