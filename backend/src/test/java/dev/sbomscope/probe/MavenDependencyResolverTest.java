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
}
