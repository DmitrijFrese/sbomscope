package dev.sbomscope.sbom;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The cases the real fixtures cannot produce.
 *
 * <p>Module detection is the one heuristic in this codebase: CycloneDX marks a reactor
 * module no differently from a third-party artifact, so it is inferred from group and
 * version. These documents pin what that inference must and must not claim — in particular
 * that it stays quiet when it would be guessing.
 */
class ScopeClassifierTest {

    private final CycloneDxParser parser = new CycloneDxParser(new ObjectMapper());

    private ParsedSbom parse(String json) {
        return parser.parse(new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8)));
    }

    private DependencyScope scopeOf(ParsedSbom sbom, String bomRef) {
        return sbom.components().stream()
                .filter(component -> component.bomRef().equals(bomRef))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no component " + bomRef))
                .scope();
    }

    /** Root {@code parent}, one module, one third-party library beneath the module. */
    private String document(String moduleGroup, String moduleVersion) {
        return """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "metadata": { "component": {
                    "bom-ref": "parent", "group": "com.acme", "name": "parent", "version": "2.1.0"
                  }},
                  "components": [
                    { "bom-ref": "module", "group": "%s", "name": "web", "version": "%s" },
                    { "bom-ref": "lib", "group": "org.other", "name": "lib", "version": "9.9.9" },
                    { "bom-ref": "deep", "group": "org.other", "name": "deep", "version": "1.0.0" }
                  ],
                  "dependencies": [
                    { "ref": "parent", "dependsOn": ["module"] },
                    { "ref": "module", "dependsOn": ["lib"] },
                    { "ref": "lib", "dependsOn": ["deep"] }
                  ]
                }
                """.formatted(moduleGroup, moduleVersion);
    }

    @Test
    void treatsASiblingModuleAsApplicationCode() {
        ParsedSbom sbom = parse(document("com.acme", "2.1.0"));

        assertThat(scopeOf(sbom, "parent")).isEqualTo(DependencyScope.APPLICATION);
        assertThat(scopeOf(sbom, "module")).isEqualTo(DependencyScope.APPLICATION);
        // What the module declares is what the user can actually change.
        assertThat(scopeOf(sbom, "lib")).isEqualTo(DependencyScope.DIRECT);
        assertThat(scopeOf(sbom, "deep")).isEqualTo(DependencyScope.TRANSITIVE);
    }

    @Test
    void acceptsAModuleInASubGroup() {
        ParsedSbom sbom = parse(document("com.acme.web", "2.1.0"));

        assertThat(scopeOf(sbom, "module")).isEqualTo(DependencyScope.APPLICATION);
    }

    @Test
    void refusesAnArtifactThatMerelySharesAVersion() {
        // Same version, unrelated group: a coincidence, not a module.
        ParsedSbom sbom = parse(document("org.elsewhere", "2.1.0"));

        assertThat(scopeOf(sbom, "module")).isEqualTo(DependencyScope.DIRECT);
        assertThat(scopeOf(sbom, "lib")).isEqualTo(DependencyScope.TRANSITIVE);
    }

    @Test
    void refusesAnArtifactThatMerelySharesAGroup() {
        // The case that makes group alone unusable: an organisation consuming its own
        // published library. Same group, released separately — a real dependency, and one
        // the user can and should upgrade.
        ParsedSbom sbom = parse(document("com.acme", "1.4.2"));

        assertThat(scopeOf(sbom, "module")).isEqualTo(DependencyScope.DIRECT);
    }

    @Test
    void doesNotMistakeANeighbouringGroupForASubGroup() {
        // "com.acmex" starts with "com.acme" as a string but is a different organisation.
        ParsedSbom sbom = parse(document("com.acmex", "2.1.0"));

        assertThat(scopeOf(sbom, "module")).isEqualTo(DependencyScope.DIRECT);
    }

    @Test
    void survivesACycleInTheGraph() {
        // Diamonds and cycles occur in real graphs; the walk must terminate rather than
        // recurse until it dies.
        ParsedSbom sbom = parse("""
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "metadata": { "component": {
                    "bom-ref": "root", "group": "com.acme", "name": "root", "version": "1.0.0"
                  }},
                  "components": [
                    { "bom-ref": "a", "group": "com.acme", "name": "a", "version": "1.0.0" },
                    { "bom-ref": "b", "group": "com.acme", "name": "b", "version": "1.0.0" }
                  ],
                  "dependencies": [
                    { "ref": "root", "dependsOn": ["a"] },
                    { "ref": "a", "dependsOn": ["b"] },
                    { "ref": "b", "dependsOn": ["a"] }
                  ]
                }
                """);

        assertThat(scopeOf(sbom, "a")).isEqualTo(DependencyScope.APPLICATION);
        assertThat(scopeOf(sbom, "b")).isEqualTo(DependencyScope.APPLICATION);
    }

    @Test
    void claimsNoModulesWhenTheRootHasNoGroup() {
        // An npm root carries no group, so there is nothing to compare and module detection
        // must switch itself off rather than match on version alone.
        ParsedSbom sbom = parse("""
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.5",
                  "metadata": { "component": {
                    "bom-ref": "app", "name": "app", "version": "1.0.0"
                  }},
                  "components": [
                    { "bom-ref": "dep", "name": "some-package", "version": "1.0.0" }
                  ],
                  "dependencies": [ { "ref": "app", "dependsOn": ["dep"] } ]
                }
                """);

        assertThat(scopeOf(sbom, "app")).isEqualTo(DependencyScope.APPLICATION);
        assertThat(scopeOf(sbom, "dep"))
                .as("matching version alone must never promote a dependency")
                .isEqualTo(DependencyScope.DIRECT);
    }
}
