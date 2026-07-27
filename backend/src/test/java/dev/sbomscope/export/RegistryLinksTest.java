package dev.sbomscope.export;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RegistryLinksTest {

    @Test
    void linksMavenCoordinatesToMavenCentral() {
        assertThat(RegistryLinks.forPurl("pkg:maven/tools.jackson.core/jackson-databind@3.1.4?type=jar"))
                .isEqualTo("https://central.sonatype.com/artifact/tools.jackson.core/jackson-databind/3.1.4");
    }

    @Test
    void linksNpmPackagesToNpmjs() {
        assertThat(RegistryLinks.forPurl("pkg:npm/react@19.2.8"))
                .isEqualTo("https://www.npmjs.com/package/react/v/19.2.8");
    }

    @Test
    void decodesNpmScopes() {
        // Scoped packages are percent-encoded in a purl but not in an npmjs.com URL.
        assertThat(RegistryLinks.forPurl("pkg:npm/%40types/react@19.2.17"))
                .isEqualTo("https://www.npmjs.com/package/@types/react/v/19.2.17");
    }

    @Test
    void omitsTheVersionWhenThePurlHasNone() {
        assertThat(RegistryLinks.forPurl("pkg:maven/com.example/lib"))
                .isEqualTo("https://central.sonatype.com/artifact/com.example/lib");
    }

    @Test
    void returnsNullForEcosystemsWeCannotLink() {
        assertThat(RegistryLinks.forPurl("pkg:golang/github.com/example/mod@v1.0.0")).isNull();
        assertThat(RegistryLinks.forPurl("not-a-purl")).isNull();
        assertThat(RegistryLinks.forPurl(null)).isNull();
    }
}
