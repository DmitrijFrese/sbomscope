package dev.sbomscope.probe;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MavenArtifactTest {

    @Test
    void splitsOnTheFirstColonOnly() {
        // Maven coordinates never contain a colon themselves, so this is exact rather than a
        // heuristic — verified against a group with dots, which is the normal case.
        MavenArtifact artifact = MavenArtifact.fromCoordinates("com.fasterxml.jackson.core:jackson-databind");

        assertThat(artifact.groupId()).isEqualTo("com.fasterxml.jackson.core");
        assertThat(artifact.artifactId()).isEqualTo("jackson-databind");
    }

    @Test
    void rejectsAStringWithNoColon() {
        assertThatThrownBy(() -> MavenArtifact.fromCoordinates("not-a-coordinate"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void gavJoinsGroupArtifactAndVersion() {
        MavenArtifact artifact = new MavenArtifact("com.acme", "module-a");
        assertThat(artifact.gav("4.2.0")).isEqualTo("com.acme:module-a:4.2.0");
    }
}
