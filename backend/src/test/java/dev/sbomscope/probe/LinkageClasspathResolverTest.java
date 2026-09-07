package dev.sbomscope.probe;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LinkageClasspathResolverTest {

    @Test
    void derivesTheBuildClasspathGoalFromThePinnedTreeGoal() {
        assertThat(LinkageClasspathResolver.buildClasspathGoal(
                "org.apache.maven.plugins:maven-dependency-plugin:3.6.1:tree"))
                .isEqualTo("org.apache.maven.plugins:maven-dependency-plugin:3.6.1:build-classpath");
    }

    @Test
    void refusesAGoalThatIsNotTheFullyQualifiedTreeGoal() {
        assertThatThrownBy(() -> LinkageClasspathResolver.buildClasspathGoal("dependency:tree"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> LinkageClasspathResolver.buildClasspathGoal(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    /**
     * The separator is the platform's, and on Windows splitting on a bare colon would tear
     * {@code C:\repo\x.jar} in half at the drive letter.
     */
    @Test
    void splitsTheClasspathOnThePlatformSeparatorAndKeepsWholePaths() {
        String first = Path.of("C:", "repo", "okio-2.8.0.jar").toString();
        String second = Path.of("C:", "repo", "okhttp-4.9.2.jar").toString();

        List<Path> jars = LinkageClasspathResolver.parseClasspath(
                first + File.pathSeparator + second + "\n");

        assertThat(jars).containsExactly(Path.of(first), Path.of(second));
        assertThat(jars).allSatisfy(jar -> assertThat(jar.toString()).endsWith(".jar"));
    }

    @Test
    void dropsEntriesThatAreNotJars() {
        String jar = Path.of("C:", "repo", "a.jar").toString();
        String classes = Path.of("C:", "workspace", "target", "classes").toString();

        assertThat(LinkageClasspathResolver.parseClasspath(jar + File.pathSeparator + classes))
                .containsExactly(Path.of(jar));
    }

    @Test
    void returnsAnIncompleteAnswerRatherThanAnEmptyClasspathWhenThereIsNothingToResolve() {
        LinkageClasspathResolver resolver = new LinkageClasspathResolver(
                new dev.sbomscope.logging.ActivityLogger(new tools.jackson.databind.ObjectMapper()));

        var resolved = resolver.resolve(List.of(), java.util.Map.of(), null);

        assertThat(resolved.complete()).isFalse();
        assertThat(resolved.jars()).isEmpty();
        assertThat(resolved.detail()).isNotBlank();
    }
}
