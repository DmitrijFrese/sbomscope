package dev.sbomscope.settings;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The plugin goals the Tier 2 probe drives are version-pinned and user-configurable, because
 * which version exists is a fact about the user's repository — a curated mirror proxying an
 * approved subset of Central may carry a different one.
 */
class MavenToolSettingsTest {

    private MavenToolSettings withPluginVersions(String dependencyPlugin, String helpPlugin) {
        return new MavenToolSettings(true, "/usr/bin/mvn", 20, 8, null, dependencyPlugin, helpPlugin);
    }

    @Test
    void buildsFullyQualifiedGoalsFromTheConfiguredVersions() {
        MavenToolSettings settings = withPluginVersions("3.7.1", "3.5.0");

        assertThat(settings.dependencyTreeGoal())
                .isEqualTo("org.apache.maven.plugins:maven-dependency-plugin:3.7.1:tree");
        assertThat(settings.effectivePomGoal())
                .isEqualTo("org.apache.maven.plugins:maven-help-plugin:3.5.0:effective-pom");
    }

    /**
     * Clearing the field is the natural way to undo a change, so it must fall back to what
     * SBOMscope ships with rather than producing a goal with an empty version in it.
     */
    @Test
    void blankFallsBackToTheShippedDefaultRatherThanBreakingTheGoal() {
        for (MavenToolSettings settings : new MavenToolSettings[] {
                withPluginVersions(null, null),
                withPluginVersions("", ""),
                withPluginVersions("   ", "   ")}) {
            assertThat(settings.dependencyTreeGoal()).isEqualTo(
                    "org.apache.maven.plugins:maven-dependency-plugin:%s:tree"
                            .formatted(MavenToolSettings.DEFAULT_DEPENDENCY_PLUGIN_VERSION));
            assertThat(settings.effectivePomGoal()).isEqualTo(
                    "org.apache.maven.plugins:maven-help-plugin:%s:effective-pom"
                            .formatted(MavenToolSettings.DEFAULT_HELP_PLUGIN_VERSION));
        }
    }

    /**
     * The version is interpolated into a colon-separated goal coordinate, so a colon or a space
     * would not merely be invalid — it would change which goal Maven runs. The pattern is what
     * {@code SettingsService} rejects on the way in.
     */
    @Test
    void rejectsVersionsThatCouldAlterTheGoalCoordinate() {
        assertThat(MavenToolSettings.VERSION_PATTERN.matcher("3.6.1").matches()).isTrue();
        assertThat(MavenToolSettings.VERSION_PATTERN.matcher("3.0.0-M1").matches()).isTrue();
        assertThat(MavenToolSettings.VERSION_PATTERN.matcher("3.6.1:evil").matches()).isFalse();
        assertThat(MavenToolSettings.VERSION_PATTERN.matcher("3.6.1 clean").matches()).isFalse();
        assertThat(MavenToolSettings.VERSION_PATTERN.matcher("").matches()).isFalse();
    }
}
