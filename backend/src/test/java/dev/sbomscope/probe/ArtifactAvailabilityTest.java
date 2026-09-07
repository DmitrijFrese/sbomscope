package dev.sbomscope.probe;

import dev.sbomscope.logging.ActivityLogger;
import dev.sbomscope.probe.ArtifactAvailability.Availability;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The reading of a Maven resolution attempt, using output captured from real runs on 2026-09-07.
 *
 * <p>No test here starts Maven. What matters is the classification — telling "the repository
 * answered and had nothing" apart from "the repository could not be asked" — and that is a
 * decision about text, provable without a process.
 */
class ArtifactAvailabilityTest {

    private final ArtifactAvailability availability =
            new ArtifactAvailability(new ActivityLogger(new ObjectMapper()));

    /** Verbatim from `dependency:get` for spring-security-crypto 6.1.14, which is commercial-only. */
    private static final String NOT_FOUND_OUTPUT = """
            [INFO] Scanning for projects...
            [ERROR] Failed to execute goal org.apache.maven.plugins:maven-dependency-plugin:3.7.0:get (default-cli) on project standalone-pom: The following artifacts could not be resolved: org.springframework.security:spring-security-crypto:pom:6.1.14 (absent): org.springframework.security:spring-security-crypto:pom:6.1.14 was not found in https://repo.maven.apache.org/maven2 during a previous attempt. This failure was cached in the local repository and resolution is not reattempted until the update interval of central has elapsed or updates are forced -> [Help 1]
            [ERROR] To see the full stack trace of the errors, re-run Maven with the -e switch.
            """;

    /** A mirror that could not be reached at all. The version may be perfectly fine. */
    private static final String TRANSPORT_OUTPUT = """
            [INFO] Scanning for projects...
            [ERROR] Failed to execute goal on project standalone-pom: Could not transfer artifact org.example:thing:pom:1.2.3 from/to central (https://repo.maven.apache.org/maven2): Connection refused -> [Help 1]
            """;

    @Test
    void derivesTheGetGoalFromThePinnedTreeGoal() {
        assertThat(ArtifactAvailability.dependencyGetGoal(
                "org.apache.maven.plugins:maven-dependency-plugin:3.7.0:tree"))
                .isEqualTo("org.apache.maven.plugins:maven-dependency-plugin:3.7.0:get");
    }

    @Test
    void refusesTheBarePrefixGoalBecauseItLosesThePinnedVersion() {
        assertThatThrownBy(() -> ArtifactAvailability.dependencyGetGoal("dependency:tree"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void treatsAMissingVersionAsUnknownRatherThanRunningMaven() {
        ArtifactAvailability.Result result = availability.check(
                MavenArtifact.fromCoordinates("org.example:thing"), "  ", context());

        assertThat(result.availability()).isEqualTo(Availability.UNKNOWN);
        assertThat(result.detail()).isNotBlank();
    }

    /**
     * The classification this class exists for, exercised through the same predicate the live path
     * uses. A repository that answered and had nothing is a fact about the version; a repository
     * that could not be reached is a fact about the network, and calling the second "unavailable"
     * would send a reader hunting for a replacement that does not need finding.
     */
    @Test
    void tellsAbsenceApartFromNotBeingAbleToAsk() {
        assertThat(ArtifactAvailability.classify(failed(NOT_FOUND_OUTPUT)))
                .isEqualTo(Availability.UNAVAILABLE);
        assertThat(ArtifactAvailability.classify(failed(TRANSPORT_OUTPUT)))
                .isEqualTo(Availability.UNKNOWN);
    }

    @Test
    void neverCallsAVersionAbsentWhenMavenNeverManagedToAsk() {
        MavenInvocation.Result startFailed =
                new MavenInvocation.Result(true, false, -1, "", "program not found");
        MavenInvocation.Result timedOut =
                new MavenInvocation.Result(false, true, -1, NOT_FOUND_OUTPUT, null);

        assertThat(ArtifactAvailability.classify(startFailed)).isEqualTo(Availability.UNKNOWN);
        // Even carrying "was not found" text: a run that was killed proves nothing.
        assertThat(ArtifactAvailability.classify(timedOut)).isEqualTo(Availability.UNKNOWN);
    }

    @Test
    void aSuccessfulResolutionIsTheOnlyThingThatMeansAvailable() {
        assertThat(ArtifactAvailability.classify(new MavenInvocation.Result(false, false, 0, "", null)))
                .isEqualTo(Availability.AVAILABLE);
    }

    private static MavenInvocation.Result failed(String output) {
        return new MavenInvocation.Result(false, false, 1, output, null);
    }

    private static ProbeContext context() {
        return new ProbeContext("mvn", "target/availability-repo", null, Duration.ofMinutes(1), null,
                "org.apache.maven.plugins:maven-dependency-plugin:3.7.0:tree");
    }
}
