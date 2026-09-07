package dev.sbomscope.bump;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class TargetAvailabilityTest {

    /** What the probe repository would hold for a line whose later patches went commercial. */
    private static final List<String> SPRING_SECURITY_CRYPTO =
            List.of("6.1.8", "6.1.9", "6.2.7", "6.3.4", "6.4.2", "6.5.5");

    @Test
    void aVersionInTheMetadataIsKnown() {
        assertThat(TargetAvailability.of("6.1.9", SPRING_SECURITY_CRYPTO))
                .isEqualTo(TargetAvailability.KNOWN);
    }

    /**
     * The case that prompted this: 6.1.14 sits between versions the metadata does list, so its
     * absence is not our copy being stale — it was never published where this Maven can see it.
     */
    @Test
    void aVersionMissingBelowTheHighestKnownReleaseIsAbsent() {
        assertThat(TargetAvailability.of("6.1.14", SPRING_SECURITY_CRYPTO))
                .isEqualTo(TargetAvailability.ABSENT);
    }

    @Test
    void aVersionAboveEverythingKnownMeansOurMetadataIsBehind() {
        // Not ABSENT: a release later than anything on disk is exactly what a stale snapshot
        // looks like, and calling it missing would flag every genuinely new fix.
        assertThat(TargetAvailability.of("7.0.0", SPRING_SECURITY_CRYPTO))
                .isEqualTo(TargetAvailability.UNKNOWN);
    }

    @Test
    void aPreReleaseIsNeverAbsentBecauseKnownVersionsDropsThem() {
        // knownVersions filters out anything containing a hyphen, so a milestone could not appear
        // in the list even when the repository has it.
        assertThat(TargetAvailability.of("6.2.0-RC1", SPRING_SECURITY_CRYPTO))
                .isEqualTo(TargetAvailability.UNKNOWN);
    }

    @Test
    void nothingOnDiskMeansNoClaimEitherWay() {
        assertThat(TargetAvailability.of("6.1.14", List.of())).isEqualTo(TargetAvailability.UNKNOWN);
        assertThat(TargetAvailability.of("6.1.14", null)).isEqualTo(TargetAvailability.UNKNOWN);
    }

    @Test
    void noTargetIsNotAQuestion() {
        assertThat(TargetAvailability.of(null, SPRING_SECURITY_CRYPTO))
                .isEqualTo(TargetAvailability.UNKNOWN);
        assertThat(TargetAvailability.of("  ", SPRING_SECURITY_CRYPTO))
                .isEqualTo(TargetAvailability.UNKNOWN);
    }
}
