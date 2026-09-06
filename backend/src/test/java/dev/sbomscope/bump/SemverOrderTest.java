package dev.sbomscope.bump;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class SemverOrderTest {

    @Test
    void comparesNumericCoreSegmentsNumerically() {
        assertThat(SemverOrder.INSTANCE.compare("1.10.0", "1.9.0")).isPositive();
    }

    @Test
    void prereleaseSortsBelowTheRelease() {
        assertThat(SemverOrder.INSTANCE.compare("1.0.0-alpha", "1.0.0")).isNegative();
    }

    @Test
    void numericPrereleaseIdentifiersCompareNumerically() {
        assertThat(SemverOrder.INSTANCE.compare("1.0.0-alpha.2", "1.0.0-alpha.10"))
                .isNegative();
    }

    @Test
    void numericPrereleaseIdentifiersSortBelowAlphanumericOnes() {
        assertThat(SemverOrder.INSTANCE.compare("1.0.0-2", "1.0.0-beta")).isNegative();
    }

    @Test
    void aLongerEqualPrereleaseHasHigherPrecedence() {
        assertThat(SemverOrder.INSTANCE.compare("1.0.0-alpha.1", "1.0.0-alpha")).isPositive();
    }

    @Test
    void ignoresBuildMetadata() {
        assertThat(SemverOrder.INSTANCE.compare("1.2.3+one", "1.2.3+two")).isZero();
    }
}
