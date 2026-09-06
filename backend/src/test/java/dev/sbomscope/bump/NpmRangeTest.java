package dev.sbomscope.bump;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class NpmRangeTest {

    @Test
    void exactVersionAdmitsItself() {
        assertThat(NpmRange.admits("4.17.20", "4.17.20")).isTrue();
    }

    @Test
    void exactVersionDoesNotAdmitAnotherPatch() {
        assertThat(NpmRange.admits("4.17.20", "4.17.21")).isFalse();
    }

    @Test
    void caretAdmitsACompatibleFix() {
        assertThat(NpmRange.admits("^4.17.20", "4.18.0")).isTrue();
    }

    @Test
    void caretDoesNotAdmitTheNextMajor() {
        assertThat(NpmRange.admits("^4.17.20", "5.0.0")).isFalse();
    }

    @Test
    void zeroMajorCaretStopsAtTheNextMinor() {
        assertThat(NpmRange.admits("^0.2.3", "0.3.0")).isFalse();
    }

    @Test
    void tildeAdmitsACompatiblePatch() {
        assertThat(NpmRange.admits("~1.2.3", "1.2.9")).isTrue();
    }

    @Test
    void tildeDoesNotAdmitTheNextMinor() {
        assertThat(NpmRange.admits("~1.2.3", "1.3.0")).isFalse();
    }

    @Test
    void greaterThanOrEqualAdmitsANewerVersion() {
        assertThat(NpmRange.admits(">=1.2.3", "9.0.0")).isTrue();
    }

    @Test
    void greaterThanOrEqualDoesNotAdmitAnOlderVersion() {
        assertThat(NpmRange.admits(">=1.2.3", "1.2.2")).isFalse();
    }

    @Test
    void unsupportedSpecifierIsRejected() {
        assertThat(NpmRange.isSupported("workspace:*")).isFalse();
    }

    @Test
    void rewritePreservesTheCaret() {
        assertThat(NpmRange.rewrite("^4.17.20", "4.17.21")).isEqualTo("^4.17.21");
    }

    @Test
    void rewritePreservesGreaterThanOrEqual() {
        assertThat(NpmRange.rewrite(">=1.2.3", "2.0.0")).isEqualTo(">=2.0.0");
    }
}
