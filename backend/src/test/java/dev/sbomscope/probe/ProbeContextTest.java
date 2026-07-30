package dev.sbomscope.probe;

import java.time.Duration;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ProbeContextTest {

    private ProbeContext contextWith(String profiles) {
        return new ProbeContext("/usr/bin/mvn", "/tmp/probe-repo", null, Duration.ofSeconds(60), profiles);
    }

    @Test
    void buildsASingleDashPArgumentFromCommaSeparatedProfiles() {
        assertThat(contextWith("prod,internal-repo").profileArgs()).containsExactly("-Pprod,internal-repo");
    }

    @Test
    void isEmptyWhenNoProfileIsConfigured() {
        assertThat(contextWith(null).profileArgs()).isEmpty();
        assertThat(contextWith("").profileArgs()).isEmpty();
        assertThat(contextWith("   ").profileArgs()).isEmpty();
    }

    @Test
    void trimsSurroundingWhitespace() {
        assertThat(contextWith("  prod ").profileArgs()).containsExactly("-Pprod");
    }
}
