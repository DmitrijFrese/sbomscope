package dev.sbomscope.config;

import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.io.FileSystemResource;

import static org.assertj.core.api.Assertions.assertThat;

class LocalServerBindingTest {

    @Test
    void committedServerConfigurationBindsToLoopback() throws Exception {
        var resource = new FileSystemResource(Path.of("src/main/resources/application.yml"));
        var sources = new YamlPropertySourceLoader().load("application", resource);

        assertThat(sources.getFirst().getProperty("server.address")).isEqualTo("127.0.0.1");
    }
}
