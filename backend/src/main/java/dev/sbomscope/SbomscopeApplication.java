package dev.sbomscope;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point for the local SBOMscope server.
 *
 * <p>The application is deliberately single-process and local: workspace scanning needs
 * direct filesystem access, and all vulnerability data is read from local caches rather
 * than fetched on demand.
 */
@SpringBootApplication
public class SbomscopeApplication {

    public static void main(String[] args) {
        SpringApplication.run(SbomscopeApplication.class, args);
    }
}
