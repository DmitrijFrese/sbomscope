package dev.sbomscope.api;

import java.time.Instant;
import java.util.Optional;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.info.BuildProperties;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Reports that the backend is up, and which build the UI is talking to.
 */
@RestController
@RequestMapping("/api")
class StatusController {

    private final String version;
    private final Instant startedAt = Instant.now();

    /**
     * @param buildProperties present when running the packaged jar; absent when the
     *                        application is started straight from compiled classes,
     *                        which is why it is resolved leniently.
     */
    StatusController(ObjectProvider<BuildProperties> buildProperties) {
        this.version = Optional.ofNullable(buildProperties.getIfAvailable())
                .map(BuildProperties::getVersion)
                .orElse("dev");
    }

    record StatusResponse(String application, String version, Instant startedAt) {}

    @GetMapping("/status")
    StatusResponse status() {
        return new StatusResponse("SBOMscope", version, startedAt);
    }
}
