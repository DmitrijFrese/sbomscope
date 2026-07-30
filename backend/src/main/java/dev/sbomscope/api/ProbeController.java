package dev.sbomscope.api;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import dev.sbomscope.probe.BumpProbeService;
import dev.sbomscope.probe.ProbeTaskView;

/**
 * The probe queue as a whole, rather than one component's view of it.
 *
 * <p>Deliberately not under {@code /api/sboms/{id}/component/...} like the rest of the probe
 * endpoints: everything there is addressed by the component it belongs to, and the question this
 * answers — "what is running, and how do I stop it" — is asked precisely by somebody who no
 * longer knows which component that was.
 */
@RestController
@RequestMapping("/api/probes")
class ProbeController {

    private final BumpProbeService probes;

    ProbeController(BumpProbeService probes) {
        this.probes = probes;
    }

    /**
     * Running, queued, and recently finished — live rows first in the order they will execute,
     * then the session's history, most recent first.
     */
    @GetMapping
    List<ProbeTaskView> all() {
        return probes.probes();
    }

    /**
     * Stops a probe, running or queued.
     *
     * <p>{@code DELETE} because what it removes is the task, not the findings: a stopped run
     * keeps every row it had settled and can be resumed with the existing continue endpoint.
     * A 404 means it had already finished — the row stays in the list as history, but there is
     * nothing left to stop. A race the reader loses harmlessly, since the list is polled.
     */
    @DeleteMapping("/{id}")
    ResponseEntity<Void> cancel(@PathVariable String id) {
        if (!probes.cancel(id)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "That probe is no longer running.");
        }
        return ResponseEntity.noContent().build();
    }
}
