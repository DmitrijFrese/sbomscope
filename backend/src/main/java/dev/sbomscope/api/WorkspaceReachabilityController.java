package dev.sbomscope.api;

import java.util.List;
import java.util.UUID;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import dev.sbomscope.reachability.WorkspaceAnalysisTaskView;
import dev.sbomscope.reachability.WorkspaceReachabilityService;

/** Monitoring controls for SBOMscope-owned isolated WALA worker processes. */
@RestController
@RequestMapping("/api/workspace-analyses")
class WorkspaceReachabilityController {
    private final WorkspaceReachabilityService analyses;
    WorkspaceReachabilityController(WorkspaceReachabilityService analyses) { this.analyses = analyses; }

    @GetMapping List<WorkspaceAnalysisTaskView> all() { return analyses.tasks(); }

    @DeleteMapping("/{id}")
    ResponseEntity<Void> cancel(@PathVariable UUID id) {
        if (!analyses.cancel(id)) throw new ResponseStatusException(org.springframework.http.HttpStatus.NOT_FOUND,
                "That workspace analysis is no longer running.");
        return ResponseEntity.noContent().build();
    }
}
