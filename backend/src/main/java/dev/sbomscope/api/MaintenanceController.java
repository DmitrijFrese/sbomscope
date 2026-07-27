package dev.sbomscope.api;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import dev.sbomscope.maintenance.PurgeService;
import dev.sbomscope.maintenance.PurgeTarget;

@RestController
@RequestMapping("/api/maintenance")
class MaintenanceController {

    /**
     * Either word is accepted. Asking someone to type an exact phrase is only useful as a
     * pause for thought, and failing them for choosing the wrong synonym of "delete" adds
     * irritation without adding safety.
     */
    private static final Set<String> CONFIRMATIONS = Set.of("PURGE", "DELETE");

    private final PurgeService purge;

    MaintenanceController(PurgeService purge) {
        this.purge = purge;
    }

    record PurgeRequest(String confirmation, List<String> targets) {}

    /**
     * Erases the chosen local data. Guarded by a typed confirmation because it cannot be
     * undone — there is no bin to recover from, and the OSV archives can cost a 200 MB
     * download to replace.
     */
    @PostMapping("/purge")
    PurgeService.PurgeResult purge(@RequestBody PurgeRequest request) {
        if (request.confirmation() == null
                || !CONFIRMATIONS.contains(request.confirmation().trim().toUpperCase())) {
            throw new IllegalArgumentException(
                    "Type PURGE to confirm. Nothing has been deleted.");
        }

        Set<PurgeTarget> targets = parseTargets(request.targets());
        if (targets.isEmpty()) {
            throw new IllegalArgumentException(
                    "Choose at least one thing to erase. Nothing has been deleted.");
        }

        return purge.purge(targets);
    }

    private Set<PurgeTarget> parseTargets(List<String> requested) {
        Set<PurgeTarget> targets = EnumSet.noneOf(PurgeTarget.class);
        if (requested == null) {
            return targets;
        }
        for (String value : requested) {
            if (value == null || value.isBlank()) {
                continue;
            }
            try {
                targets.add(PurgeTarget.valueOf(value.trim().toUpperCase()));
            } catch (IllegalArgumentException e) {
                // Deleting something other than what was asked for is the one outcome a
                // purge must never produce, so an unrecognised target fails the request
                // rather than being quietly skipped.
                throw new IllegalArgumentException("Unknown purge target: " + value);
            }
        }
        return targets;
    }
}
