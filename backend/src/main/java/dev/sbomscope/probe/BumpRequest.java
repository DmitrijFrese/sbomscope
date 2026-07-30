package dev.sbomscope.probe;

import java.util.List;
import java.util.UUID;

import dev.sbomscope.sbom.ComponentGraph;
import dev.sbomscope.sbom.GraphNode;
import dev.sbomscope.sbom.StoredComponent;
import dev.sbomscope.scanner.UpgradeAdvice.AdvisoryFix;
import dev.sbomscope.scanner.UpgradeAdviceService;

/**
 * Everything one bump probe needs, gathered by the controller from data it already has.
 *
 * @param moduleDirectDependencies the owning module's full direct dependency set — not
 *                                 derivable from {@code graph} alone, which only carries the
 *                                 routes that reach {@code component}, not everything else the
 *                                 module declares
 */
public record BumpRequest(
        UUID sbomId,
        StoredComponent component,
        ComponentGraph graph,
        List<GraphNode> moduleDirectDependencies,
        List<AdvisoryFix> advisories,
        String workspacePath,
        UpgradeAdviceService.TargetEvaluator targetEvaluator) {}
