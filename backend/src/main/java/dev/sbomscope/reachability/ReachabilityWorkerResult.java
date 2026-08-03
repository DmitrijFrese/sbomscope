package dev.sbomscope.reachability;

import java.util.List;

/** Bounded evidence returned by one module-scoped worker JVM. */
public record ReachabilityWorkerResult(
        String engine,
        String algorithm,
        List<ComponentCoverage> components) {

    public record ComponentCoverage(
            String purl,
            int reachableMethods,
            int directMethods,
            List<List<String>> displayPaths,
            boolean representativePathsLimited,
            boolean ambiguousClassOwnership) {}
}
