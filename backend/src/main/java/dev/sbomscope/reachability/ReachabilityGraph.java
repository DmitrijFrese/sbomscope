package dev.sbomscope.reachability;

import java.util.List;

/** Inspectable method edges produced by one engine run. */
public record ReachabilityGraph(String engine, String algorithm, List<MethodEdge> edges) {

    public record MethodEdge(String caller, String callee) {}
}
