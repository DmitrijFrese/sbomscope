package dev.sbomscope.reachability;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.stereotype.Component;

/**
 * Separates complete per-module method coverage from the deliberately bounded path display.
 *
 * <p>Counting every possible call path is not a useful exact measure: a cyclic graph can have
 * arbitrarily many walks. Instead, coverage is the exact finite set of compiled application
 * methods from this module that can reach any method in the component boundary. The displayed
 * paths are the first ten shortest simple routes that explain that coverage.
 */
@Component
public class WorkspaceRouteFinder {

    static final int DISPLAY_CAP = 10;
    private static final int MAX_ROUTE_DEPTH = 16;
    private static final int MAX_SEARCHED_PATHS = 25_000;

    public RouteCoverage find(String module, Map<String, String> modules,
                               List<ReachabilityGraph.MethodEdge> edges, Set<String> targetClasses) {
        Map<String, List<String>> outgoing = outgoing(edges);
        Set<String> starts = outgoing.keySet().stream()
                .filter(method -> module.equals(modules.get(owner(method))))
                .collect(java.util.stream.Collectors.toCollection(java.util.TreeSet::new));
        Set<String> reachingTarget = methodsReachingTarget(edges, targetClasses);
        int reachableMethods = (int) starts.stream().filter(reachingTarget::contains).count();
        int directMethods = (int) starts.stream()
                .filter(method -> outgoing.getOrDefault(method, List.of()).stream()
                        .anyMatch(callee -> targetClasses.contains(owner(callee))))
                .count();
        DisplayPaths displayed = displayPaths(starts, outgoing, targetClasses);
        return new RouteCoverage(reachableMethods, directMethods, displayed.paths(), displayed.limited());
    }

    private Map<String, List<String>> outgoing(List<ReachabilityGraph.MethodEdge> edges) {
        Map<String, List<String>> result = new HashMap<>();
        for (ReachabilityGraph.MethodEdge edge : edges) {
            result.computeIfAbsent(edge.caller(), unused -> new ArrayList<>()).add(edge.callee());
        }
        result.values().forEach(paths -> paths.sort(Comparator.naturalOrder()));
        return result;
    }

    private Set<String> methodsReachingTarget(List<ReachabilityGraph.MethodEdge> edges,
                                               Set<String> targetClasses) {
        Map<String, List<String>> incoming = new HashMap<>();
        Deque<String> queue = new ArrayDeque<>();
        Set<String> result = new HashSet<>();
        for (ReachabilityGraph.MethodEdge edge : edges) {
            incoming.computeIfAbsent(edge.callee(), unused -> new ArrayList<>()).add(edge.caller());
            if (targetClasses.contains(owner(edge.callee())) && result.add(edge.callee())) {
                queue.addLast(edge.callee());
            }
        }
        while (!queue.isEmpty()) {
            String current = queue.removeFirst();
            for (String caller : incoming.getOrDefault(current, List.of())) {
                if (result.add(caller)) queue.addLast(caller);
            }
        }
        return result;
    }

    private DisplayPaths displayPaths(Set<String> starts, Map<String, List<String>> outgoing,
                                      Set<String> targetClasses) {
        Deque<List<String>> queue = new ArrayDeque<>();
        starts.forEach(start -> queue.addLast(List.of(start)));
        List<List<String>> result = new ArrayList<>();
        int searched = 0;
        boolean depthLimited = false;
        while (!queue.isEmpty() && result.size() < DISPLAY_CAP && searched++ < MAX_SEARCHED_PATHS) {
            List<String> path = queue.removeFirst();
            if (path.size() > MAX_ROUTE_DEPTH) {
                depthLimited = true;
                continue;
            }
            String current = path.getLast();
            for (String callee : outgoing.getOrDefault(current, List.of())) {
                List<String> next = new ArrayList<>(path);
                next.add(callee);
                if (targetClasses.contains(owner(callee))) {
                    result.add(List.copyOf(next));
                    if (result.size() == DISPLAY_CAP) break;
                } else if (!path.contains(callee)) {
                    queue.addLast(List.copyOf(next));
                }
            }
        }
        return new DisplayPaths(List.copyOf(result), depthLimited || !queue.isEmpty());
    }

    private String owner(String method) {
        int separator = method.indexOf('#');
        return separator < 0 ? method : method.substring(0, separator);
    }

    private record DisplayPaths(List<List<String>> paths, boolean limited) {}

    public record RouteCoverage(int reachableMethods, int directMethods, List<List<String>> displayPaths,
                                boolean representativePathsLimited) {}
}
