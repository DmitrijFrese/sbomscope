package dev.sbomscope.reachability;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarFile;

import tools.jackson.databind.ObjectMapper;

/**
 * Narrow worker entry point selected by {@code --reachability-worker}, before Spring starts.
 * It accepts paths chosen by the parent only; it contains no Maven, shell or network capability.
 */
public final class ReachabilityWorkerMain {
    static final String SWITCH = "--reachability-worker";

    private ReachabilityWorkerMain() {}

    public static boolean handles(String[] args) {
        return args.length == 3 && SWITCH.equals(args[0]);
    }

    public static void run(String[] args) {
        if (!handles(args)) {
            throw new IllegalArgumentException("Worker requires --reachability-worker <input.json> <output.json>");
        }
        try {
            ObjectMapper mapper = new ObjectMapper();
            ReachabilityWorkerRequest request = mapper.readValue(Path.of(args[1]).toFile(), ReachabilityWorkerRequest.class);
            WorkspaceAnalysisInputs inputs = new WorkspaceAnalysisInputs(
                    request.productionOutputs().stream().map(Path::of).toList(),
                    request.supportingOutputs().stream().map(Path::of).toList(),
                    request.dependencyArtifacts().stream()
                            .map(item -> new WorkspaceAnalysisInputs.ComponentArtifact(item.purl(), Path.of(item.jar())))
                            .toList(),
                    request.missingInputs(), request.blockers(), request.fingerprint());
            ReachabilityGraph graph = new WalaReachabilityEngine().analyse(inputs);
            mapper.writeValue(Path.of(args[2]).toFile(), boundedResult(inputs, graph));
        } catch (Exception e) {
            System.err.println(diagnostic(e));
            System.exit(2);
        }
    }

    private static String diagnostic(Exception failure) {
        Set<String> messages = new LinkedHashSet<>();
        Throwable current = failure;
        while (current != null && messages.size() < 4) {
            String message = current.getMessage();
            messages.add(current.getClass().getSimpleName()
                    + (message == null || message.isBlank() ? "" : ": " + message.strip()));
            current = current.getCause();
        }
        return String.join(" Caused by: ", messages);
    }

    public static ReachabilityWorkerRequest requestFor(WorkspaceAnalysisInputs inputs) {
        return new ReachabilityWorkerRequest(
                inputs.productionOutputs().stream().map(Path::toString).toList(),
                inputs.supportingOutputs().stream().map(Path::toString).toList(),
                inputs.dependencyArtifacts().stream().map(item -> new ReachabilityWorkerRequest.Artifact(
                        item.purl(), item.jar().toString())).toList(),
                inputs.missingInputs(), inputs.blockers(), inputs.fingerprint());
    }

    static ReachabilityWorkerResult boundedResult(WorkspaceAnalysisInputs inputs, ReachabilityGraph graph)
            throws Exception {
        Map<String, Set<String>> classesByPurl = new HashMap<>();
        Map<String, Set<String>> ownersByClass = new HashMap<>();
        for (Path output : java.util.stream.Stream.concat(
                inputs.productionOutputs().stream(), inputs.supportingOutputs().stream()).distinct().toList()) {
            String owner = "workspace:" + output.toAbsolutePath().normalize();
            classesInDirectory(output).forEach(name -> ownersByClass
                    .computeIfAbsent(name, unused -> new LinkedHashSet<>()).add(owner));
        }
        for (WorkspaceAnalysisInputs.ComponentArtifact artifact : inputs.dependencyArtifacts()) {
            Set<String> classes = classesIn(artifact.jar());
            classesByPurl.computeIfAbsent(artifact.purl(), unused -> new LinkedHashSet<>()).addAll(classes);
            classes.forEach(name -> ownersByClass.computeIfAbsent(name, unused -> new LinkedHashSet<>())
                    .add(artifact.purl()));
        }
        Set<String> collidingClasses = ownersByClass.entrySet().stream()
                .filter(entry -> entry.getValue().size() > 1)
                .map(Map.Entry::getKey)
                .collect(java.util.stream.Collectors.toSet());
        Map<String, String> productionClasses = new HashMap<>();
        for (Path output : inputs.productionOutputs()) {
            classesInDirectory(output).forEach(name -> productionClasses.put(name, "module"));
        }
        WorkspaceRouteFinder routeFinder = new WorkspaceRouteFinder();
        List<ReachabilityWorkerResult.ComponentCoverage> coverage = classesByPurl.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .map(entry -> {
                    WorkspaceRouteFinder.RouteCoverage routes = routeFinder.find(
                            "module", productionClasses, graph.edges(), entry.getValue());
                    return new ReachabilityWorkerResult.ComponentCoverage(
                            entry.getKey(), routes.reachableMethods(), routes.directMethods(),
                            routes.displayPaths(), routes.representativePathsLimited(),
                            entry.getValue().stream().anyMatch(collidingClasses::contains));
                })
                .toList();
        return new ReachabilityWorkerResult(graph.engine(), graph.algorithm(), coverage);
    }

    private static Set<String> classesIn(Path jarPath) throws Exception {
        try (JarFile jar = new JarFile(jarPath.toFile())) {
            return jar.stream()
                    .map(entry -> entry.getName())
                    .filter(name -> name.endsWith(".class") && !name.startsWith("META-INF/"))
                    .map(name -> name.substring(0, name.length() - ".class".length()).replace('/', '.'))
                    .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));
        }
    }

    private static Set<String> classesInDirectory(Path output) throws Exception {
        try (var files = Files.walk(output)) {
            return files.filter(path -> path.toString().endsWith(".class"))
                    .map(path -> output.relativize(path).toString().replace('\\', '/'))
                    .map(name -> name.substring(0, name.length() - ".class".length()).replace('/', '.'))
                    .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));
        }
    }
}
