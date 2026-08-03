package dev.sbomscope.reachability;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.jar.JarFile;

import org.springframework.stereotype.Component;

import com.ibm.wala.classLoader.BinaryDirectoryTreeModule;
import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.classLoader.JarFileModule;
import com.ibm.wala.core.util.config.AnalysisScopeReader;
import com.ibm.wala.ipa.callgraph.AnalysisCacheImpl;
import com.ibm.wala.ipa.callgraph.AnalysisOptions;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.callgraph.CallGraphBuilder;
import com.ibm.wala.ipa.callgraph.Entrypoint;
import com.ibm.wala.ipa.callgraph.impl.DefaultEntrypoint;
import com.ibm.wala.ipa.callgraph.impl.Util;
import com.ibm.wala.ipa.callgraph.propagation.cfa.ZeroXContainerCFABuilder;
import com.ibm.wala.ipa.cha.ClassHierarchyFactory;
import com.ibm.wala.ipa.cha.IClassHierarchy;
import com.ibm.wala.types.ClassLoaderReference;

/**
 * WALA 0-CFA graph construction for JVM workspace bytecode.
 *
 * <p>Every compiled production method is a conservative root. This is intentional: entry-point
 * discovery for Spring is a separate problem, and treating an unrecognised controller/listener
 * as unreachable would make the negative result less safe. WALA is only handed inputs supplied
 * by {@link WorkspaceInputDiscovery}; it never receives a workspace root or a Maven executable.
 */
@Component
public class WalaReachabilityEngine implements ReachabilityEngine {

    static final String ENGINE = "WALA 1.8.0";
    static final String ALGORITHM = "0-CFA";

    @Override
    public ReachabilityGraph analyse(WorkspaceAnalysisInputs inputs) {
        if (!inputs.hasProductionOutputs()) {
            return new ReachabilityGraph(ENGINE, ALGORITHM, List.of());
        }

        List<JarFile> openedJars = new ArrayList<>();
        try {
            var scope = AnalysisScopeReader.instance.makeJavaBinaryAnalysisScope(
                    inputs.productionOutputs().getFirst().toString(), null);
            for (Path output : inputs.productionOutputs().subList(1, inputs.productionOutputs().size())) {
                scope.addToScope(ClassLoaderReference.Application,
                        new BinaryDirectoryTreeModule(output.toFile()));
            }
            for (Path output : inputs.supportingOutputs()) {
                scope.addToScope(ClassLoaderReference.Application,
                        new BinaryDirectoryTreeModule(output.toFile()));
            }
            for (WorkspaceAnalysisInputs.ComponentArtifact artifact : inputs.dependencyArtifacts()) {
                JarFile jar = new JarFile(artifact.jar().toFile());
                openedJars.add(jar);
                scope.addToScope(ClassLoaderReference.Application,
                        new JarFileModule(jar));
            }

            // Missing JARs are already a completeness blocker. Do not materialize them as WALA
            // phantom classes: a 0-CFA builder can attempt to enumerate a phantom's methods,
            // which is unsupported and turns otherwise useful positive evidence into a failure.
            IClassHierarchy hierarchy = ClassHierarchyFactory.make(scope);
            Set<String> workspaceClasses = productionClassNames(inputs.productionOutputs());
            List<Entrypoint> roots = productionEntrypoints(hierarchy, workspaceClasses);
            if (roots.isEmpty()) {
                return new ReachabilityGraph(ENGINE, ALGORITHM, List.of());
            }

            AnalysisOptions options = new AnalysisOptions(scope, roots);
            // WALA's convenience factories are deprecated in 1.8.0. This is their current
            // implementation written out explicitly: Java's default selectors and summaries,
            // then a zero-CFA builder with container context handling and no extra instance-key
            // sensitivity. Keeping it here prevents a future WALA update from turning a warning
            // into a broken production analysis path.
            Util.addDefaultSelectors(options, hierarchy);
            Util.addDefaultBypassLogic(options, WalaReachabilityEngine.class.getClassLoader(), hierarchy);
            CallGraphBuilder<?> builder = new ZeroXContainerCFABuilder(
                    hierarchy, options, new AnalysisCacheImpl(), null, null, 0);
            CallGraph graph = builder.makeCallGraph(options, null);
            return new ReachabilityGraph(ENGINE, ALGORITHM, edges(graph));
        } catch (Exception e) {
            String location = e.getStackTrace().length == 0 ? "" : " at " + e.getStackTrace()[0];
            throw new ReachabilityAnalysisException(
                    "WALA could not construct the workspace call graph (" + e.getClass().getSimpleName() + location + ").", e);
        } finally {
            for (JarFile jar : openedJars) {
                try {
                    jar.close();
                } catch (IOException ignored) {
                    // The graph has already been produced; a Windows handle cleanup failure is non-fatal.
                }
            }
        }
    }

    private List<Entrypoint> productionEntrypoints(IClassHierarchy hierarchy, Set<String> workspaceClasses) {
        List<Entrypoint> roots = new ArrayList<>();
        for (IClass clazz : hierarchy) {
            if (!ClassLoaderReference.Application.equals(clazz.getClassLoader().getReference())
                    || !workspaceClasses.contains(clazz.getName().toString())) {
                continue;
            }
            try {
                for (IMethod method : clazz.getDeclaredMethods()) {
                    if (!method.isAbstract() && !method.isNative()) {
                        roots.add(new DefaultEntrypoint(method.getReference(), hierarchy));
                    }
                }
            } catch (UnsupportedOperationException ignored) {
                // WALA represents unresolved classes as phantoms; their name can overlap a
                // workspace output, but they have no bytecode or declared methods to root.
            }
        }
        return roots;
    }

    private Set<String> productionClassNames(List<Path> outputs) throws IOException {
        Set<String> names = new HashSet<>();
        for (Path output : outputs) {
            try (var files = Files.walk(output)) {
                files.filter(path -> path.toString().endsWith(".class")).forEach(path -> {
                    Path relative = output.relativize(path);
                    String name = relative.toString().replace('\\', '/');
                    names.add("L" + name.substring(0, name.length() - ".class".length()));
                });
            }
        }
        return names;
    }

    private List<ReachabilityGraph.MethodEdge> edges(CallGraph graph) {
        List<ReachabilityGraph.MethodEdge> result = new ArrayList<>();
        graph.forEach(node -> graph.getSuccNodes(node).forEachRemaining(target -> result.add(
                new ReachabilityGraph.MethodEdge(methodName(node.getMethod()), methodName(target.getMethod())))));
        return result.stream().distinct()
                .sorted(Comparator.comparing(ReachabilityGraph.MethodEdge::caller)
                        .thenComparing(ReachabilityGraph.MethodEdge::callee))
                .toList();
    }

    private String methodName(IMethod method) {
        String owner = method.getDeclaringClass().getName().toString();
        if (owner.startsWith("L")) {
            owner = owner.substring(1);
        }
        return owner.replace('/', '.') + "#" + method.getSelector();
    }
}
