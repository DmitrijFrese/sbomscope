package dev.sbomscope.reachability;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import org.springframework.stereotype.Component;

import dev.sbomscope.sbom.DependencyScope;
import dev.sbomscope.sbom.StoredComponent;

/**
 * Finds only bytecode and Maven artifacts that already exist on disk.
 *
 * <p>No Maven process is started here and no path is created or written. The configured artifact
 * cache is a user-owned read-only input; the app-owned probe repository is deliberately absent
 * from this type's API.
 */
@Component
public class WorkspaceInputDiscovery {

    private static final int MAX_WORKSPACE_DEPTH = 12;
    static final long MAX_CLASS_INSPECTION_BYTES = 16L * 1024 * 1024;
    private static final byte[][] REFLECTION_REFERENCES = {
            "java/lang/reflect/".getBytes(StandardCharsets.ISO_8859_1),
            "java/lang/Proxy".getBytes(StandardCharsets.ISO_8859_1)
    };

    public WorkspaceAnalysisInputs discover(Path workspace, Path mavenLocalRepository,
                                             List<StoredComponent> components) {
        List<Path> outputs = productionOutputs(workspace);
        List<WorkspaceAnalysisInputs.ComponentArtifact> artifacts = new ArrayList<>();
        List<String> missing = new ArrayList<>();
        Set<CompletenessBlocker> blockers = EnumSet.noneOf(CompletenessBlocker.class);

        if (outputs.isEmpty()) {
            blockers.add(CompletenessBlocker.MISSING_PRODUCTION_OUTPUT);
            missing.add("No Maven production output directory (`target/classes`) was found. Run your usual build first.");
        }

        for (StoredComponent component : components) {
            if (!isExternalMavenComponent(component)) {
                continue;
            }
            addArtifact(mavenLocalRepository, component, artifacts, missing, blockers);
            if (isSpringOrAop(component)) {
                blockers.add(CompletenessBlocker.SPRING_OR_AOP_PRESENT);
            }
        }

        if (referencesReflection(outputs)) {
            blockers.add(CompletenessBlocker.REFLECTION_REFERENCED);
        }

        return new WorkspaceAnalysisInputs(
                outputs.stream().sorted().toList(),
                artifacts.stream().sorted(Comparator.comparing(artifact -> artifact.jar().toString())).toList(),
                List.copyOf(missing), Set.copyOf(blockers), fingerprint(outputs, artifacts));
    }

    /** Builds the exact read-only input for one mapped module and its SBOM dependency closure. */
    public WorkspaceAnalysisInputs discoverModule(Path productionOutput, Path mavenLocalRepository,
                                                   List<StoredComponent> dependencyClosure) {
        List<WorkspaceAnalysisInputs.ComponentArtifact> artifacts = new ArrayList<>();
        List<String> missing = new ArrayList<>();
        Set<CompletenessBlocker> blockers = EnumSet.noneOf(CompletenessBlocker.class);
        for (StoredComponent component : dependencyClosure) {
            if (!isExternalMavenComponent(component)) continue;
            addArtifact(mavenLocalRepository, component, artifacts, missing, blockers);
            if (isSpringOrAop(component)) blockers.add(CompletenessBlocker.SPRING_OR_AOP_PRESENT);
        }
        List<Path> outputs = List.of(productionOutput);
        if (referencesReflection(outputs)) blockers.add(CompletenessBlocker.REFLECTION_REFERENCED);
        List<WorkspaceAnalysisInputs.ComponentArtifact> sorted = artifacts.stream()
                .sorted(Comparator.comparing(artifact -> artifact.jar().toString())).toList();
        return new WorkspaceAnalysisInputs(outputs, sorted, List.copyOf(missing), Set.copyOf(blockers),
                fingerprint(outputs, sorted));
    }

    private List<Path> productionOutputs(Path workspace) {
        List<Path> outputs = new ArrayList<>();
        try {
            Files.walkFileTree(workspace, EnumSet.noneOf(java.nio.file.FileVisitOption.class),
                    MAX_WORKSPACE_DEPTH, new SimpleFileVisitor<>() {
                        @Override
                        public FileVisitResult preVisitDirectory(Path directory, BasicFileAttributes attributes) {
                            Path name = directory.getFileName();
                            if (name != null && (name.toString().equals(".git") || name.toString().equals("node_modules"))) {
                                return FileVisitResult.SKIP_SUBTREE;
                            }
                            if (name != null && name.toString().equals("classes")
                                    && directory.getParent() != null
                                    && directory.getParent().getFileName().toString().equals("target")) {
                                outputs.add(directory.toAbsolutePath().normalize());
                                return FileVisitResult.SKIP_SUBTREE;
                            }
                            return FileVisitResult.CONTINUE;
                        }
                    });
        } catch (IOException e) {
            throw new IllegalArgumentException("Could not inspect workspace outputs at " + workspace, e);
        }
        return outputs;
    }

    private boolean isExternalMavenComponent(StoredComponent component) {
        return component.scope() != DependencyScope.APPLICATION
                && component.purl() != null
                && component.purl().startsWith("pkg:maven/")
                && !component.purl().contains("type=pom")
                && nonBlank(component.group()) && nonBlank(component.name()) && nonBlank(component.version());
    }

    private void addArtifact(Path repository, StoredComponent component,
                             List<WorkspaceAnalysisInputs.ComponentArtifact> artifacts,
                             List<String> missing, Set<CompletenessBlocker> blockers) {
        try {
            Path jar = expectedJar(repository, component);
            if (Files.isRegularFile(jar) && Files.isReadable(jar)) {
                artifacts.add(new WorkspaceAnalysisInputs.ComponentArtifact(component.purl(), jar));
            } else {
                blockers.add(CompletenessBlocker.MISSING_DEPENDENCY_JAR);
                missing.add("Missing Maven artifact for %s: %s".formatted(component.coordinates(), jar));
            }
        } catch (IllegalArgumentException e) {
            blockers.add(CompletenessBlocker.MISSING_DEPENDENCY_JAR);
            missing.add("Rejected unsafe Maven coordinates for %s; no cache path was inspected."
                    .formatted(component.coordinates()));
        }
    }

    private Path expectedJar(Path repository, StoredComponent component) {
        Path root = repository.toAbsolutePath().normalize();
        Path relative = Path.of("");
        for (String groupSegment : component.group().split("\\.", -1)) {
            validateMavenSegment(groupSegment);
            relative = relative.resolve(groupSegment);
        }
        validateMavenSegment(component.name());
        validateMavenSegment(component.version());
        Path candidate = root.resolve(relative)
                .resolve(component.name())
                .resolve(component.version())
                .resolve(component.name() + "-" + component.version() + ".jar")
                .normalize();
        if (!candidate.startsWith(root) || candidate.equals(root)) {
            throw new IllegalArgumentException("Maven artifact path escaped the configured repository");
        }
        return candidate;
    }

    private void validateMavenSegment(String value) {
        if (value == null || value.isBlank() || value.equals(".") || value.equals("..")
                || value.indexOf('/') >= 0 || value.indexOf('\\') >= 0 || value.indexOf(':') >= 0
                || value.indexOf('\0') >= 0) {
            throw new IllegalArgumentException("Unsafe Maven path segment");
        }
        try {
            if (Path.of(value).isAbsolute()) throw new IllegalArgumentException("Absolute Maven path segment");
        } catch (java.nio.file.InvalidPathException e) {
            throw new IllegalArgumentException("Invalid Maven path segment", e);
        }
    }

    private boolean isSpringOrAop(StoredComponent component) {
        String group = component.group() == null ? "" : component.group().toLowerCase(Locale.ROOT);
        String name = component.name() == null ? "" : component.name().toLowerCase(Locale.ROOT);
        return group.startsWith("org.springframework") || group.startsWith("org.aspectj")
                || group.startsWith("net.bytebuddy") || name.contains("cglib") || name.contains("byte-buddy");
    }

    private boolean referencesReflection(List<Path> outputs) {
        for (Path output : outputs) {
            try (var files = Files.walk(output)) {
                boolean found = files.filter(path -> path.toString().endsWith(".class"))
                        .anyMatch(this::containsReflectionReference);
                if (found) {
                    return true;
                }
            } catch (IOException e) {
                throw new IllegalArgumentException("Could not inspect compiled output at " + output, e);
            }
        }
        return false;
    }

    private boolean containsReflectionReference(Path classFile) {
        try (InputStream input = Files.newInputStream(classFile)) {
            byte[] buffer = new byte[8192];
            int longestReference = java.util.Arrays.stream(REFLECTION_REFERENCES)
                    .mapToInt(reference -> reference.length).max().orElse(1);
            byte[] tail = new byte[longestReference - 1];
            int tailLength = 0;
            long inspected = 0;
            int read;
            while ((read = input.read(buffer)) != -1) {
                inspected += read;
                if (inspected > MAX_CLASS_INSPECTION_BYTES) return true;
                byte[] window = new byte[tailLength + read];
                System.arraycopy(tail, 0, window, 0, tailLength);
                System.arraycopy(buffer, 0, window, tailLength, read);
                for (byte[] reference : REFLECTION_REFERENCES) {
                    if (contains(window, reference)) return true;
                }
                tailLength = Math.min(tail.length, window.length);
                System.arraycopy(window, window.length - tailLength, tail, 0, tailLength);
            }
            return false;
        } catch (IOException e) {
            return true; // unreadable class is a conservative blocker, surfaced by missing input later.
        }
    }

    private boolean contains(byte[] content, byte[] sought) {
        outer:
        for (int offset = 0; offset <= content.length - sought.length; offset++) {
            for (int index = 0; index < sought.length; index++) {
                if (content[offset + index] != sought[index]) continue outer;
            }
            return true;
        }
        return false;
    }

    private String fingerprint(List<Path> outputs, List<WorkspaceAnalysisInputs.ComponentArtifact> artifacts) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            List<Path> allInputs = new ArrayList<>();
            for (Path output : outputs) {
                try (var files = Files.walk(output)) {
                    files.filter(Files::isRegularFile).forEach(allInputs::add);
                } catch (IOException e) {
                    allInputs.add(output);
                }
            }
            artifacts.stream().map(WorkspaceAnalysisInputs.ComponentArtifact::jar).forEach(allInputs::add);
            allInputs.stream().sorted().forEach(path -> updateFingerprint(digest, path));
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 must be available in every supported Java runtime", e);
        }
    }

    private void updateFingerprint(MessageDigest digest, Path path) {
        try {
            BasicFileAttributes attributes = Files.readAttributes(path, BasicFileAttributes.class);
            digest.update(path.toString().getBytes(StandardCharsets.UTF_8));
            digest.update(Long.toString(attributes.size()).getBytes(StandardCharsets.UTF_8));
            digest.update(Long.toString(attributes.lastModifiedTime().toMillis()).getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            digest.update(("unreadable:" + path).getBytes(StandardCharsets.UTF_8));
        }
    }

    private boolean nonBlank(String value) {
        return value != null && !value.isBlank();
    }
}
