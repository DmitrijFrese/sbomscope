package dev.sbomscope.bump;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/** Discovers npm manifests the workspace actually contains. */
public class NpmWorkspace {

    private static final int MAX_WORKSPACE_DEPTH = 12;

    public record ScannedPackage(Path absolutePath, boolean contained, boolean hasLockfile,
                                 PomFile file, PackageJsonScanner.PackageScan scan) {}

    public record WorkspaceScan(Path root, List<ScannedPackage> packages, List<String> notes) {
        public List<PomFile> files() {
            return packages.stream().map(ScannedPackage::file).toList();
        }
    }

    private final PackageJsonScanner scanner;

    public NpmWorkspace() {
        this(new PackageJsonScanner());
    }

    NpmWorkspace(PackageJsonScanner scanner) {
        this.scanner = scanner;
    }

    public WorkspaceScan discover(Path workspace) {
        Path root = workspace.toAbsolutePath().normalize();
        Path rootManifest = root.resolve("package.json").normalize();
        Map<Path, ScannedPackage> found = new LinkedHashMap<>();
        List<String> notes = new ArrayList<>();
        packageJsonUnder(root, root, notes).forEach(path -> visit(path, root, found, notes));

        ScannedPackage rootPackage = found.get(rootManifest);
        if (rootPackage != null) {
            // The tree covers contained workspace patterns. Keep explicit external workspaces
            // visible as read-only instead of silently dropping their declarations.
            for (String workspacePattern : PackageJsonScanner.workspacePatterns(
                    rootPackage.file().path(), rootPackage.file().text())) {
                discoverExternalPattern(workspacePattern, root, found, notes);
            }
        }
        return new WorkspaceScan(root, List.copyOf(found.values()), List.copyOf(notes));
    }

    private void discoverExternalPattern(String workspacePattern, Path root,
                                         Map<Path, ScannedPackage> found, List<String> notes) {
        String pattern = workspacePattern.replace('\\', '/');
        while (pattern.endsWith("/")) {
            pattern = pattern.substring(0, pattern.length() - 1);
        }
        if (pattern.isBlank()) {
            return;
        }
        int wildcard = firstWildcard(pattern);
        if (wildcard < 0) {
            Path candidate = root.resolve(pattern).resolve("package.json").normalize();
            if (!candidate.startsWith(root)) {
                visit(candidate, root, found, notes);
            }
            return;
        }

        int slash = pattern.substring(0, wildcard).lastIndexOf('/');
        String prefix = slash < 0 ? "" : pattern.substring(0, slash);
        Path base = root.resolve(prefix).toAbsolutePath().normalize();
        if (!Files.isDirectory(base) || !Files.isReadable(base)) {
            notes.add("Could not read npm workspace path: " + displayPath(root, base));
            return;
        }
        if (base.startsWith(root)) {
            return;
        }

        Pattern matcher = Pattern.compile(globRegex(pattern));
        packageJsonUnder(base, root, notes).stream()
                .filter(path -> !path.startsWith(root))
                .filter(path -> matcher.matcher(relativePath(root, path.getParent())).matches())
                .forEach(path -> visit(path, root, found, notes));
    }

    private List<Path> packageJsonUnder(Path base, Path root, List<String> notes) {
        List<Path> paths = new ArrayList<>();
        try {
            Files.walkFileTree(base, java.util.Set.of(), MAX_WORKSPACE_DEPTH + 1,
                    new SimpleFileVisitor<>() {
                        @Override
                        public FileVisitResult preVisitDirectory(Path directory,
                                                                 BasicFileAttributes attributes) {
                            return directory.equals(base) || !ignoredDirectory(directory)
                                    ? FileVisitResult.CONTINUE : FileVisitResult.SKIP_SUBTREE;
                        }

                        @Override
                        public FileVisitResult visitFile(Path file, BasicFileAttributes attributes) {
                            if (attributes.isRegularFile()
                                    && "package.json".equals(file.getFileName().toString())) {
                                paths.add(file);
                            }
                            return FileVisitResult.CONTINUE;
                        }
                    });
        } catch (IOException exception) {
            notes.add("Could not read npm workspace path: " + displayPath(root, base));
        }
        paths.sort(Path::compareTo);
        return paths;
    }

    private boolean ignoredDirectory(Path directory) {
        String name = directory.getFileName().toString();
        return "node_modules".equals(name) || ".git".equals(name) || name.startsWith(".");
    }

    private ScannedPackage visit(Path candidate, Path root, Map<Path, ScannedPackage> found,
                                 List<String> notes) {
        Path absolute = candidate.toAbsolutePath().normalize();
        if (found.containsKey(absolute)) {
            return found.get(absolute);
        }
        if (!Files.isReadable(absolute) || !Files.isRegularFile(absolute)) {
            notes.add("Could not read package.json: " + displayPath(root, absolute));
            return null;
        }
        byte[] bytes;
        try {
            bytes = Files.readAllBytes(absolute);
        } catch (IOException exception) {
            notes.add("Could not read package.json: " + displayPath(root, absolute));
            return null;
        }
        boolean contained = absolute.startsWith(root);
        String path = displayPath(root, absolute);
        String text = new String(bytes, StandardCharsets.UTF_8);
        PomFile file = new PomFile(path, fingerprint(bytes), contained && Files.isWritable(absolute), text);
        ScannedPackage scanned = new ScannedPackage(absolute, contained,
                Files.isRegularFile(absolute.resolveSibling("package-lock.json")), file,
                scanner.scan(path, text));
        found.put(absolute, scanned);
        if (!contained) {
            notes.add("npm workspace outside the workspace is read-only: " + path);
        }
        return scanned;
    }

    private int firstWildcard(String pattern) {
        for (int index = 0; index < pattern.length(); index++) {
            if ("*?[{".indexOf(pattern.charAt(index)) >= 0) {
                return index;
            }
        }
        return -1;
    }

    private String globRegex(String glob) {
        StringBuilder regex = new StringBuilder("^");
        for (int index = 0; index < glob.length(); index++) {
            char value = glob.charAt(index);
            if (value == '*' && index + 1 < glob.length() && glob.charAt(index + 1) == '*') {
                if (index + 2 < glob.length() && glob.charAt(index + 2) == '/') {
                    regex.append("(?:.*/)?");
                    index += 2;
                } else {
                    regex.append(".*");
                    index++;
                }
            } else if (value == '*') {
                regex.append("[^/]*");
            } else if (value == '?') {
                regex.append("[^/]");
            } else if (value == '{' && glob.indexOf('}', index) > index) {
                int end = glob.indexOf('}', index);
                String[] alternatives = glob.substring(index + 1, end).split(",", -1);
                regex.append("(?:");
                for (int alternative = 0; alternative < alternatives.length; alternative++) {
                    if (alternative > 0) {
                        regex.append('|');
                    }
                    regex.append(Pattern.quote(alternatives[alternative]));
                }
                regex.append(')');
                index = end;
            } else if (value == '[' && glob.indexOf(']', index) > index) {
                int end = glob.indexOf(']', index);
                String characters = glob.substring(index + 1, end);
                regex.append('[');
                if (characters.startsWith("!")) {
                    regex.append('^').append(characters.substring(1));
                } else {
                    regex.append(characters);
                }
                regex.append(']');
                index = end;
            } else if (".()^$+|\\".indexOf(value) >= 0) {
                regex.append('\\').append(value);
            } else {
                regex.append(value);
            }
        }
        return regex.append('$').toString();
    }

    private String displayPath(Path root, Path path) {
        String value = path.startsWith(root) ? root.relativize(path).toString() : path.toString();
        return value.replace('\\', '/');
    }

    private String relativePath(Path root, Path path) {
        return root.relativize(path.toAbsolutePath().normalize()).toString().replace('\\', '/');
    }

    private String fingerprint(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }
}
