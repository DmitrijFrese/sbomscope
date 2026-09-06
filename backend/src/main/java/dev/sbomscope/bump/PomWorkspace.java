package dev.sbomscope.bump;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Discovers the finite Maven model rooted at a workspace pom. */
public class PomWorkspace {

    private static final int MAX_MODULE_DEPTH = 12;

    public record ScannedPom(Path absolutePath, boolean contained, PomFile file,
                             PomScanner.PomScan scan) {}

    public record WorkspaceScan(Path root, List<ScannedPom> poms, List<String> notes) {
        public List<PomFile> files() {
            return poms.stream().map(ScannedPom::file).toList();
        }
    }

    private final PomScanner scanner;

    public PomWorkspace() {
        this(new PomScanner());
    }

    PomWorkspace(PomScanner scanner) {
        this.scanner = scanner;
    }

    public WorkspaceScan discover(Path workspace) {
        Path root = workspace.toAbsolutePath().normalize();
        Path rootPom = root.resolve("pom.xml").normalize();
        if (!Files.isRegularFile(rootPom)) {
            throw new IllegalArgumentException("The workspace holds no pom.xml");
        }

        Map<Path, ScannedPom> found = new LinkedHashMap<>();
        List<String> notes = new ArrayList<>();
        visit(rootPom, root, 0, found, notes);
        return new WorkspaceScan(root, List.copyOf(found.values()), List.copyOf(notes));
    }

    private void visit(Path candidate, Path root, int moduleDepth,
                       Map<Path, ScannedPom> found, List<String> notes) {
        Path absolute = candidate.toAbsolutePath().normalize();
        if (found.containsKey(absolute)) {
            return;
        }
        if (!Files.isReadable(absolute) || !Files.isRegularFile(absolute)) {
            notes.add("Could not read pom: " + displayPath(root, absolute));
            return;
        }

        boolean contained = absolute.startsWith(root);
        byte[] bytes;
        try {
            bytes = Files.readAllBytes(absolute);
        } catch (IOException e) {
            notes.add("Could not read pom: " + displayPath(root, absolute));
            return;
        }
        String text = new String(bytes, StandardCharsets.UTF_8);
        String path = displayPath(root, absolute);
        PomScanner.PomScan scan = scanner.scan(path, text);
        PomFile file = new PomFile(path, fingerprint(bytes), contained && Files.isWritable(absolute), text);
        found.put(absolute, new ScannedPom(absolute, contained, file, scan));

        if (!contained) {
            notes.add("Parent pom outside the workspace is read-only: " + path);
        }

        String relativeParent = scan.parentRelativePath();
        if (relativeParent != null && !relativeParent.isBlank()) {
            Path parent = absolute.getParent().resolve(relativeParent).normalize();
            visit(parent, root, moduleDepth, found, notes);
        }

        if (!contained) {
            return;
        }
        if (moduleDepth >= MAX_MODULE_DEPTH) {
            if (!scan.modules().isEmpty()) {
                notes.add("Module discovery stopped at depth " + MAX_MODULE_DEPTH + " in " + path);
            }
            return;
        }
        for (String module : scan.modules()) {
            Path modulePath = absolute.getParent().resolve(module).normalize();
            visit(modulePath.resolve("pom.xml"), root, moduleDepth + 1, found, notes);
        }
    }

    private String displayPath(Path root, Path path) {
        String value = path.startsWith(root) ? root.relativize(path).toString() : path.toString();
        return value.replace('\\', '/');
    }

    private String fingerprint(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }
}
