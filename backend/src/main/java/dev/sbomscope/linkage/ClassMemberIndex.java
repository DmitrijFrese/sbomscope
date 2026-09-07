package dev.sbomscope.linkage;

import com.ibm.wala.shrike.shrikeCT.ClassConstants;
import com.ibm.wala.shrike.shrikeCT.ClassReader;
import com.ibm.wala.shrike.shrikeCT.ConstantPoolParser;
import com.ibm.wala.shrike.shrikeCT.InvalidClassFileException;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

/**
 * Reads the member declarations and member references already encoded in class files.
 * Resolution is deliberately left to the later linkage stages.
 */
public final class ClassMemberIndex {

    private static final String VERSIONS_PREFIX = "META-INF/versions/";

    private final Map<String, ClassMembers> classes;
    private final Set<MemberRef> declared;
    private final Set<MemberRef> referenced;
    private final List<String> skipped;

    private ClassMemberIndex(Map<String, ClassMembers> classes, List<String> skipped) {
        this.classes = Map.copyOf(classes);
        this.declared = union(classes.values(), ClassMembers::declared);
        this.referenced = union(classes.values(), ClassMembers::referenced);
        this.skipped = List.copyOf(skipped);
    }

    /**
     * @param artifact      a jar file, or a directory containing class files
     * @param targetRelease Java feature release that selects multi-release jar variants
     * @throws IOException when the artifact cannot be opened
     */
    public static ClassMemberIndex read(Path artifact, int targetRelease) throws IOException {
        if (!Files.exists(artifact)) {
            throw new IOException("Artifact does not exist: " + artifact);
        }

        Map<String, ClassMembers> classes = new LinkedHashMap<>();
        List<String> skipped = new ArrayList<>();
        if (Files.isDirectory(artifact)) {
            readDirectory(artifact, classes, skipped);
        } else {
            readJar(artifact, targetRelease, classes, skipped);
        }
        return new ClassMemberIndex(classes, skipped);
    }

    /**
     * An index over already-read classes. The reading factory is the usual entry point; this exists so
     * a caller — a test, or a stage assembling a partial view — can build an index without a file.
     */
    public static ClassMemberIndex of(Collection<ClassMembers> classes) {
        Map<String, ClassMembers> byInternalName = new LinkedHashMap<>();
        for (ClassMembers members : classes) {
            byInternalName.putIfAbsent(members.internalName(), members);
        }
        return new ClassMemberIndex(byInternalName, List.of());
    }

    public Collection<ClassMembers> classes() {
        return classes.values();
    }

    public Optional<ClassMembers> find(String internalName) {
        return Optional.ofNullable(classes.get(internalName));
    }

    /** The union over every class. */
    public Set<MemberRef> declared() {
        return declared;
    }

    /** The union over every class. */
    public Set<MemberRef> referenced() {
        return referenced;
    }

    /** One entry per unreadable class file, as {@code <entry path>: <reason>}. */
    public List<String> skipped() {
        return skipped;
    }

    private static void readDirectory(Path directory, Map<String, ClassMembers> classes,
                                      List<String> skipped) throws IOException {
        try (var paths = Files.walk(directory)) {
            for (Path path : paths.filter(Files::isRegularFile)
                    .sorted(Comparator.comparing(path -> path.toString()))
                    .toList()) {
                String entryPath = directory.relativize(path).toString().replace('\\', '/');
                if (isClassEntry(entryPath)) {
                    readClass(entryPath, Files.readAllBytes(path), classes, skipped);
                }
            }
        }
    }

    private static void readJar(Path artifact, int targetRelease, Map<String, ClassMembers> classes,
                                List<String> skipped) throws IOException {
        try (JarFile jar = new JarFile(artifact.toFile())) {
            boolean multiRelease = isMultiRelease(jar.getManifest());
            Map<String, JarEntry> entries = selectEntries(jar, multiRelease, targetRelease);
            for (Map.Entry<String, JarEntry> selected : entries.entrySet()) {
                try (InputStream stream = jar.getInputStream(selected.getValue())) {
                    readClass(selected.getValue().getName(), stream.readAllBytes(), classes, skipped);
                }
            }
        }
    }

    private static Map<String, JarEntry> selectEntries(JarFile jar, boolean multiRelease,
                                                         int targetRelease) {
        Map<String, VersionedEntry> selected = new LinkedHashMap<>();
        List<JarEntry> entries = jar.stream()
                .filter(entry -> !entry.isDirectory())
                .filter(entry -> entry.getName().endsWith(".class"))
                .sorted(Comparator.comparing(JarEntry::getName))
                .toList();
        for (JarEntry entry : entries) {
            String entryPath = entry.getName();
            if (entryPath.startsWith(VERSIONS_PREFIX)) {
                if (!multiRelease) {
                    continue;
                }
                VersionedPath versioned = versionedPath(entryPath);
                if (versioned == null || versioned.release() < 9 || versioned.release() > targetRelease
                        || !isClassEntry(versioned.basePath())) {
                    continue;
                }
                replaceIfNewer(selected, versioned.basePath(), entry, versioned.release());
            } else if (isClassEntry(entryPath)) {
                replaceIfNewer(selected, entryPath, entry, 0);
            }
        }
        Map<String, JarEntry> result = new LinkedHashMap<>();
        selected.forEach((path, entry) -> result.put(path, entry.entry()));
        return result;
    }

    private static void replaceIfNewer(Map<String, VersionedEntry> selected, String basePath,
                                       JarEntry entry, int release) {
        VersionedEntry previous = selected.get(basePath);
        if (previous == null || release > previous.release()) {
            selected.put(basePath, new VersionedEntry(entry, release));
        }
    }

    private static VersionedPath versionedPath(String entryPath) {
        String remainder = entryPath.substring(VERSIONS_PREFIX.length());
        int separator = remainder.indexOf('/');
        if (separator < 1 || separator == remainder.length() - 1) {
            return null;
        }
        try {
            return new VersionedPath(Integer.parseInt(remainder.substring(0, separator)),
                    remainder.substring(separator + 1));
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private static boolean isMultiRelease(Manifest manifest) {
        if (manifest == null) {
            return false;
        }
        for (Map.Entry<Object, Object> attribute : manifest.getMainAttributes().entrySet()) {
            if (attribute.getKey() instanceof Attributes.Name name
                    && name.toString().equalsIgnoreCase("Multi-Release")) {
                return attribute.getValue().toString().equalsIgnoreCase("true");
            }
        }
        return false;
    }

    private static boolean isClassEntry(String entryPath) {
        return entryPath.endsWith(".class")
                && !hasFileName(entryPath, "module-info.class")
                && !hasFileName(entryPath, "package-info.class");
    }

    private static boolean hasFileName(String entryPath, String fileName) {
        return entryPath.equals(fileName) || entryPath.endsWith("/" + fileName);
    }

    private static void readClass(String entryPath, byte[] bytes, Map<String, ClassMembers> classes,
                                  List<String> skipped) {
        try {
            ClassMembers members = readClass(bytes);
            classes.put(members.internalName(), members);
        } catch (InvalidClassFileException | RuntimeException exception) {
            skipped.add(entryPath + ": " + reason(exception));
        }
    }

    private static ClassMembers readClass(byte[] bytes) throws InvalidClassFileException {
        ClassReader reader = new ClassReader(bytes);
        String internalName = reader.getName();
        Set<MemberRef> declared = new LinkedHashSet<>();
        for (int i = 0; i < reader.getFieldCount(); i++) {
            declared.add(new MemberRef(internalName, reader.getFieldName(i), reader.getFieldType(i)));
        }
        for (int i = 0; i < reader.getMethodCount(); i++) {
            declared.add(new MemberRef(internalName, reader.getMethodName(i), reader.getMethodType(i)));
        }

        Set<MemberRef> referenced = new LinkedHashSet<>();
        ConstantPoolParser constantPool = reader.getCP();
        for (int i = 1; i < constantPool.getItemCount(); i++) {
            byte itemType;
            try {
                itemType = constantPool.getItemType(i);
            } catch (IllegalArgumentException ignored) {
                continue;
            }
            if (itemType == ClassConstants.CONSTANT_FieldRef
                    || itemType == ClassConstants.CONSTANT_MethodRef
                    || itemType == ClassConstants.CONSTANT_InterfaceMethodRef) {
                referenced.add(new MemberRef(constantPool.getCPRefClass(i),
                        constantPool.getCPRefName(i), constantPool.getCPRefType(i)));
            }
        }
        return new ClassMembers(internalName, reader.getSuperName(), List.of(reader.getInterfaceNames()),
                reader.getMajorVersion(), declared, referenced);
    }

    private static String reason(Exception exception) {
        return exception.getMessage() == null ? exception.getClass().getSimpleName() : exception.getMessage();
    }

    private static Set<MemberRef> union(Collection<ClassMembers> classes,
                                        java.util.function.Function<ClassMembers, Set<MemberRef>> members) {
        Set<MemberRef> result = new LinkedHashSet<>();
        for (ClassMembers classMembers : classes) {
            result.addAll(members.apply(classMembers));
        }
        return Set.copyOf(result);
    }

    private record VersionedPath(int release, String basePath) {}

    private record VersionedEntry(JarEntry entry, int release) {}
}
