package dev.sbomscope.linkage;

import java.io.IOException;
import java.net.URI;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** The running JVM's platform image, read through the jrt filesystem. */
public final class PlatformClasses {

    private static volatile List<ClassMemberIndex> indexes;

    private PlatformClasses() {
    }

    /** One index per platform module, memoised because the platform image cannot change while the JVM runs. */
    public static List<ClassMemberIndex> indexes() throws IOException {
        List<ClassMemberIndex> current = indexes;
        if (current != null) {
            return current;
        }
        synchronized (PlatformClasses.class) {
            current = indexes;
            if (current == null) {
                Path modules = FileSystems.getFileSystem(URI.create("jrt:/")).getPath("/modules");
                try (var entries = Files.list(modules)) {
                    List<Path> modulesInOrder = entries.toList();
                    List<ClassMemberIndex> loaded = new ArrayList<>();
                    for (Path module : modulesInOrder) {
                        loaded.add(ClassMemberIndex.read(module, Runtime.version().feature()));
                    }
                    current = List.copyOf(loaded);
                }
                indexes = current;
            }
            return current;
        }
    }

}
