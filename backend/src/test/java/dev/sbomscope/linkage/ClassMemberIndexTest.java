package dev.sbomscope.linkage;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import static org.assertj.core.api.Assertions.assertThat;

class ClassMemberIndexTest {

    @TempDir
    Path temporaryDirectory;

    @Test
    void readsClassFilesFromADirectory() throws IOException, URISyntaxException {
        ClassMemberIndex index = ClassMemberIndex.read(classesDirectory(), 21);

        assertThat(index.classes()).isNotEmpty();
        assertThat(index.find("dev/sbomscope/linkage/ClassMemberIndex")).isPresent();
        assertThat(index.find("dev/sbomscope/linkage/ClassMemberIndex").orElseThrow().declared())
                .anySatisfy(member -> assertThat(member)
                        .isEqualTo(new MemberRef("dev/sbomscope/linkage/ClassMemberIndex", "read",
                                "(Ljava/nio/file/Path;I)Ldev/sbomscope/linkage/ClassMemberIndex;")));
        assertThat(index.find("dev/sbomscope/linkage/ClassMemberIndex").orElseThrow().referenced())
                .isNotEmpty()
                .allSatisfy(member -> {
                    assertThat(member.owner()).isNotBlank();
                    assertThat(member.name()).isNotBlank();
                    assertThat(member.descriptor()).isNotBlank();
                });
        assertThat(index.classes()).noneMatch(members ->
                members.internalName().endsWith("module-info")
                        || members.internalName().endsWith("package-info"));
    }

    @Test
    void selectsTheApplicableMultiReleaseClassBody() throws IOException {
        Path jar = temporaryDirectory.resolve("multi-release.jar");
        writeJar(jar, true, resourceBytes(ClassMemberIndex.class), resourceBytes(MemberRef.class));

        ClassMemberIndex java21 = ClassMemberIndex.read(jar, 21);
        ClassMemberIndex java11 = ClassMemberIndex.read(jar, 11);

        assertThat(java21.classes()).hasSize(1);
        assertThat(java21.find("dev/sbomscope/linkage/MemberRef")).isPresent();
        assertThat(java11.classes()).hasSize(1);
        assertThat(java11.find("dev/sbomscope/linkage/ClassMemberIndex")).isPresent();
    }

    @Test
    void ignoresVersionedClassesWithoutTheMultiReleaseManifestAttribute() throws IOException {
        Path jar = temporaryDirectory.resolve("ordinary.jar");
        writeJar(jar, false, resourceBytes(ClassMemberIndex.class), resourceBytes(MemberRef.class));

        ClassMemberIndex index = ClassMemberIndex.read(jar, 21);

        assertThat(index.classes()).hasSize(1);
        assertThat(index.find("dev/sbomscope/linkage/ClassMemberIndex")).isPresent();
    }

    @Test
    void recordsUnreadableClassesAndContinues() throws IOException {
        Path jar = temporaryDirectory.resolve("bad.jar");
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        try (JarOutputStream output = new JarOutputStream(java.nio.file.Files.newOutputStream(jar), manifest)) {
            output.putNextEntry(new JarEntry("com/example/Bad.class"));
            output.write("not a class file".getBytes(StandardCharsets.UTF_8));
            output.closeEntry();
        }

        ClassMemberIndex index = ClassMemberIndex.read(jar, 21);

        assertThat(index.skipped()).hasSize(1);
        assertThat(index.skipped().getFirst()).startsWith("com/example/Bad.class:");
    }

    private Path classesDirectory() throws URISyntaxException {
        return Path.of(ClassMemberIndex.class.getProtectionDomain().getCodeSource().getLocation().toURI());
    }

    private void writeJar(Path jar, boolean multiRelease, byte[] baseBody, byte[] versionedBody)
            throws IOException {
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        if (multiRelease) {
            manifest.getMainAttributes().putValue("Multi-Release", "true");
        }
        try (JarOutputStream output = new JarOutputStream(java.nio.file.Files.newOutputStream(jar), manifest)) {
            writeEntry(output, "com/example/A.class", baseBody);
            writeEntry(output, "META-INF/versions/17/com/example/A.class", versionedBody);
        }
    }

    private void writeEntry(JarOutputStream output, String name, byte[] bytes) throws IOException {
        output.putNextEntry(new JarEntry(name));
        output.write(bytes);
        output.closeEntry();
    }

    private byte[] resourceBytes(Class<?> type) throws IOException {
        String path = "/" + type.getName().replace('.', '/') + ".class";
        try (InputStream stream = type.getResourceAsStream(path)) {
            return stream.readAllBytes();
        }
    }
}
