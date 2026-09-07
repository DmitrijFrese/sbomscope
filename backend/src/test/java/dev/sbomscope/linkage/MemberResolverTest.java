package dev.sbomscope.linkage;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class MemberResolverTest {

    private static final String INDEX = "dev/sbomscope/linkage/ClassMemberIndex";
    private static final MemberRef MISSING_MEMBER = new MemberRef(INDEX, "noSuchMemberAnywhere", "()V");

    @Test
    void resolvesADeclaredMember() throws IOException, URISyntaxException {
        assertThat(resolverWithPlatform().resolve(new MemberRef(INDEX, "read",
                "(Ljava/nio/file/Path;I)Ldev/sbomscope/linkage/ClassMemberIndex;")))
                .isEqualTo(Resolution.RESOLVED);
    }

    @Test
    void resolvesAnInheritedPlatformMember() throws IOException, URISyntaxException {
        assertThat(resolverWithPlatform().resolve(new MemberRef(INDEX, "toString", "()Ljava/lang/String;")))
                .isEqualTo(Resolution.RESOLVED);
    }

    @Test
    void resolvesAMemberThroughASuperinterface() throws IOException {
        MemberResolver resolver = MemberResolver.over(PlatformClasses.indexes());

        assertThat(resolver.resolve(new MemberRef("java/util/ArrayList", "stream",
                "()Ljava/util/stream/Stream;"))).isEqualTo(Resolution.RESOLVED);
    }

    @Test
    void reportsAGenuinelyAbsentMemberAsMissing() throws IOException, URISyntaxException {
        assertThat(resolverWithPlatform().resolve(MISSING_MEMBER)).isEqualTo(Resolution.MISSING);
    }

    @Test
    void reportsAnIncompleteHierarchyAsUnresolvable() throws IOException, URISyntaxException {
        MemberResolver resolver = MemberResolver.over(List.of(classesIndex()));

        assertThat(resolver.resolve(MISSING_MEMBER)).isEqualTo(Resolution.UNRESOLVABLE);
    }

    @Test
    void reportsAnUnknownOwnerAsUnresolvable() throws IOException, URISyntaxException {
        assertThat(resolverWithPlatform().resolve(new MemberRef("com/example/NotOnTheClasspath", "x", "()V")))
                .isEqualTo(Resolution.UNRESOLVABLE);
    }

    @Test
    void reportsAnArrayOwnerAsUnresolvable() throws IOException, URISyntaxException {
        assertThat(resolverWithPlatform().resolve(new MemberRef("[Ljava/lang/String;", "clone",
                "()Ljava/lang/Object;"))).isEqualTo(Resolution.UNRESOLVABLE);
    }

    @Test
    void retainsTheFirstClassInClasspathOrder() throws IOException, URISyntaxException {
        ClassMemberIndex first = classesIndex();
        ClassMemberIndex second = ClassMemberIndex.read(classesDirectory(), Runtime.version().feature());
        MemberResolver resolver = MemberResolver.over(List.of(first, second));

        assertThat(resolver.find(INDEX).orElseThrow()).isSameAs(first.find(INDEX).orElseThrow());
    }

    @Test
    void terminatesWhenAHierarchyContainsADiamond() throws IOException {
        MemberResolver resolver = MemberResolver.over(PlatformClasses.indexes());

        assertThat(resolver.resolve(new MemberRef("java/util/ArrayList", "stream",
                "()Ljava/util/stream/Stream;"))).isEqualTo(Resolution.RESOLVED);
    }

    private MemberResolver resolverWithPlatform() throws IOException, URISyntaxException {
        List<ClassMemberIndex> classpath = new ArrayList<>();
        classpath.add(classesIndex());
        classpath.addAll(PlatformClasses.indexes());
        return MemberResolver.over(classpath);
    }

    private ClassMemberIndex classesIndex() throws IOException, URISyntaxException {
        return ClassMemberIndex.read(classesDirectory(), Runtime.version().feature());
    }

    private Path classesDirectory() throws URISyntaxException {
        return Path.of(MemberResolver.class.getProtectionDomain().getCodeSource().getLocation().toURI());
    }
}
