package dev.sbomscope.linkage;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class LinkageDifferTest {

    private static final ClassMembers OBJECT = members("java/lang/Object", null, Set.of(), Set.of());
    private static final MemberRef GONE = new MemberRef("com/example/Api", "gone", "()V");

    @Test
    void reportsAMemberThatDisappearsWithItsConsumer() {
        ClassMemberIndex consumers = consumers(GONE);
        LinkageDiff diff = LinkageDiffer.between(List.of(consumers), resolver(api(GONE)), List.of(consumers), resolver(api()));

        assertThat(diff.newlyMissing()).containsExactly(new LinkageFinding(GONE, List.of("com/example/Consumer")));
        assertThat(diff.verdict()).isEqualTo(LinkageVerdict.ERRORS_FOUND);
        assertThat(diff.missingBefore()).isZero();
        assertThat(diff.missingAfter()).isEqualTo(1);
    }

    @Test
    void reportsNoDifferenceForAnUnchangedClasspath() {
        ClassMemberIndex consumers = consumers(GONE);
        MemberResolver resolver = resolver(api(GONE));

        LinkageDiff diff = LinkageDiffer.between(List.of(consumers), resolver, List.of(consumers), resolver);

        assertThat(diff.newlyMissing()).isEmpty();
        assertThat(diff.verdict()).isEqualTo(LinkageVerdict.CLEAN);
        assertThat(diff.warnings()).isEmpty();
    }

    @Test
    void doesNotReportPreExistingBreakage() {
        LinkageDiff diff = LinkageDiffer.between(List.of(consumers(GONE)), resolver(api()), List.of(consumers(GONE)), resolver(api()));

        assertThat(diff.newlyMissing()).isEmpty();
        assertThat(diff.missingBefore()).isEqualTo(1);
        assertThat(diff.missingAfter()).isEqualTo(1);
        assertThat(diff.verdict()).isEqualTo(LinkageVerdict.CLEAN);
    }

    @Test
    void reportsAMissingMemberWhenTheBeforeStateWasUnresolvable() {
        LinkageDiff diff = LinkageDiffer.between(List.of(consumers(GONE)),
                MemberResolver.over(List.of(standardLibrary())), List.of(consumers(GONE)), resolver(api()));

        assertThat(diff.newlyMissing()).containsExactly(new LinkageFinding(GONE, List.of("com/example/Consumer")));
        assertThat(diff.verdict()).isEqualTo(LinkageVerdict.ERRORS_FOUND);
        assertThat(diff.warnings()).contains("the current classpath resolved nothing");
    }

    @Test
    void warnsWhenAConsumerHasNoReferences() {
        ClassMemberIndex consumers = ClassMemberIndex.of(List.of(
                members("com/example/Consumer", "java/lang/Object", Set.of(), Set.of())));

        LinkageDiff diff = LinkageDiffer.between(List.of(consumers), resolver(), List.of(consumers), resolver());

        assertThat(diff.referencesChecked()).isZero();
        assertThat(diff.warnings()).containsExactly("no member references were found to check");
        assertThat(diff.verdict()).isEqualTo(LinkageVerdict.UNCHECKED);
    }

    @Test
    void warnsIndependentlyWhenEitherResolverResolvesNothing() {
        ClassMemberIndex consumers = consumers(GONE);
        MemberResolver working = resolver(api(GONE));

        LinkageDiff missingBefore = LinkageDiffer.between(List.of(consumers),
                MemberResolver.over(List.of()), List.of(consumers), working);
        LinkageDiff missingAfter = LinkageDiffer.between(List.of(consumers), working, List.of(consumers),
                MemberResolver.over(List.of()));

        assertThat(missingBefore.warnings()).contains("the current classpath resolved nothing");
        assertThat(missingAfter.warnings()).contains("the proposed classpath resolved nothing");
    }

    @Test
    void sortsFindingsByOwnerNameAndDescriptor() {
        MemberRef zeta = new MemberRef("z/Api", "gone", "()V");
        MemberRef alphaZ = new MemberRef("a/Api", "z", "()V");
        MemberRef alphaA = new MemberRef("a/Api", "a", "(I)V");
        ClassMemberIndex consumers = consumers(zeta, alphaZ, alphaA);
        MemberResolver before = resolver(api(zeta), api(alphaZ), api(alphaA));
        MemberResolver after = resolver(api("z/Api"), api("a/Api"));

        LinkageDiff diff = LinkageDiffer.between(List.of(consumers), before, List.of(consumers), after);

        assertThat(diff.newlyMissing()).extracting(LinkageFinding::reference)
                .containsExactly(alphaA, alphaZ, zeta);
    }

    @Test
    void keepsFindingsWhenSanityWarningsFire() {
        LinkageDiff diff = LinkageDiffer.between(List.of(consumers(GONE)), MemberResolver.over(List.of()),
                List.of(consumers(GONE)), resolver(api()));

        assertThat(diff.verdict()).isEqualTo(LinkageVerdict.ERRORS_FOUND);
        assertThat(diff.warnings()).contains("the current classpath resolved nothing");
        assertThat(diff.newlyMissing()).containsExactly(new LinkageFinding(GONE, List.of("com/example/Consumer")));
    }

    @Test
    void isQuietForRealClassesOnAnUnchangedClasspath() throws IOException, URISyntaxException {
        Path classesDirectory = Path.of(LinkageDiffer.class.getProtectionDomain()
                .getCodeSource().getLocation().toURI());
        ClassMemberIndex classes = ClassMemberIndex.read(classesDirectory, Runtime.version().feature());
        List<ClassMemberIndex> classpath = new ArrayList<>();
        classpath.add(classes);
        classpath.addAll(PlatformClasses.indexes());
        MemberResolver resolver = MemberResolver.over(classpath);

        LinkageDiff diff = LinkageDiffer.between(List.of(classes), resolver, List.of(classes), resolver);

        assertThat(diff.referencesChecked()).isGreaterThan(0);
        assertThat(diff.newlyMissing()).isEmpty();
        assertThat(diff.verdict()).isEqualTo(LinkageVerdict.CLEAN);
    }

    /**
     * The baseline is today's artifacts, not tomorrow's resolved against today's classpath.
     *
     * <p>Found by running the real thing on 2026-09-07: sharing one consumer list between the two
     * sides reported 2 of the 9 references the okhttp/okio plan actually broke, because the other
     * 7 also failed to resolve against the old okio — an old library cannot break on a call the
     * old code never made. Every element of that mask is reproduced here in miniature.
     */
    @Test
    void usesEachSidesOwnConsumersSoTheBaselineCannotMaskAFinding() {
        MemberRef onlyCalledAfter = new MemberRef("com/example/Api", "addedCall", "()V");

        // Today: the old consumer never calls it, and today's classpath is sound.
        ClassMemberIndex today = ClassMemberIndex.of(List.of(
                members("com/example/Consumer", "java/lang/Object", Set.of(), Set.of())));
        MemberResolver todayClasspath = resolver(api());

        // Planned: the new consumer calls it, and the planned classpath does not declare it.
        ClassMemberIndex planned = consumers(onlyCalledAfter);
        MemberResolver plannedClasspath = resolver(api());

        LinkageDiff perSide = LinkageDiffer.between(List.of(today), todayClasspath,
                List.of(planned), plannedClasspath);

        assertThat(perSide.newlyMissing())
                .containsExactly(new LinkageFinding(onlyCalledAfter, List.of("com/example/Consumer")));
        assertThat(perSide.verdict()).isEqualTo(LinkageVerdict.ERRORS_FOUND);

        // Sharing the planned consumers for both sides masks it: the reference is MISSING on both,
        // so the difference is empty and the screen would report the plan as safe.
        LinkageDiff shared = LinkageDiffer.between(List.of(planned), todayClasspath,
                List.of(planned), plannedClasspath);
        assertThat(shared.newlyMissing()).isEmpty();
    }

    /**
     * A jar with no classes is ordinary, not broken. Found live on 2026-09-07: resolving
     * okhttp 4.9.2 pulls {@code kotlin-stdlib-common}, a multiplatform metadata artifact holding
     * zero class files. A per-artifact assertion fired on it, and on an otherwise clean plan that
     * would have forced UNCHECKED and made a working check look broken.
     */
    @Test
    void doesNotWarnAboutOneClasslessArtifactBesideArtifactsThatHaveClasses() {
        ClassMemberIndex metadataOnlyJar = ClassMemberIndex.of(List.of());
        ClassMemberIndex realJar = consumers(GONE);
        MemberResolver resolver = resolver(api(GONE));

        LinkageDiff diff = LinkageDiffer.between(
                List.of(metadataOnlyJar, realJar), resolver,
                List.of(metadataOnlyJar, realJar), resolver);

        assertThat(diff.warnings()).isEmpty();
        assertThat(diff.verdict()).isEqualTo(LinkageVerdict.CLEAN);
    }

    @Test
    void warnsWhenAWholeSideYieldsNoClasses() {
        ClassMemberIndex empty = ClassMemberIndex.of(List.of());
        MemberResolver resolver = resolver(api(GONE));

        LinkageDiff diff = LinkageDiffer.between(
                List.of(empty), resolver, List.of(consumers(GONE)), resolver);

        assertThat(diff.warnings()).contains("the current artifacts contain no classes");
        assertThat(diff.verdict()).isNotEqualTo(LinkageVerdict.CLEAN);
    }

    private static ClassMemberIndex consumers(MemberRef... references) {
        return ClassMemberIndex.of(List.of(members("com/example/Consumer", "java/lang/Object", Set.of(),
                Set.of(references))));
    }

    private static MemberResolver resolver(ClassMembers... classes) {
        List<ClassMembers> allClasses = new ArrayList<>();
        allClasses.add(OBJECT);
        allClasses.addAll(List.of(classes));
        return MemberResolver.over(List.of(ClassMemberIndex.of(allClasses)));
    }

    private static ClassMemberIndex standardLibrary() {
        return ClassMemberIndex.of(List.of(OBJECT));
    }

    private static ClassMembers api(MemberRef... declared) {
        return api("com/example/Api", declared);
    }

    private static ClassMembers api(String internalName, MemberRef... declared) {
        return members(internalName, "java/lang/Object", Set.of(declared), Set.of());
    }

    private static ClassMembers members(String internalName, String superName, Set<MemberRef> declared,
                                        Set<MemberRef> referenced) {
        return new ClassMembers(internalName, superName, List.of(), 61, declared, referenced);
    }
}
