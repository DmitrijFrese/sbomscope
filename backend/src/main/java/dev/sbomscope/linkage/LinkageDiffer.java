package dev.sbomscope.linkage;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/** Compares the linkage consequences of two supplied classpaths. */
public final class LinkageDiffer {

    private static final Comparator<MemberRef> MEMBER_ORDER = Comparator
            .comparing(MemberRef::owner)
            .thenComparing(MemberRef::name)
            .thenComparing(MemberRef::descriptor);

    private LinkageDiffer() {}

    /**
     * Each side carries its own consumers, and that is the whole correctness of this method.
     *
     * <p>The baseline is <em>today's artifacts against today's classpath</em>, not tomorrow's
     * artifacts against today's. Resolving the proposed jars' references against the current
     * classpath asks a meaningless question — code that does not exist yet cannot be broken today —
     * and it masks real findings: measured 2026-09-07 on the okhttp 3.0.1&rarr;4.9.2 / okio
     * 1.6.0&rarr;1.17.6 plan, sharing one consumer list reported 2 of the 9 newly broken
     * references, because the other 7 also failed to resolve against an okio that the old okhttp
     * never called into.
     *
     * @param beforeConsumers the project's own classes and dependency jars as they are now
     * @param afterConsumers  the same as they would be once the plan is applied
     */
    public static LinkageDiff between(List<ClassMemberIndex> beforeConsumers,
                                      MemberResolver before,
                                      List<ClassMemberIndex> afterConsumers,
                                      MemberResolver after) {
        List<String> warnings = new ArrayList<>();
        if (beforeConsumers.isEmpty() || afterConsumers.isEmpty()) {
            warnings.add("no consumer artifacts were supplied");
        }

        Map<MemberRef, Set<String>> beforeReferences = referencesOf(beforeConsumers, "current", warnings);
        Map<MemberRef, Set<String>> afterReferences = referencesOf(afterConsumers, "proposed", warnings);

        Set<MemberRef> examined = new TreeSet<>(MEMBER_ORDER);
        examined.addAll(beforeReferences.keySet());
        examined.addAll(afterReferences.keySet());
        if (examined.isEmpty()) {
            warnings.add("no member references were found to check");
        }

        Set<MemberRef> missingBeforeRefs = missing(beforeReferences.keySet(), before);
        Set<MemberRef> missingAfterRefs = missing(afterReferences.keySet(), after);

        int missingBefore = missingBeforeRefs.size();
        int missingAfter = missingAfterRefs.size();
        int unresolvableBefore = countUnresolvable(beforeReferences.keySet(), before);
        int unresolvableAfter = countUnresolvable(afterReferences.keySet(), after);

        List<LinkageFinding> newlyMissing = new ArrayList<>();
        for (MemberRef reference : missingAfterRefs) {
            if (!missingBeforeRefs.contains(reference)) {
                newlyMissing.add(new LinkageFinding(reference,
                        List.copyOf(afterReferences.getOrDefault(reference, Set.of()))));
            }
        }
        newlyMissing.sort(Comparator.comparing(LinkageFinding::reference, MEMBER_ORDER));

        if (!beforeReferences.isEmpty() && unresolvableBefore == beforeReferences.size()) {
            warnings.add("the current classpath resolved nothing");
        }
        if (!afterReferences.isEmpty() && unresolvableAfter == afterReferences.size()) {
            warnings.add("the proposed classpath resolved nothing");
        }

        LinkageVerdict verdict = !newlyMissing.isEmpty()
                ? LinkageVerdict.ERRORS_FOUND
                : warnings.isEmpty() ? LinkageVerdict.CLEAN : LinkageVerdict.UNCHECKED;
        return new LinkageDiff(verdict, List.copyOf(newlyMissing), examined.size(), missingBefore,
                missingAfter, unresolvableAfter, List.copyOf(warnings));
    }

    /**
     * References made by one side's consumers, attributed to the classes making them.
     *
     * <p>The "no classes" assertion is made about the side as a whole, deliberately, and not per
     * artifact. A single jar holding no classes is ordinary rather than broken — measured
     * 2026-09-07, resolving okhttp 4.9.2 pulls {@code kotlin-stdlib-common}, a Kotlin
     * multiplatform metadata artifact with **zero** class files. Warning per artifact fired on
     * that, and on an otherwise clean plan it would have forced the verdict to {@code UNCHECKED}
     * and made a working check look broken. A side where *nothing* yielded a class is still the
     * tooling failure the assertion was written for.
     */
    private static Map<MemberRef, Set<String>> referencesOf(List<ClassMemberIndex> consumers,
                                                            String side,
                                                            List<String> warnings) {
        Map<MemberRef, Set<String>> referencedBy = new LinkedHashMap<>();
        int classesSeen = 0;
        for (ClassMemberIndex consumer : consumers) {
            for (ClassMembers members : consumer.classes()) {
                classesSeen++;
                for (MemberRef reference : members.referenced()) {
                    referencedBy.computeIfAbsent(reference, ignored -> new TreeSet<>())
                            .add(members.internalName());
                }
            }
        }
        if (!consumers.isEmpty() && classesSeen == 0) {
            warnings.add("the " + side + " artifacts contain no classes");
        }
        return referencedBy;
    }

    private static Set<MemberRef> missing(Set<MemberRef> references, MemberResolver resolver) {
        Set<MemberRef> found = new TreeSet<>(MEMBER_ORDER);
        for (MemberRef reference : references) {
            if (resolver.resolve(reference) == Resolution.MISSING) {
                found.add(reference);
            }
        }
        return found;
    }

    private static int countUnresolvable(Set<MemberRef> references, MemberResolver resolver) {
        int total = 0;
        for (MemberRef reference : references) {
            if (resolver.resolve(reference) == Resolution.UNRESOLVABLE) {
                total++;
            }
        }
        return total;
    }
}
