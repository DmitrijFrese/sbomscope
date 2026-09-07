package dev.sbomscope.linkage;

import java.util.ArrayDeque;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** Resolves a member reference against the classpath supplied by the caller. */
public final class MemberResolver {

    private final Map<String, ClassMembers> classes;

    private MemberResolver(Map<String, ClassMembers> classes) {
        this.classes = Map.copyOf(classes);
    }

    /**
     * @param classpath in classpath order; the first duplicate class is the one the JVM would load
     */
    public static MemberResolver over(List<ClassMemberIndex> classpath) {
        Map<String, ClassMembers> classes = new LinkedHashMap<>();
        for (ClassMemberIndex index : classpath) {
            for (ClassMembers members : index.classes()) {
                classes.putIfAbsent(members.internalName(), members);
            }
        }
        return new MemberResolver(classes);
    }

    public Resolution resolve(MemberRef reference) {
        if (reference.owner().startsWith("[")) {
            return Resolution.UNRESOLVABLE;
        }

        ArrayDeque<String> pending = new ArrayDeque<>();
        Set<String> visited = new LinkedHashSet<>();
        pending.add(reference.owner());
        boolean incomplete = false;
        while (!pending.isEmpty()) {
            String type = pending.remove();
            if (!visited.add(type)) {
                continue;
            }
            Optional<ClassMembers> members = find(type);
            if (members.isEmpty()) {
                incomplete = true;
                continue;
            }
            ClassMembers present = members.orElseThrow();
            if (declares(present, reference)) {
                return Resolution.RESOLVED;
            }
            if (present.superName() != null) {
                pending.add(present.superName());
            }
            pending.addAll(present.interfaceNames());
        }
        return incomplete ? Resolution.UNRESOLVABLE : Resolution.MISSING;
    }

    public Optional<ClassMembers> find(String internalName) {
        return Optional.ofNullable(classes.get(internalName));
    }

    private boolean declares(ClassMembers members, MemberRef reference) {
        return members.declared().stream().anyMatch(member ->
                member.name().equals(reference.name())
                        && member.descriptor().equals(reference.descriptor()));
    }
}
