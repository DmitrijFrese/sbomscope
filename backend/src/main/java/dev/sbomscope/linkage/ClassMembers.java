package dev.sbomscope.linkage;

import java.util.List;
import java.util.Set;

/** What one class file declares, and what it references. */
public record ClassMembers(
        String internalName,
        String superName,
        List<String> interfaceNames,
        int majorVersion,
        Set<MemberRef> declared,
        Set<MemberRef> referenced) {

    public ClassMembers {
        interfaceNames = List.copyOf(interfaceNames);
        declared = Set.copyOf(declared);
        referenced = Set.copyOf(referenced);
    }
}
