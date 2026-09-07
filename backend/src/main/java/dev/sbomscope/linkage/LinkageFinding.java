package dev.sbomscope.linkage;

import java.util.List;

/** A reference that resolves in the current state and would not after the plan is applied. */
public record LinkageFinding(MemberRef reference, List<String> referencedBy) {}
