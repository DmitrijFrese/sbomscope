package dev.sbomscope.bump;

import java.util.List;

import dev.sbomscope.linkage.LinkageFinding;
import dev.sbomscope.linkage.LinkageVerdict;

/** The differential linkage answer for the dependency edits a reader selected. */
public record LinkageCheck(
        LinkageVerdict verdict,
        List<LinkageFinding> newlyMissing,
        int referencesChecked,
        List<String> notes) {}
