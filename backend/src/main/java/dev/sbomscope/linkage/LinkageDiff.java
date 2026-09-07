package dev.sbomscope.linkage;

import java.util.List;

public record LinkageDiff(
        LinkageVerdict verdict,
        List<LinkageFinding> newlyMissing,
        int referencesChecked,
        int missingBefore,
        int missingAfter,
        int unresolvableAfter,
        List<String> warnings) {}
