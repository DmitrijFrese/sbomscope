package dev.sbomscope.linkage;

/**
 * UNRESOLVABLE is not a weaker MISSING: the supplied classpath lacks enough hierarchy to decide.
 * Only MISSING may be reported as a linkage error.
 */
public enum Resolution {
    RESOLVED,
    MISSING,
    UNRESOLVABLE
}
