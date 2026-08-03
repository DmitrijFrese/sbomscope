package dev.sbomscope.reachability;

/**
 * A fact that prevents a negative bytecode-only result from being treated as complete.
 *
 * <p>These are not errors. They explain why a graph may still be useful for a positive path
 * while remaining insufficient to say that no runtime route exists.
 */
public enum CompletenessBlocker {
    MISSING_PRODUCTION_OUTPUT,
    MISSING_DEPENDENCY_JAR,
    MODULE_MAPPING_INCOMPLETE,
    SPRING_OR_AOP_PRESENT,
    REFLECTION_REFERENCED
}
