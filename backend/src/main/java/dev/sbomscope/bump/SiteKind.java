package dev.sbomscope.bump;

public enum SiteKind {
    /** <dependency><version> in a module's own pom. */
    DIRECT,
    /** <dependencyManagement><dependency><version> in this workspace. */
    MANAGED,
    /** The version is ${property}; the property is defined in this workspace. */
    PROPERTY,
    /** The version comes from an imported BOM. Two remedies are offered, never one. */
    IMPORTED_BOM,
    /** Vulnerable transitive declared nowhere in the workspace. Structural remedy only. */
    UNDECLARED,
    /** A dependency in a package.json — dependencies, devDependencies or optionalDependencies. */
    NPM_DIRECT
}
