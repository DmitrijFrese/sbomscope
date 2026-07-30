package dev.sbomscope.probe;

/**
 * One of an owning module's direct dependencies, at the version it currently declares.
 *
 * <p>The whole-module probe needs the module's <em>entire</em> direct set, not just the one
 * ancestor being varied: Maven's nearest-wins resolution depends on every competing
 * declaration, and a component reached by two routes resolves through whichever one wins —
 * information a single-dependency POM cannot recover.
 */
public record ModuleDependency(MavenArtifact artifact, String version) {}
