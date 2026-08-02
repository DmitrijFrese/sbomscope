package dev.sbomscope.maintenance;

/**
 * What a purge may erase.
 *
 * <p>Separate targets rather than one "delete everything" button, because they cost very
 * different amounts to get back. Uploaded SBOMs are a drag-and-drop away; the npm OSV
 * archive is a 200 MB download that a restricted machine may not be able to perform at all.
 */
public enum PurgeTarget {

    /** Uploaded SBOMs, their components and dependency edges, and the stored documents. */
    SBOMS,

    /**
     * The purl-keyed vulnerability cache — scan records and findings.
     *
     * <p>Separate from {@link #SBOMS} because it is deliberately shared across them: deleting
     * every SBOM leaves the cache intact, so re-uploading gives findings back without
     * re-running the scanner. Clearing it is a different intention.
     */
    FINDINGS,

    /** Scanner path, whether scanning is on, database directory, export preference. */
    SETTINGS,

    /** Offline OSV, KEV and EPSS source files and their derived database rows. */
    OSV_DATABASE,

    /** Inactive numbered log history only; the two files Logback is writing remain. */
    ROLLED_LOGS,

    /** SBOMscope's isolated Maven repository, never the user's ~/.m2. */
    MAVEN_PROBE_CACHE
}
