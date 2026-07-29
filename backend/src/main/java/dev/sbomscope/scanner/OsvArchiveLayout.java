package dev.sbomscope.scanner;

import java.nio.file.Path;

/**
 * Where the OSV archives live on disk.
 *
 * <p>A static helper rather than a method on {@link OsvDatabaseService}, because both that
 * service and {@link OsvArchiveMatcher} need it and the download has to be able to trigger
 * the index afterwards. Left as an instance method it made those two depend on each other,
 * and the layout is a fact about the filesystem rather than behaviour either of them owns.
 */
final class OsvArchiveLayout {

    private OsvArchiveLayout() {
    }

    /** Exactly the layout osv-scanner expects: {dir}/osv-scanner/{ecosystem}/all.zip */
    static Path archivePath(String databaseDirectory, String ecosystem) {
        return Path.of(databaseDirectory, "osv-scanner", ecosystem, "all.zip");
    }
}
