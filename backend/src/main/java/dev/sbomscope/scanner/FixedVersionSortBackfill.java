package dev.sbomscope.scanner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * Fills in the {@code fixed_version_sort} key for findings written before V3 added it.
 *
 * <p><b>Why this is not part of the migration.</b> The key is produced by
 * {@link VersionOrder#sortKey}, from the same parse the comparator uses, and writing it in SQL
 * would mean a second reading of what a version is living in a migration file — which is the
 * exact drift the column was introduced to remove. Migrations stay additive and declarative;
 * the value comes from the code that owns the rule.
 *
 * <p><b>Why it cannot be left undone.</b> A row with a fix version and no key sorts as though
 * the advisory named no fix. That is not a wrong position in a list, it is a false statement
 * about an advisory, and it would persist until that component happened to be re-scanned.
 *
 * <p>Runs after the application is serving, for the same reason the automatic scanner does: it
 * is work nobody asked for and it must not land on launch. One pass, then never again — the
 * insert path has written the key since V3, so a second run finds nothing.
 */
@Component
class FixedVersionSortBackfill {

    private static final Logger log = LoggerFactory.getLogger(FixedVersionSortBackfill.class);

    private final VulnerabilityRepository repository;

    FixedVersionSortBackfill(VulnerabilityRepository repository) {
        this.repository = repository;
    }

    @EventListener(ApplicationReadyEvent.class)
    void backfill() {
        try {
            int repaired = repository.backfillFixedVersionSortKeys();
            if (repaired > 0) {
                log.info("Filled in the fix-version sort key for {} finding(s)", repaired);
            }
        } catch (RuntimeException e) {
            // Nothing is waiting on this, and a findings table that sorts imperfectly is a far
            // smaller problem than an application that will not start.
            log.warn("Could not backfill fix-version sort keys", e);
        }
    }
}
