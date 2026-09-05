package dev.sbomscope.sbom;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * Fills version sort keys for components written before V13 added their column.
 *
 * <p><b>Why this is not part of the migration.</b> The key is produced by
 * {@link dev.sbomscope.scanner.VersionOrder#sortKey}, from the same parse the comparator uses,
 * and writing it in SQL would mean a second reading of what a version is living in a migration
 * file — which is the exact drift the column was introduced to remove. Migrations stay additive
 * and declarative; the value comes from the code that owns the rule.
 *
 * <p><b>Why it cannot be left undone.</b> A row with a version and no key sorts as though the
 * component named no version. That is not a wrong position in a list, it is a false statement
 * about a component, and it would persist until that SBOM happened to be uploaded again.
 *
 * <p>Runs after the application is serving because this is work nobody asked for and it must not
 * land on launch. Imports write the key from V13 onward, and the repository selects only an
 * unfilled, nonblank version, so a second run finds nothing.
 */
@Component
class ComponentVersionSortBackfill {

    private static final Logger log = LoggerFactory.getLogger(ComponentVersionSortBackfill.class);

    private final SbomRepository repository;

    ComponentVersionSortBackfill(SbomRepository repository) {
        this.repository = repository;
    }

    @EventListener(ApplicationReadyEvent.class)
    void backfill() {
        try {
            int repaired = repository.backfillVersionSortKeys();
            if (repaired > 0) {
                log.info("Filled in component-version sort keys for {} component(s)", repaired);
            }
        } catch (RuntimeException e) {
            // Nothing is waiting on this, and a findings table that sorts imperfectly is a far
            // smaller problem than an application that will not start.
            log.warn("Could not backfill component-version sort keys", e);
        }
    }
}
