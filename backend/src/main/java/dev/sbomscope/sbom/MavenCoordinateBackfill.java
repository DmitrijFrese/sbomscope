package dev.sbomscope.sbom;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * Fills Maven qualifiers for components written before V12 added their columns.
 *
 * <p><b>Why this is not part of the migration.</b> The values come from
 * {@link PurlQualifierParser}, which the import path reads too, and writing the parse in SQL
 * would create a second interpretation of the purl grammar. Migrations stay additive and
 * declarative; the values come from the code that owns the rule.
 *
 * <p><b>Why it cannot be left undone.</b> A null classifier or type means the purl did not name
 * one. Leaving a qualifier-bearing row null would therefore be a false statement about an
 * existing component, and sorting, filtering and display would all repeat it.
 *
 * <p>Runs after the application is serving because this is work nobody asked for and it must
 * not land on launch. Imports write both columns from V12 onward, and the repository selects
 * only an unfilled qualifier, so a second run finds nothing.
 */
@Component
class MavenCoordinateBackfill {

    private static final Logger log = LoggerFactory.getLogger(MavenCoordinateBackfill.class);

    private final SbomRepository repository;

    MavenCoordinateBackfill(SbomRepository repository) {
        this.repository = repository;
    }

    @EventListener(ApplicationReadyEvent.class)
    void backfill() {
        try {
            int repaired = repository.backfillMavenCoordinates();
            if (repaired > 0) {
                log.info("Filled in Maven coordinates for {} component(s)", repaired);
            }
        } catch (RuntimeException e) {
            // Nothing is waiting on this, and incomplete optional coordinates are a smaller
            // problem than an application that will not start.
            log.warn("Could not backfill Maven coordinates", e);
        }
    }
}
