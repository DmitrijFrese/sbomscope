-- V12 - Maven type and classifier qualifiers used for display and query behaviour (B25).
--
-- Additive, as constraint 8 requires. Existing rows are filled after the application is
-- serving by MavenCoordinateBackfill: the purl parse belongs in Java beside the import path,
-- not as a second implementation embedded in this migration.
--
-- Both columns are nullable. npm has neither value, and an absent Maven qualifier is a real
-- statement that must stay distinguishable from one explicitly written in the purl. In
-- particular, Maven defaults an absent type to jar for execution, but storage records what the
-- document said rather than synthesising that default.
--
-- The maven_ prefix is deliberate. component_type already means the CycloneDX component kind
-- (library, application, framework); Maven's type means jar, pom, test-jar or war. Calling both
-- fields "type" would leave two permanently similar names for different concepts on one row.

-- One statement per column, as V3 and V8 already do here. H2 rejects several ADD COLUMN
-- clauses in a single ALTER TABLE, and a migration that cannot run is worse than a verbose one.

ALTER TABLE component
    ADD COLUMN maven_type VARCHAR(256);

ALTER TABLE component
    ADD COLUMN maven_classifier VARCHAR(256);
