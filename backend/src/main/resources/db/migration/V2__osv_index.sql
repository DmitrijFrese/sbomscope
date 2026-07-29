-- V2 - the persisted advisory index that upgrade paths evaluate candidate versions against.
--
-- Additive rather than folded into V1, although constraint 8 still permits rewriting the
-- baseline while the repository is private. Folding is for migrations a later one would undo;
-- this introduces a genuinely new table that nothing supersedes, and the baseline is now
-- installed with real data in it, so rewriting would cost a database nobody needs to lose.
--
-- Why this exists at all: the OSV archives name their entries by advisory id, not by package,
-- so answering "which advisories concern this library" means parsing the whole archive -
-- measured at 5.2 seconds and ~152 MB retained for npm's 223,786 advisories. Holding that in
-- memory spent almost all of it on the 99% of packages a given project does not have. Parsed
-- once into here instead, a lookup is an indexed SELECT and nothing is retained.
--
-- This is derived data. It can be rebuilt from the archive at any time, and erasing the OSV
-- archives should take it with them.

-- What was indexed, and from which archive, so a replaced download rebuilds by itself.
CREATE TABLE osv_index_source (
    ecosystem  VARCHAR(32)              NOT NULL,

    -- Archive path, size and modification time. Compared rather than trusted: a refreshed
    -- download changes it, which is what invalidates the rows below without anyone having to
    -- remember to say so.
    identity   VARCHAR(1024)            NOT NULL,

    advisories INTEGER                  NOT NULL,
    packages   INTEGER                  NOT NULL,
    built_at   TIMESTAMP WITH TIME ZONE NOT NULL,

    CONSTRAINT pk_osv_index_source PRIMARY KEY (ecosystem)
);

-- One row per advisory per package it affects.
--
-- Per package rather than per advisory, because an advisory routinely covers several
-- coordinates - the Jackson advisory names both com.fasterxml.jackson.core and
-- tools.jackson.core - and evaluating a version against ranges belonging to a different
-- library is the mistake fixedVersionFor was written to avoid.
CREATE TABLE osv_index (
    ecosystem    VARCHAR(32)  NOT NULL,

    -- Lowercased on write, exactly as PackageKey normalises the scanner's own names, so both
    -- sides of the lookup agree.
    package_name VARCHAR(512) NOT NULL,

    osv_id       VARCHAR(128) NOT NULL,
    cve_id       VARCHAR(64),

    -- The advisory's own GHSA scale. Deliberately not a CVSS score: OSV stores severity as
    -- vector strings, and turning one into a number here would mean owning a CVSS
    -- implementation this project has already declined to write.
    rating       VARCHAR(32),

    -- The affected[] entries naming this package, as OSV wrote them. Kept as the source
    -- document rather than a decomposed form so AffectedVersions - the one place version
    -- ranges are interpreted - can read them unchanged.
    affected     CLOB         NOT NULL,

    CONSTRAINT pk_osv_index PRIMARY KEY (ecosystem, package_name, osv_id)
);

CREATE INDEX idx_osv_index_lookup ON osv_index (ecosystem, package_name);
