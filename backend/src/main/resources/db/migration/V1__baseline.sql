-- V1 - baseline schema.
--
-- This file replaces the original V1-V4. They were squashed while SBOMscope was still
-- pre-release with a single user, because V4 had already introduced a column that V5 would
-- have had to remove: a reader would have met `is_direct BOOLEAN` in one migration and had
-- to reconstruct the history to learn it no longer exists. One file, one current truth.
--
-- The squash is a one-time break. Any database created by the earlier migrations will fail
-- to start against this file - Flyway sees V1's checksum change and V2-V4 recorded but
-- absent - and the fix is to delete ~/.sbomscope/db/sbomscope.mv.db with the application
-- stopped, leaving ~/.sbomscope/osv-db alone. Settings live in this database, so the
-- scanner path has to be entered again afterwards.
--
-- Squashing stops here. Once the repository is public and there are installations that are
-- not the maintainer's, migrations become strictly additive. See constraint 8 in AGENTS.md.

-- An uploaded document, plus the optional workspace it is associated with.
CREATE TABLE sbom (
    id              UUID                     NOT NULL,
    filename        VARCHAR(512)             NOT NULL,
    uploaded_at     TIMESTAMP WITH TIME ZONE NOT NULL,
    -- Null when the user uploaded an SBOM without pointing at a source tree;
    -- workspace usage detection is optional by design.
    workspace_path  VARCHAR(4096),
    spec_version    VARCHAR(32),
    component_count INTEGER                  NOT NULL DEFAULT 0,

    CONSTRAINT pk_sbom PRIMARY KEY (id)
);

CREATE INDEX idx_sbom_uploaded_at ON sbom (uploaded_at DESC);

-- One library within one SBOM.
--
-- Components are stored per SBOM rather than globally: the same library at the same
-- version can legitimately appear in several SBOMs with different graph positions, and
-- deleting an SBOM must not disturb the others. Cross-SBOM sharing happens at the
-- vulnerability cache layer instead, keyed by purl.
CREATE TABLE component (
    id             UUID          NOT NULL,
    sbom_id        UUID          NOT NULL,

    -- The SBOM-internal identifier ("bom-ref") that the dependency graph points at.
    -- Unique only within its own SBOM, which is why it is not a global key.
    bom_ref        VARCHAR(1024) NOT NULL,

    group_name     VARCHAR(512),
    name           VARCHAR(512)  NOT NULL,
    version        VARCHAR(256),
    purl           VARCHAR(2048),
    component_type VARCHAR(64),

    -- The component the document describes, as opposed to one of its dependencies.
    is_root        BOOLEAN       NOT NULL DEFAULT FALSE,

    -- Where this sits relative to the code being described:
    --
    --   APPLICATION  your own code - the root, and the sibling modules of a multi-module
    --                build, which are not dependencies you can upgrade
    --   DIRECT       declared by your own code, i.e. what is written in pom.xml or
    --                package.json
    --   TRANSITIVE   pulled in by something else
    --
    -- Replaces an earlier is_direct boolean, which could only describe "depended on by the
    -- root". In an aggregate Maven build the root is the parent pom and its direct
    -- dependencies are the project's own modules, so every genuinely declared dependency
    -- was reported as transitive and nothing useful was reported as direct.
    dependency_scope VARCHAR(16) NOT NULL DEFAULT 'TRANSITIVE',

    CONSTRAINT pk_component PRIMARY KEY (id),
    CONSTRAINT fk_component_sbom FOREIGN KEY (sbom_id) REFERENCES sbom (id) ON DELETE CASCADE,
    CONSTRAINT uq_component_bom_ref UNIQUE (sbom_id, bom_ref),
    CONSTRAINT ck_component_scope CHECK (dependency_scope IN ('APPLICATION', 'DIRECT', 'TRANSITIVE'))
);

CREATE INDEX idx_component_sbom ON component (sbom_id);
CREATE INDEX idx_component_purl ON component (purl);
CREATE INDEX idx_component_name ON component (sbom_id, name);

-- Edges of the dependency graph, as declared by the SBOM's "dependencies" array.
-- Stored by bom-ref rather than component id so an edge can be written without resolving
-- both endpoints first, and so dangling references in a malformed SBOM degrade into a
-- missing node rather than a failed import.
CREATE TABLE component_dependency (
    sbom_id      UUID          NOT NULL,
    from_bom_ref VARCHAR(1024) NOT NULL,
    to_bom_ref   VARCHAR(1024) NOT NULL,

    CONSTRAINT pk_component_dependency PRIMARY KEY (sbom_id, from_bom_ref, to_bom_ref),
    CONSTRAINT fk_dependency_sbom FOREIGN KEY (sbom_id) REFERENCES sbom (id) ON DELETE CASCADE
);

CREATE INDEX idx_dependency_from ON component_dependency (sbom_id, from_bom_ref);
CREATE INDEX idx_dependency_to ON component_dependency (sbom_id, to_bom_ref);

-- Settings the user changes from the UI live here rather than in application.yml, so no
-- file editing or restart is needed. Secrets deliberately do not: a value sitting in the
-- database is trivially readable and travels with any backup.
CREATE TABLE app_setting (
    setting_key   VARCHAR(128)             NOT NULL,
    setting_value VARCHAR(4096),
    updated_at    TIMESTAMP WITH TIME ZONE NOT NULL,

    CONSTRAINT pk_app_setting PRIMARY KEY (setting_key)
);

-- One row per component that has been scanned, whether or not anything was found.
-- Without this, "no vulnerabilities" and "never checked" would be indistinguishable - a
-- dangerous ambiguity in a security tool rather than a cosmetic one.
CREATE TABLE vulnerability_scan (
    purl            VARCHAR(2048)            NOT NULL,
    scanned_at      TIMESTAMP WITH TIME ZONE NOT NULL,
    scanner_version VARCHAR(128),

    CONSTRAINT pk_vulnerability_scan PRIMARY KEY (purl)
);

CREATE INDEX idx_vulnerability_scan_scanned_at ON vulnerability_scan (scanned_at);

-- Findings are keyed by purl rather than by component row, so results are shared across
-- every SBOM containing the same library at the same version: scanning one project
-- benefits the next, and the findings view joins on purl at query time.
CREATE TABLE vulnerability_finding (
    id              UUID          NOT NULL,
    purl            VARCHAR(2048) NOT NULL,

    -- The advisory's own identifier, typically GHSA-*. Advisories aliasing each other
    -- are collapsed by osv-scanner into a group; we store the group's primary id.
    osv_id          VARCHAR(128)  NOT NULL,
    -- Taken from the advisory aliases. Null for GHSA-only and MAL-* entries, which have
    -- no CVE counterpart - roughly 3% of the Maven set.
    cve_id          VARCHAR(64),

    summary         VARCHAR(2048),

    -- Numeric score as computed by the scanner, alongside the vector it came from and
    -- which CVSS revision produced it: a v3 6.5 and a v4 6.5 are not the same statement.
    -- The vector is null when a group's aliased advisories disagreed and none could be
    -- attributed to the score.
    severity_score  DECIMAL(4, 1),
    -- GitHub's own qualitative label, from the advisory's database_specific block. A
    -- different scale from a different source than severity_score.
    severity_rating VARCHAR(32),
    cvss_vector     VARCHAR(512),
    cvss_version    VARCHAR(16),

    -- The fix on our own version's branch, chosen from the affected entry matching this
    -- component. An advisory often lists fixes for several parallel branches.
    fixed_version   VARCHAR(128),

    published_at    TIMESTAMP WITH TIME ZONE,

    CONSTRAINT pk_vulnerability_finding PRIMARY KEY (id),
    CONSTRAINT fk_finding_scan FOREIGN KEY (purl)
        REFERENCES vulnerability_scan (purl) ON DELETE CASCADE,
    CONSTRAINT uq_finding_per_component UNIQUE (purl, osv_id)
);

CREATE INDEX idx_finding_purl ON vulnerability_finding (purl);
CREATE INDEX idx_finding_cve ON vulnerability_finding (cve_id);
