-- V5 - EPSS exploitation probabilities, from FIRST.org's daily bulk file.
--
-- Additive, and separate from V4 rather than folded in with it: KEV and EPSS are independent
-- feeds with different shapes, cadences and licences, and additive-only means a later split
-- would not be available if they shared a migration.
--
-- Derived data, like osv_index and kev_entry: rebuildable from the downloaded file at any time,
-- and erased with it.
--
-- The whole file is stored - 354,453 rows measured 2026-08-01, against the 212 distinct CVEs in
-- the maintainer's own SBOMs. Storing only the CVEs currently present was the alternative and
-- was rejected: fetching is manual under constraint 2, so a CVE discarded today stays blank
-- until somebody presses the button again, and "we threw this away" would render identically to
-- "EPSS does not score this". Keeping everything also makes a refresh a straight reload with no
-- dependency on what happens to be in vulnerability_finding at the time.

CREATE TABLE epss_score (
    cve_id     VARCHAR(64)      NOT NULL,

    -- Probability of exploitation in the next 30 days, 0..1.
    score      DOUBLE PRECISION NOT NULL,

    -- The proportion of all scored CVEs at or below that score. Published alongside the score
    -- and stored because it is what makes the score readable: 0.033 looks negligible where
    -- "87th percentile" says it is worse than most of what you own.
    percentile DOUBLE PRECISION NOT NULL,

    CONSTRAINT pk_epss_score PRIMARY KEY (cve_id)
);

-- Which file produced the rows above.
--
-- Both fields below come from the file's own first line, not from anything we observed:
--   #model_version:v2026.06.15,score_date:2026-07-31T12:03:43Z
--
-- That matters more here than for an advisory archive. Scores drift slowly - measured
-- 2026-08-01, 0.9% of scores move day over day and 0.01% by more than 0.01 - but a model
-- version changes every score at once, and has done roughly annually. So "why did this number
-- change" is answered by model_version, and comparing scores across a model boundary compares
-- two different methodologies rather than two states of one vulnerability.
CREATE TABLE epss_source (
    only_row      BOOLEAN                  NOT NULL DEFAULT TRUE,

    model_version VARCHAR(64)              NOT NULL,
    score_date    TIMESTAMP WITH TIME ZONE NOT NULL,
    loaded_scores INTEGER                  NOT NULL,

    -- File path, size and modification time, as osv_index_source and kev_source use.
    identity      VARCHAR(1024)            NOT NULL,

    loaded_at     TIMESTAMP WITH TIME ZONE NOT NULL,

    CONSTRAINT pk_epss_source PRIMARY KEY (only_row),
    CONSTRAINT ck_epss_source_single CHECK (only_row)
);
