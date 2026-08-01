-- V4 - CISA's Known Exploited Vulnerabilities catalogue.
--
-- Additive, as constraint 8 requires: the repository is public and somebody else's data may
-- already be on the other end of V1-V3.
--
-- Derived data, like osv_index: rebuildable at any time from the downloaded file, and erased
-- with it. Kept in a table rather than read from the JSON on demand because the findings view
-- sorts by it, and sorting executes in SQL so that the view and the export cannot diverge.
--
-- Measured 2026-08-01: 1,656 entries, of which 52 intersect the Maven OSV archive and 13 the
-- npm one. A small table by design - KEV is a rare, loud mark rather than a column with a value
-- on every row.
--
-- Keyed by CVE, which is the whole reason a third rendering exists in the UI: 3% of Maven
-- advisories and 97.5% of npm ones carry no CVE at all, and for those the question cannot be
-- asked rather than being answered "no".

CREATE TABLE kev_entry (
    -- The catalogue's own key. Its published schema pins the format as CVE-YYYY-N{4,19}.
    cve_id             VARCHAR(64)  NOT NULL,

    vendor_project     VARCHAR(256),
    product            VARCHAR(256),
    vulnerability_name VARCHAR(512),

    -- When CISA added it. Surfaced, and load-bearing: an entry added four years ago and one
    -- added last week are very different statements about how far behind you are.
    date_added         DATE         NOT NULL,

    short_description  CLOB,

    -- Stored and deliberately never rendered. Both are BOD 26-04 obligations binding on US
    -- federal agencies; showing that due date to a developer would invent a deadline they do
    -- not have, which is a false statement rather than a spare column. Kept only so the stored
    -- record is the record.
    required_action    CLOB,
    due_date           DATE,

    -- CISA writes 'Known' or 'Unknown'. Narrowed to a boolean on the way in because 'Unknown'
    -- means CISA lacks confirmation, not that ransomware is absent - so this is a positive
    -- signal only, and a three-valued column would invite reading the third value as a denial.
    known_ransomware   BOOLEAN      NOT NULL,

    notes              CLOB,

    -- The record's cwes[], comma-separated. Nothing reads it yet; stored so that a later
    -- decision is a render change rather than a re-parse.
    cwes               VARCHAR(512),

    CONSTRAINT pk_kev_entry PRIMARY KEY (cve_id)
);

-- Which download produced the rows above, so the UI can state an as-of date that is the
-- catalogue's own claim rather than a file timestamp we inferred.
--
-- One row, enforced rather than assumed: a second row would leave "when is this data from"
-- with two answers and no rule for choosing.
CREATE TABLE kev_source (
    only_row        BOOLEAN                  NOT NULL DEFAULT TRUE,

    -- The catalogue states both. catalogVersion is CISA's own version string (dated, e.g.
    -- 2026.07.29); date_released is the timestamp inside the document.
    catalog_version VARCHAR(64)              NOT NULL,
    date_released   TIMESTAMP WITH TIME ZONE NOT NULL,

    -- What the document said it held, kept beside what we actually loaded: a disagreement is
    -- worth being able to see rather than silently trusting one of them.
    entry_count     INTEGER                  NOT NULL,
    loaded_entries  INTEGER                  NOT NULL,

    -- File path, size and modification time, compared rather than trusted - the same device
    -- osv_index_source uses, so replacing the file invalidates these rows by itself.
    identity        VARCHAR(1024)            NOT NULL,

    loaded_at       TIMESTAMP WITH TIME ZONE NOT NULL,

    CONSTRAINT pk_kev_source PRIMARY KEY (only_row),
    CONSTRAINT ck_kev_source_single CHECK (only_row)
);
