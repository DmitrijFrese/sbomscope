-- V6 - offline JVM workspace reachability evidence.
--
-- Results belong to an SBOM/workspace pairing, not to the global vulnerability cache: they
-- describe the bytecode the user had built at one point in time. A fresh input fingerprint
-- creates a new run; previous runs remain an auditable explanation of an earlier answer.

CREATE TABLE workspace_analysis_run (
    id                UUID                     NOT NULL,
    sbom_id           UUID                     NOT NULL,
    input_fingerprint VARCHAR(128)             NOT NULL,
    status            VARCHAR(16)              NOT NULL,
    engine            VARCHAR(128),
    algorithm         VARCHAR(128),
    blockers          VARCHAR(2048),
    error_message     VARCHAR(4096),
    requested_at      TIMESTAMP WITH TIME ZONE NOT NULL,
    started_at        TIMESTAMP WITH TIME ZONE,
    finished_at       TIMESTAMP WITH TIME ZONE,

    CONSTRAINT pk_workspace_analysis_run PRIMARY KEY (id),
    CONSTRAINT fk_workspace_analysis_run_sbom FOREIGN KEY (sbom_id)
        REFERENCES sbom (id) ON DELETE CASCADE,
    CONSTRAINT ck_workspace_analysis_status
        CHECK (status IN ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED'))
);

CREATE INDEX idx_workspace_analysis_latest
    ON workspace_analysis_run (sbom_id, requested_at DESC);

-- One component/module answer per run. method_paths is a compact JSON array of inspectable
-- bytecode method routes; it is deliberately separate from the OSV finding because, today,
-- OSV generally does not identify vulnerable methods. The claim is therefore library-use
-- evidence, not proof that an advisory's vulnerable function was reached.
CREATE TABLE workspace_reachability_evidence (
    id                UUID          NOT NULL,
    analysis_run_id   UUID          NOT NULL,
    purl              VARCHAR(2048) NOT NULL,
    module_path       VARCHAR(4096),
    status            VARCHAR(24)   NOT NULL,
    method_paths      CLOB,
    detail            VARCHAR(4096),

    CONSTRAINT pk_workspace_reachability_evidence PRIMARY KEY (id),
    CONSTRAINT fk_workspace_evidence_run FOREIGN KEY (analysis_run_id)
        REFERENCES workspace_analysis_run (id) ON DELETE CASCADE,
    CONSTRAINT ck_workspace_evidence_status
        CHECK (status IN ('REACHABLE', 'NO_CALL_PATH', 'NEEDS_REVIEW', 'UNAVAILABLE'))
);

CREATE INDEX idx_workspace_evidence_component
    ON workspace_reachability_evidence (analysis_run_id, purl);
