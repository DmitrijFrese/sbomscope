-- Per-module identity and coverage are first-class evidence, rather than prose in an Inspector row.
-- Existing V6 runs remain valid: their pre-coverage evidence simply has zero counts.

CREATE TABLE workspace_analysis_module (
    id                    UUID          NOT NULL,
    analysis_run_id       UUID          NOT NULL,
    module_path           VARCHAR(4096) NOT NULL,
    production_output     VARCHAR(4096) NOT NULL,
    application_bom_ref   VARCHAR(2048),
    mapping_status        VARCHAR(16)   NOT NULL,
    mapping_detail        VARCHAR(4096),

    CONSTRAINT pk_workspace_analysis_module PRIMARY KEY (id),
    CONSTRAINT fk_workspace_analysis_module_run FOREIGN KEY (analysis_run_id)
        REFERENCES workspace_analysis_run (id) ON DELETE CASCADE,
    CONSTRAINT uq_workspace_analysis_module UNIQUE (analysis_run_id, module_path),
    CONSTRAINT ck_workspace_analysis_module_mapping
        CHECK (mapping_status IN ('MAPPED', 'UNMAPPED'))
);

ALTER TABLE workspace_reachability_evidence
    ADD COLUMN reachable_method_count INTEGER NOT NULL DEFAULT 0;

ALTER TABLE workspace_reachability_evidence
    ADD COLUMN direct_method_count INTEGER NOT NULL DEFAULT 0;

ALTER TABLE workspace_reachability_evidence
    ADD COLUMN displayed_path_count INTEGER NOT NULL DEFAULT 0;
