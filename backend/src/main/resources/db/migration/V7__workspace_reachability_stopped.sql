-- V7 - a user-stopped isolated worker is neither a completed analysis nor a failure.
ALTER TABLE workspace_analysis_run DROP CONSTRAINT ck_workspace_analysis_status;
ALTER TABLE workspace_analysis_run ADD CONSTRAINT ck_workspace_analysis_status
    CHECK (status IN ('QUEUED', 'RUNNING', 'COMPLETED', 'STOPPED', 'FAILED'));
