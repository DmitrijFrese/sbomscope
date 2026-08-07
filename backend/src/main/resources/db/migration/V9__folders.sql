-- V9 - projects and folders for the sidebar (B19).
--
-- Additive, as constraint 8 requires.
--
-- ONE self-referencing table rather than a `project` table and a `folder` table. A project is
-- simply a folder with no parent, which is what makes "an SBOM may sit at any level" a property
-- of the schema instead of three cases in every query that walks it.
--
-- The depth limit - a project plus two levels beneath it - is deliberately NOT expressed here.
-- It is a judgement about how deep a 280px sidebar column stays readable, so it belongs in
-- FolderService where it can be stated once and reported as a real error, rather than in a
-- constraint that would surface as an opaque integrity violation.
--
-- Nothing outside the sidebar reads folder_id. Filing is a convenience laid over the list, and
-- the findings pipeline is keyed by SBOM exactly as before.

CREATE TABLE folder (
    id         UUID                     NOT NULL,

    name       VARCHAR(256)             NOT NULL,

    -- Null means this folder is a project: a root of the tree. The FK is self-referencing, and
    -- ON DELETE is deliberately absent - deleting a folder relocates its contents to the parent
    -- in FolderService rather than cascading, because a cascade here would destroy uploaded
    -- documents as a side effect of tidying the sidebar.
    parent_id  UUID,

    created_at TIMESTAMP WITH TIME ZONE NOT NULL,

    CONSTRAINT pk_folder PRIMARY KEY (id),
    CONSTRAINT fk_folder_parent FOREIGN KEY (parent_id) REFERENCES folder (id)
);

-- Sibling names are unique case-insensitively - two projects called "Payments" and "payments"
-- in one column are a reading hazard rather than two things - and that rule lives in
-- FolderService rather than here, for two independent reasons.
--
-- H2 has no function-based indexes, so `(parent_id, LOWER(name))` is a syntax error rather
-- than a constraint; this was written that way first and caught by the migration failing.
-- And even a plain `(parent_id, name)` unique index would not have done the job: H2 treats
-- NULLs as distinct, so it would constrain subfolders while leaving top-level projects free
-- to collide - the one case a user meets first. Checking both cases explicitly in Java is
-- what makes the rule uniform, and it can name the folder that already has the name.
CREATE INDEX idx_folder_parent ON folder (parent_id);

-- Null means the document sits outside every project. That is the ordinary state rather than a
-- missing value, and such documents stay first-class in the sidebar beside the folders.
--
-- ON DELETE SET NULL: deleting a folder must never take a document with it. FolderService
-- relocates to the parent explicitly, and this is the backstop that keeps the document alive
-- even if some future path deletes a row directly.
ALTER TABLE sbom
    ADD COLUMN folder_id UUID;

ALTER TABLE sbom
    ADD CONSTRAINT fk_sbom_folder FOREIGN KEY (folder_id) REFERENCES folder (id) ON DELETE SET NULL;

CREATE INDEX idx_sbom_folder ON sbom (folder_id);
