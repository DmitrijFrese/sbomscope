-- V10 - manual ordering for the sidebar tree (B19, third pass).
--
-- Additive, as constraint 8 requires.
--
-- The sidebar sorted folders by name and documents newest-first, which is a fine default and
-- a poor arrangement: the order that matters is the reader's own, and nothing could express
-- it. Ordering is therefore stored rather than derived.
--
-- SCOPED TO A SIBLING GROUP, not global. `sort_order` is meaningful only among rows sharing a
-- parent (folder.parent_id, sbom.folder_id), and within a group the render also separates
-- folders from documents, so two rows of different kinds never compare their values. A single
-- global sequence would have to be rewritten whenever anything moved between folders.
--
-- ASCENDING, and new rows take MIN - 1 so they land at the top of their group without
-- rewriting their siblings - the placement decided on 2026-08-07, matching the newest-first
-- document order it replaces. Values therefore drift negative over time, which is harmless:
-- only the relative order is ever read, and an explicit reorder rewrites the whole group to
-- a dense 0..n-1 sequence.

ALTER TABLE folder
    ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0;

ALTER TABLE sbom
    ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0;

-- Backfill so that turning ordering on changes nothing the reader can see: existing folders
-- keep the alphabetical order they were displayed in, and existing documents keep
-- newest-first. Without this every row would share sort_order 0 and the tree would reshuffle
-- into whatever order the database happened to return.
--
-- PARTITION BY treats NULL as its own group, which is exactly right here: top-level folders
-- (parent_id NULL) and unfiled documents (folder_id NULL) are each a real sibling group.
UPDATE folder f
SET sort_order = (
    SELECT ordered.position
    FROM (SELECT id,
                 ROW_NUMBER() OVER (PARTITION BY parent_id ORDER BY LOWER(name)) AS position
          FROM folder) ordered
    WHERE ordered.id = f.id
);

UPDATE sbom s
SET sort_order = (
    SELECT ordered.position
    FROM (SELECT id,
                 ROW_NUMBER() OVER (PARTITION BY folder_id ORDER BY uploaded_at DESC) AS position
          FROM sbom) ordered
    WHERE ordered.id = s.id
);

-- Reads are always "this group, in order", so the index leads with the grouping column.
CREATE INDEX idx_folder_sibling_order ON folder (parent_id, sort_order);
CREATE INDEX idx_sbom_sibling_order ON sbom (folder_id, sort_order);
