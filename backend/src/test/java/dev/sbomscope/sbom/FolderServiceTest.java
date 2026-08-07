package dev.sbomscope.sbom;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Projects and folders (B19), against the real Flyway-built schema.
 *
 * <p>The depth limit, the cycle check and "delete never deletes a document" all live in
 * {@link FolderService} rather than in the schema — see the class comment there for why —
 * so this is where they are actually exercised.
 *
 * <p>{@code @Transactional}: each test method's writes roll back afterwards, matching
 * {@code OsvArchiveMatcherTest} and {@code PurgeTest}. Without it every method shares one
 * committed database — a real fixture of this suite, not incidental — and sibling-name
 * collisions between test methods would fail tests that are individually correct.
 */
@SpringBootTest
@Transactional
class FolderServiceTest {

    @Autowired
    private FolderService folders;

    @Autowired
    private SbomService sboms;

    private static final String MINIMAL_SBOM = """
            {"bomFormat":"CycloneDX","specVersion":"1.6","components":[
              {"type":"library","bom-ref":"pkg:maven/example/lib@1.0.0",
               "group":"example","name":"lib","version":"1.0.0"}
            ]}
            """;

    private StoredSbom uploadDocument(String filename) {
        return sboms.importSbom(filename, null,
                new ByteArrayInputStream(MINIMAL_SBOM.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void aFolderWithNoParentIsAProject() {
        StoredFolder project = folders.create("Payments Platform", null);
        assertThat(project.isProject()).isTrue();

        StoredFolder sub = folders.create("backend", project.id());
        assertThat(sub.isProject()).isFalse();
    }

    @Test
    void goesThreeLevelsDeepAndNoFurther() {
        StoredFolder project = folders.create("Project", null);
        StoredFolder level2 = folders.create("Level 2", project.id());
        StoredFolder level3 = folders.create("Level 3", level2.id());

        // A project plus two levels beneath it is exactly three — the boundary asked for
        // ("a project can contain two levels of subfolders"), not one either side of it.
        assertThat(level3).isNotNull();

        assertThatThrownBy(() -> folders.create("Level 4", level3.id()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("levels deep");
    }

    @Test
    void siblingNamesCollideCaseInsensitively() {
        folders.create("Payments", null);

        assertThatThrownBy(() -> folders.create("payments", null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("already");
    }

    @Test
    void theSameNameIsFineUnderDifferentParents() {
        // "backend" under two different projects is the ordinary case this uniqueness rule
        // is scoped to allow, not an edge case to tolerate.
        StoredFolder projectA = folders.create("Project A", null);
        StoredFolder projectB = folders.create("Project B", null);

        StoredFolder backendA = folders.create("backend", projectA.id());
        StoredFolder backendB = folders.create("backend", projectB.id());

        assertThat(backendA.name()).isEqualTo(backendB.name());
        assertThat(backendA.parentId()).isNotEqualTo(backendB.parentId());
    }

    @Test
    void aFolderCannotBeMovedIntoItsOwnDescendant() {
        StoredFolder project = folders.create("Project", null);
        StoredFolder child = folders.create("Child", project.id());

        assertThatThrownBy(() -> folders.move(project.id(), child.id()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("inside it");
    }

    @Test
    void movingASubtreeRespectsTheDepthLimitOfWhatItCarriesWithIt() {
        // A two-level branch (Child -> Grandchild) moved under a level-2 folder would put
        // its leaves at level 4 — the height of the subtree matters, not just the folder
        // being moved.
        StoredFolder projectA = folders.create("Project A", null);
        StoredFolder child = folders.create("Child", projectA.id());
        folders.create("Grandchild", child.id());

        StoredFolder projectB = folders.create("Project B", null);
        StoredFolder targetLevel2 = folders.create("Target", projectB.id());

        assertThatThrownBy(() -> folders.move(child.id(), targetLevel2.id()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("levels deep");
    }

    @Test
    void deletingAFolderRelocatesItsContentsAndNeverDeletesADocument() {
        StoredFolder project = folders.create("Project", null);
        StoredFolder child = folders.create("Child", project.id());
        StoredFolder grandchild = folders.create("Grandchild", child.id());
        StoredSbom doc = uploadDocument("relocated.cdx.json");
        folders.moveSbom(doc.id(), grandchild.id());

        folders.delete(child.id());

        // The grandchild folder moves up to the project, the deleted folder is gone, and
        // the document is still findable under its (relocated) folder — nothing lost.
        assertThat(folders.findAll())
                .filteredOn(f -> f.id().equals(grandchild.id()))
                .first()
                .extracting(StoredFolder::parentId)
                .isEqualTo(project.id());
        assertThat(folders.findAll()).noneMatch(f -> f.id().equals(child.id()));
        assertThat(sboms.findById(doc.id())).isPresent();
    }

    @Test
    void deletingAProjectMovesItsDocumentsToTheTopLevelRatherThanDeletingThem() {
        StoredFolder project = folders.create("Short-lived project", null);
        StoredSbom doc = uploadDocument("orphaned.cdx.json");
        folders.moveSbom(doc.id(), project.id());

        folders.delete(project.id());

        assertThat(sboms.findById(doc.id())).isPresent();
    }

    /**
     * The children of one folder, in display order.
     *
     * <p>Every ordering test works inside a parent it created rather than at the top level,
     * and that is not incidental: {@code SbomControllerTest} is not {@code @Transactional}, so
     * a folder it creates through MockMvc <b>commits</b> into the shared in-memory database and
     * is still there when this class runs. A top-level group therefore has members no test
     * here put in it. Scoping to an owned parent makes these assertions independent of run
     * order — and the strict membership check in {@code reorderFolders} is what surfaced it.
     */
    private List<StoredFolder> childrenOf(StoredFolder parent) {
        return folders.findAll().stream()
                .filter(folder -> parent.id().equals(folder.parentId()))
                .toList();
    }

    @Test
    void aNewFolderLandsAtTheTopOfItsGroup() {
        // The placement decided on 2026-08-07: a new folder appears where the reader is
        // already looking, matching the newest-first document order it replaces.
        StoredFolder parent = folders.create("Ordering", null);
        folders.create("First", parent.id());
        folders.create("Second", parent.id());
        StoredFolder third = folders.create("Third", parent.id());

        assertThat(childrenOf(parent)).extracting(StoredFolder::name)
                .containsExactly("Third", "Second", "First");
        assertThat(childrenOf(parent)).first().extracting(StoredFolder::id).isEqualTo(third.id());
    }

    @Test
    void reorderRewritesTheGroupInTheOrderGiven() {
        StoredFolder parent = folders.create("Ordering", null);
        StoredFolder a = folders.create("A", parent.id());
        StoredFolder b = folders.create("B", parent.id());
        StoredFolder c = folders.create("C", parent.id());

        folders.reorderFolders(parent.id(), List.of(a.id(), b.id(), c.id()));

        assertThat(childrenOf(parent)).extracting(StoredFolder::id)
                .containsExactly(a.id(), b.id(), c.id());
    }

    @Test
    void reorderRefusesAListThatIsNotExactlyTheGroup() {
        // A reorder accepting a foreign id would be a move that skipped the depth, cycle and
        // name checks — which is the whole reason the two operations are separate.
        StoredFolder parent = folders.create("Ordering", null);
        StoredFolder inside = folders.create("Inside", parent.id());
        StoredFolder elsewhere = folders.create("Elsewhere", null);

        assertThatThrownBy(() -> folders.reorderFolders(parent.id(), List.of(inside.id(), elsewhere.id())))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("does not list exactly");

        assertThatThrownBy(() -> folders.reorderFolders(parent.id(), List.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void sortByNameOverwritesTheManualOrderForThatLevelOnly() {
        StoredFolder parent = folders.create("Ordering", null);
        StoredFolder zebra = folders.create("Zebra", parent.id());
        StoredFolder alpha = folders.create("Alpha", parent.id());
        // New folders land on top, so Alpha starts above Zebra; a manual order inverts that.
        folders.reorderFolders(parent.id(), List.of(zebra.id(), alpha.id()));
        assertThat(childrenOf(parent)).extracting(StoredFolder::name).containsExactly("Zebra", "Alpha");

        folders.sortByName(parent.id());

        assertThat(childrenOf(parent)).extracting(StoredFolder::name).containsExactly("Alpha", "Zebra");
    }

    @Test
    void aMovedFolderLandsAtTheTopOfItsDestination() {
        StoredFolder target = folders.create("Target", null);
        folders.create("Already inside", target.id());
        StoredFolder moved = folders.create("Moved", null);

        folders.move(moved.id(), target.id());

        assertThat(folders.findAll().stream()
                .filter(f -> target.id().equals(f.parentId()))
                .map(StoredFolder::id))
                .first()
                .isEqualTo(moved.id());
    }

    @Test
    void movingADocumentIntoAnUnknownFolderIsRejected() {
        StoredSbom doc = uploadDocument("subject.cdx.json");

        assertThatThrownBy(() -> folders.moveSbom(doc.id(), UUID.randomUUID()))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
