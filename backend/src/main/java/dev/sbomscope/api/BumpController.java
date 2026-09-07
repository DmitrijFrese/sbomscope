package dev.sbomscope.api;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import dev.sbomscope.bump.ApplyResult;
import dev.sbomscope.bump.BumpApplyService;
import dev.sbomscope.bump.BumpPlan;
import dev.sbomscope.bump.BumpPlanService;
import dev.sbomscope.bump.BumpEdit;
import dev.sbomscope.bump.DeclarationSite;
import dev.sbomscope.bump.LinkageCheck;
import dev.sbomscope.bump.LinkageCheckService;
import dev.sbomscope.bump.PomFile;
import dev.sbomscope.bump.PomPatcher;
import dev.sbomscope.bump.PomPatcher.PlannedEdit;
import dev.sbomscope.bump.PreviewFile;
import dev.sbomscope.bump.PreviewResult;
import dev.sbomscope.sbom.SbomService;
import dev.sbomscope.sbom.StoredSbom;

@RestController
@RequestMapping("/api/sboms/{id}/bump")
class BumpController {

    private final BumpPlanService plans;
    private final SbomService sboms;
    private final BumpApplyService applies;
    private final LinkageCheckService linkage;

    BumpController(BumpPlanService plans, SbomService sboms, BumpApplyService applies,
            LinkageCheckService linkage) {
        this.plans = plans;
        this.sboms = sboms;
        this.applies = applies;
        this.linkage = linkage;
    }

    @GetMapping
    BumpPlan plan(@PathVariable UUID id) {
        StoredSbom sbom = sboms.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "No such SBOM"));
        if (sbom.workspacePath() == null) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "This SBOM has no workspace attached");
        }
        if (!hasManifest(sbom.workspacePath())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "The workspace holds no pom.xml or package.json");
        }
        return plans.plan(sbom);
    }

    @PostMapping("/preview")
    PreviewResult preview(@PathVariable UUID id, @RequestBody PreviewRequest request) {
        StoredSbom sbom = sboms.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "No such SBOM"));
        if (sbom.workspacePath() == null) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "This SBOM has no workspace attached");
        }
        if (!hasManifest(sbom.workspacePath())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "The workspace holds no pom.xml or package.json");
        }
        BumpPlan plan = plans.plan(sbom);
        Map<String, DeclarationSite> sites = new LinkedHashMap<>();
        for (var row : plan.rows()) {
            sites.putIfAbsent(row.site().id(), row.site());
        }
        Map<String, BumpEdit> requested = new LinkedHashMap<>();
        for (BumpEdit edit : request.edits()) {
            requested.putIfAbsent(edit.siteId(), edit);
        }
        Map<String, PomFile> files = plan.files().stream().collect(java.util.stream.Collectors.toMap(
                PomFile::path, file -> file, (left, right) -> left, LinkedHashMap::new));
        Map<String, List<PlannedEdit>> editsByFile = new LinkedHashMap<>();
        List<String> warnings = new ArrayList<>();
        for (BumpEdit edit : requested.values()) {
            DeclarationSite site = sites.get(edit.siteId());
            if (site == null) {
                throw new ResponseStatusException(HttpStatus.CONFLICT,
                        "The workspace changed; rebuild the bump plan");
            }
            PomFile file = files.get(site.file());
            if (file == null || !file.editable()) {
                throw new ResponseStatusException(HttpStatus.CONFLICT,
                        "The workspace changed; rebuild the bump plan");
            }
            editsByFile.computeIfAbsent(file.path(), ignored -> new ArrayList<>())
                    .add(new PlannedEdit(site, edit.newVersion(), edit.structural()));
            if (site.kind() == dev.sbomscope.bump.SiteKind.PROPERTY && !site.sharedWith().isEmpty()) {
                warnings.add("Property " + site.propertyName() + " also changes "
                        + String.join(", ", site.sharedWith()));
            }
        }
        PomPatcher patcher = new PomPatcher();
        List<PreviewFile> preview = new ArrayList<>();
        try {
            for (PomFile file : plan.files()) {
                List<PlannedEdit> edits = editsByFile.get(file.path());
                if (edits != null) {
                    preview.add(patcher.patch(file, edits));
                }
            }
        } catch (IllegalArgumentException exception) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, exception.getMessage(), exception);
        }
        return new PreviewResult(List.copyOf(preview), List.copyOf(warnings));
    }

    @PostMapping("/linkage")
    LinkageCheck linkage(@PathVariable UUID id, @RequestBody LinkageRequest request) {
        StoredSbom sbom = sboms.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "No such SBOM"));
        if (sbom.workspacePath() == null) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "This SBOM has no workspace attached");
        }
        if (!hasManifest(sbom.workspacePath())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "The workspace holds no pom.xml or package.json");
        }
        return linkage.check(plans.plan(sbom),
                request.edits() == null ? List.of() : request.edits());
    }

    /**
     * Writes to the user's own source files — the only endpoint in SBOMscope that does.
     *
     * <p>Takes the text rather than the edits deliberately: the user may have corrected the
     * preview by hand, and applying a re-derived patch instead of what they read would mean the
     * dialog they confirmed described something other than what was written.
     */
    @PostMapping("/apply")
    ApplyResult apply(@PathVariable UUID id, @RequestBody ApplyRequest request) {
        StoredSbom sbom = sboms.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "No such SBOM"));
        if (sbom.workspacePath() == null) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "This SBOM has no workspace attached");
        }
        if (request.files() == null || request.files().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "There is nothing to apply");
        }
        try {
            return applies.apply(Path.of(sbom.workspacePath()), request.files(),
                    request.overrideGitGate());
        } catch (BumpApplyService.ApplyRefused refused) {
            // 409 for every gate refusal, each naming which gate and why: the request was
            // well-formed, the workspace was not in a state that permits writing to it.
            throw new ResponseStatusException(HttpStatus.CONFLICT, refused.getMessage(), refused);
        }
    }

    /**
     * Either manifest is enough to have something to plan. A workspace may hold both — this
     * repository does — and an npm-only project is as valid a subject here as a Maven one.
     */
    private boolean hasManifest(String workspacePath) {
        Path root = Path.of(workspacePath);
        return Files.isRegularFile(root.resolve("pom.xml"))
                || Files.isRegularFile(root.resolve("package.json"));
    }

    private record PreviewRequest(List<BumpEdit> edits) {}

    private record LinkageRequest(List<BumpEdit> edits) {}

    private record ApplyRequest(List<BumpApplyService.FileWrite> files, boolean overrideGitGate) {}
}
