package dev.sbomscope.bump;

import static dev.sbomscope.settings.SettingsService.defaultProbeRepository;

import dev.sbomscope.logging.ActivityLogger;
import dev.sbomscope.probe.DependencyResolver;
import dev.sbomscope.probe.EffectivePomCache;
import dev.sbomscope.probe.EffectivePomFragments;
import dev.sbomscope.probe.MavenArtifact;
import dev.sbomscope.probe.MetadataPrimer;
import dev.sbomscope.probe.ProbeContext;
import dev.sbomscope.settings.MavenToolSettings;
import dev.sbomscope.settings.SettingsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Fetches the release metadata a plan's rows need, on request.
 *
 * <p>{@link TargetAvailability} can only speak where {@code maven-metadata*.xml} is already on
 * disk, and until now nothing put it there deliberately — coverage was whatever some earlier probe
 * happened to leave behind. This is the deliberate half, and it is a separate action rather than
 * part of building the plan because it costs about five seconds of Maven startup per artifact,
 * while the plan itself is meant to open at once.
 *
 * <p><b>Reported before it is spent.</b> {@link #coverage} is a directory listing — no process, no
 * network — so the screen can say how many artifacts lack release data before anything is pressed,
 * and offer nothing when the answer is zero.
 */
@Service
public class ReleaseDataService {

    /** Generous: this is one Maven startup plus a few kilobytes, but on a cold plugin cache the
     * first invocation also downloads the dependency plugin itself — measured at 25 s. */
    private static final Duration PRIME_TIMEOUT = Duration.ofMinutes(3);

    /**
     * @param missing  artifacts among the plan's rows with no release metadata on disk
     * @param canFetch whether a Maven executable is configured at all. Distinguishes "nothing to
     *                 do" from "cannot be done", which look identical as a count of zero
     */
    public record Coverage(int missing, boolean canFetch) {}

    /**
     * @param availability the fresh answer per {@code groupId:artifactId}, for every artifact
     *                     asked about — including the ones that stayed UNKNOWN, so the caller can
     *                     stop showing them as pending
     * @param notes        one line per artifact that could not be fetched. Never silent
     */
    public record Result(int primed, int failed, Map<String, TargetAvailability> availability,
                         List<String> notes) {}

    private final MetadataPrimer primer;
    private final DependencyResolver resolver;
    private final EffectivePomCache effectivePoms;
    private final SettingsService settings;

    @Autowired
    ReleaseDataService(DependencyResolver resolver, EffectivePomCache effectivePoms,
                       SettingsService settings, ActivityLogger activityLog) {
        this(resolver, effectivePoms, settings, new MetadataPrimer(activityLog));
    }

    ReleaseDataService(DependencyResolver resolver, EffectivePomCache effectivePoms,
                       SettingsService settings, MetadataPrimer primer) {
        this.resolver = resolver;
        this.effectivePoms = effectivePoms;
        this.settings = settings;
        this.primer = primer;
    }

    /** What the screen shows before the reader decides, and what makes the action disappear. */
    public Coverage coverage(BumpPlan plan) {
        MavenToolSettings maven = settings.mavenSettings();
        if (!maven.hasExecutable()) {
            return new Coverage(0, false);
        }
        ProbeContext context = context(plan.workspace(), maven, new ArrayList<>());
        int missing = (int) wanted(plan).stream()
                .filter(artifact -> !primer.hasMetadata(artifact, context))
                .count();
        return new Coverage(missing, true);
    }

    /**
     * Primes every artifact in the plan that lacks metadata, one Maven invocation each.
     *
     * <p>Sequential on purpose for now. The invocations are independent and a pool would be a
     * straight division of the wall time, but each one writes into the same isolated repository,
     * and sharing a local repository between concurrent Maven processes is exactly the case Maven
     * does not promise to be safe. Making that concurrent is a measured change, not a free one.
     */
    public Result prime(BumpPlan plan) {
        MavenToolSettings maven = settings.mavenSettings();
        if (!maven.hasExecutable()) {
            return new Result(0, 0, Map.of(),
                    List.of("No Maven executable is configured, so release data cannot be fetched."));
        }

        List<String> notes = new ArrayList<>();
        ProbeContext context = context(plan.workspace(), maven, notes);
        Map<String, TargetAvailability> availability = new LinkedHashMap<>();
        int primed = 0;
        int failed = 0;

        for (MavenArtifact artifact : wanted(plan)) {
            MetadataPrimer.Result result = primer.prime(artifact, context);
            if (result.primed()) {
                primed++;
            } else {
                failed++;
                notes.add(result.detail());
            }
            List<String> known = resolver.knownVersions(artifact, context);
            String coordinates = artifact.groupId() + ":" + artifact.artifactId();
            for (BumpRow row : plan.rows()) {
                if (coordinates.equals(coordinatesOf(row))) {
                    availability.put(coordinates, TargetAvailability.of(row.minimalTarget(), known));
                    break;
                }
            }
        }
        return new Result(primed, failed, availability, notes);
    }

    /**
     * The Maven artifacts worth asking about: one per coordinate, and only where there is a target
     * to classify.
     *
     * <p>Deduplicated because a plan has one row per declaration site, and an artifact declared in
     * six modules is still one version list. npm rows are excluded — this is Maven's metadata.
     */
    private Set<MavenArtifact> wanted(BumpPlan plan) {
        Set<MavenArtifact> artifacts = new LinkedHashSet<>();
        for (BumpRow row : plan.rows()) {
            if (row.minimalTarget() == null || row.minimalTarget().isBlank()) {
                continue;
            }
            DeclarationSite site = row.site();
            if (site.ecosystem() != Ecosystem.MAVEN || site.groupId() == null || site.artifactId() == null) {
                continue;
            }
            artifacts.add(new MavenArtifact(site.groupId(), site.artifactId()));
        }
        return artifacts;
    }

    private static String coordinatesOf(BumpRow row) {
        DeclarationSite site = row.site();
        return site.groupId() + ":" + site.artifactId();
    }

    /**
     * The workspace's own repositories are lifted in, because a supplier's Nexus is usually
     * declared in the project rather than in settings.xml and their artifacts could not be primed
     * without it.
     */
    private ProbeContext context(String workspace, MavenToolSettings maven, List<String> notes) {
        String repository = defaultProbeRepository();
        Optional<EffectivePomFragments> lifted = effectivePoms.forWorkspace(workspace,
                maven.executablePath(), repository, PRIME_TIMEOUT, maven.profiles(),
                maven.effectivePomGoal());
        if (lifted.isEmpty()) {
            notes.add("Could not lift the workspace effective POM; asking the default repositories only.");
        }
        return new ProbeContext(maven.executablePath(), repository, lifted.orElse(null), PRIME_TIMEOUT,
                maven.profiles(), maven.dependencyTreeGoal());
    }
}
