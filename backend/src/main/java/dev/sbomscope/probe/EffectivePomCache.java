package dev.sbomscope.probe;

import java.io.IOException;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import dev.sbomscope.settings.MavenSettingsChangedEvent;

/**
 * Lifts {@code <dependencyManagement>} and {@code <repositories>} out of a workspace's own
 * {@code mvn help:effective-pom}, once per workspace path per process lifetime.
 *
 * <p>This is the actual fix for probes failing on supplier artifacts: a project's own
 * {@code pom.xml} routinely declares a supplier's Nexus, and that repository is not in
 * {@code settings.xml}, so a mirror only covers it when the mirror is {@code *}. Without a
 * workspace there is nothing to lift, and the probe stays isolated rather than guessing.
 */
@Component
public class EffectivePomCache {

    private static final Logger log = LoggerFactory.getLogger(EffectivePomCache.class);


    private final Map<String, Optional<EffectivePomFragments>> cache = new ConcurrentHashMap<>();

    /** Session-scoped: cleared when the Maven tool settings change, same as the probe cache. */
    @EventListener
    public void onMavenSettingsChanged(MavenSettingsChangedEvent event) {
        cache.clear();
    }

    /**
     * @param effectivePomGoal the fully qualified, version-pinned {@code help:effective-pom}
     *                         goal — see {@code MavenToolSettings.effectivePomGoal()}
     */
    public Optional<EffectivePomFragments> forWorkspace(
            String workspacePath, String mvnExecutable, String isolatedRepository, Duration timeout,
            String profiles, String effectivePomGoal) {
        // Cache key includes profiles: the same workspace lifts different dependencyManagement
        // and repositories depending on which profiles are active, and a stale fragment lifted
        // under a different profile set would silently misinform every probe in the run. The goal
        // joins it for the same reason — a fragment lifted by a plugin version that has since
        // been changed is exactly as stale, and settings changes clear this cache anyway.
        String cacheKey = String.join("|", workspacePath,
                profiles == null ? "" : profiles, effectivePomGoal);
        return cache.computeIfAbsent(cacheKey, key ->
                compute(workspacePath, mvnExecutable, isolatedRepository, timeout, profiles, effectivePomGoal));
    }

    private Optional<EffectivePomFragments> compute(
            String workspacePath, String mvnExecutable, String isolatedRepository, Duration timeout,
            String profiles, String effectivePomGoal) {
        Path pom = Path.of(workspacePath, "pom.xml");
        if (!Files.isRegularFile(pom)) {
            log.debug("No pom.xml at workspace root {}; probe stays isolated.", workspacePath);
            return Optional.empty();
        }

        Path outputFile;
        try {
            outputFile = Files.createTempFile("sbomscope-effective-pom-", ".xml");
        } catch (IOException e) {
            return Optional.empty();
        }

        try {
            List<String> command = new ArrayList<>(List.of(
                    mvnExecutable, "-N", "-B", "-q", effectivePomGoal,
                    "-f", pom.toString(),
                    "-Dmaven.repo.local=" + isolatedRepository,
                    "-Doutput=" + outputFile));
            if (profiles != null && !profiles.isBlank()) {
                command.add("-P" + profiles.trim());
            }

            MavenInvocation.Result result =
                    MavenInvocation.run("help:effective-pom", command, null, timeout);
            if (!result.ok()) {
                // Previously this failed silently and the probe carried on isolated. The
                // lift-in is precisely what makes a supplier's own repository reachable, so
                // losing it is the difference between probes that resolve and probes that
                // cannot — never something to discover by inference.
                log.warn("Could not lift dependencyManagement/repositories from {} — the probe will run "
                        + "isolated, without this project's own repositories or managed versions. {}",
                        workspacePath, result.lastMeaningfulLine());
                return Optional.empty();
            }
            if (!Files.isRegularFile(outputFile) || Files.size(outputFile) == 0) {
                log.warn("mvn help:effective-pom succeeded for {} but wrote no output to {}; "
                        + "the probe will run isolated.", workspacePath, outputFile);
                return Optional.empty();
            }

            return Optional.of(extractFragments(outputFile));
        } catch (Exception e) {
            log.warn("Could not lift dependencyManagement/repositories from {}", workspacePath, e);
            return Optional.empty();
        } finally {
            try {
                Files.deleteIfExists(outputFile);
            } catch (IOException e) {
                log.debug("Could not delete {}", outputFile, e);
            }
        }
    }

    private EffectivePomFragments extractFragments(Path effectivePom) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(effectivePom.toFile());

        Element project = document.getDocumentElement();
        return new EffectivePomFragments(
                serialiseFirstChild(project, "dependencyManagement"),
                serialiseFirstChild(project, "repositories"));
    }

    /** The direct child only — a nested one belongs to a plugin configuration, not the project. */
    private String serialiseFirstChild(Element project, String tagName) throws Exception {
        NodeList children = project.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            if (children.item(i) instanceof Element element && tagName.equals(element.getTagName())) {
                return serialise(element);
            }
        }
        return null;
    }

    private String serialise(Element element) throws Exception {
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        transformer.setOutputProperty(OutputKeys.INDENT, "no");
        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(element), new StreamResult(writer));
        return writer.toString();
    }

}
