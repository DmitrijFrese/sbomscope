package dev.sbomscope.reachability;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;

import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import dev.sbomscope.sbom.DependencyScope;
import dev.sbomscope.sbom.StoredComponent;

/**
 * Relates a compiled Maven module to an aggregate SBOM only when its coordinates match exactly.
 * Reading a POM is metadata parsing, not a Maven invocation: no plugin, profile, repository or
 * workspace code is executed. Values which need Maven's full model remain explicitly unmapped.
 */
@Component
public class WorkspaceModuleMapper {

    public List<ModuleMapping> map(Path workspace, List<Path> outputs, List<StoredComponent> components) {
        List<StoredComponent> application = components.stream()
                .filter(component -> component.scope() == DependencyScope.APPLICATION)
                .toList();
        List<ModuleMapping> result = new ArrayList<>();
        for (Path output : outputs) {
            Path root = output.toAbsolutePath().normalize().getParent().getParent();
            Coordinates coordinates = coordinates(root.resolve("pom.xml")).orElse(null);
            List<StoredComponent> matches = coordinates == null ? List.of() : application.stream()
                    .filter(component -> coordinates.matches(component))
                    .toList();
            String label = label(workspace, root);
            if (matches.size() == 1) {
                result.add(new ModuleMapping(output, label, matches.getFirst(), null));
            } else if (coordinates == null) {
                result.add(new ModuleMapping(output, label, null,
                        "Could not read complete Maven coordinates from " + root.resolve("pom.xml")));
            } else {
                result.add(new ModuleMapping(output, label, null,
                        matches.isEmpty() ? "No APPLICATION component exactly matches " + coordinates
                                : "More than one APPLICATION component matches " + coordinates));
            }
        }
        return List.copyOf(result);
    }

    private Optional<Coordinates> coordinates(Path pom) {
        if (!Files.isRegularFile(pom) || !Files.isReadable(pom)) return Optional.empty();
        try (InputStream input = Files.newInputStream(pom)) {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            Document document = factory.newDocumentBuilder().parse(input);
            Element project = document.getDocumentElement();
            Element parent = child(project, "parent");
            String group = text(project, "groupId");
            String version = text(project, "version");
            if (parent != null) {
                if (blank(group)) group = text(parent, "groupId");
                if (blank(version)) version = text(parent, "version");
            }
            String artifact = text(project, "artifactId");
            return blank(group) || blank(artifact) || blank(version)
                    || group.contains("${") || artifact.contains("${") || version.contains("${")
                    ? Optional.empty() : Optional.of(new Coordinates(group, artifact, version));
        } catch (Exception ignored) {
            return Optional.empty();
        }
    }

    private Element child(Element parent, String name) {
        for (var node = parent.getFirstChild(); node != null; node = node.getNextSibling()) {
            if (node instanceof Element element && name.equals(element.getTagName())) return element;
        }
        return null;
    }

    private String text(Element parent, String name) {
        Element child = child(parent, name);
        return child == null ? null : child.getTextContent().trim();
    }

    private boolean blank(String value) {
        return value == null || value.isBlank();
    }

    private String label(Path workspace, Path root) {
        Path relative = workspace.toAbsolutePath().normalize().relativize(root);
        return relative.toString().isBlank() ? "workspace root" : relative.toString().replace('\\', '/');
    }

    private record Coordinates(String group, String artifact, String version) {
        boolean matches(StoredComponent component) {
            return group.equals(component.group()) && artifact.equals(component.name()) && version.equals(component.version());
        }

        @Override public String toString() { return group + ":" + artifact + ":" + version; }
    }

    public record ModuleMapping(Path output, String label, StoredComponent component, String reason) {
        public boolean mapped() { return component != null; }
    }
}
