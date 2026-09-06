package dev.sbomscope.bump;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/** Reads only the installed dependency constraints that npm lockfiles v2/v3 prove. */
final class NpmLockfileReader {

    record Result(Map<String, String> requirements, String problem) {
        boolean recognized() {
            return problem == null;
        }
    }

    private final ObjectMapper json = new ObjectMapper();

    Result requirements(Path lockfile, List<String> parents, String child) {
        if (parents.isEmpty()) {
            return new Result(Map.of(), "the declaring parent is not available");
        }
        try (InputStream input = Files.newInputStream(lockfile)) {
            JsonNode root = json.readTree(input);
            JsonNode version = root == null ? null : root.get("lockfileVersion");
            if (version == null || !version.isInt()
                    || version.asInt() != 2 && version.asInt() != 3) {
                return new Result(Map.of(), "only package-lock.json versions 2 and 3 are supported");
            }
            JsonNode packages = root.get("packages");
            if (packages == null || !packages.isObject()) {
                return new Result(Map.of(), "the package-lock.json has no recognised packages map");
            }
            Map<String, String> requirements = new LinkedHashMap<>();
            for (String parent : parents) {
                JsonNode installed = packages.get("node_modules/" + parent);
                JsonNode dependencies = installed == null ? null : installed.get("dependencies");
                JsonNode requirement = dependencies == null ? null : dependencies.get(child);
                if (requirement == null || !requirement.isTextual() || requirement.asText().isBlank()) {
                    return new Result(Map.of(), "the package-lock.json does not record how "
                            + parent + " requires " + child);
                }
                requirements.put(parent, requirement.asText());
            }
            return new Result(Map.copyOf(requirements), null);
        } catch (IOException | RuntimeException exception) {
            return new Result(Map.of(), "the package-lock.json could not be read: "
                    + exception.getMessage());
        }
    }
}
