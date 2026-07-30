package dev.sbomscope.probe;

/**
 * {@code <dependencyManagement>} and {@code <repositories>}, lifted verbatim from
 * {@code mvn help:effective-pom} and spliced into a generated probe POM.
 *
 * <p>Both null when the corresponding element was absent from the effective POM — a project
 * with no repositories of its own, or no managed dependencies, is not an error.
 *
 * @param dependencyManagementXml so the probe honours the project's own pins and imported BOMs
 * @param repositoriesXml         so a supplier's Nexus that is not in {@code settings.xml} is
 *                                still reachable — the actual fix for probes failing on
 *                                supplier artifacts
 */
public record EffectivePomFragments(String dependencyManagementXml, String repositoriesXml) {}
