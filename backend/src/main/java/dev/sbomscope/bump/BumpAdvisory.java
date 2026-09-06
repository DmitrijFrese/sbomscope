package dev.sbomscope.bump;

/** @param cveId its CVE counterpart, or null when the advisory has none */
public record BumpAdvisory(String osvId, String cveId, String osvUrl, String cveUrl) {}
