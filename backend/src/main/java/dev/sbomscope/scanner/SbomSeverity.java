package dev.sbomscope.scanner;

import java.util.EnumMap;
import java.util.Map;

/**
 * What one SBOM's risk looks like from the outside — enough for a list to be triaged
 * without opening every entry.
 *
 * <p>{@code scannedComponents} is not decoration. Band counts alone cannot distinguish a
 * document that was checked and came back clean from one nobody has ever run the scanner
 * over: both report zero criticals. That is the same conflation the schema avoids by
 * writing a scan row for every component, and it must survive all the way to the screen,
 * so the count that makes the distinction possible travels with the numbers it qualifies.
 *
 * @param scannedComponents how many of the SBOM's components carry a scan record; zero
 *                          means never checked, and the counts below then say nothing
 * @param counts            rows per band across the whole SBOM, every band present even at
 *                          zero, counted the same way the findings view counts them
 */
public record SbomSeverity(int scannedComponents, Map<FindingQuery.SeverityBand, Integer> counts) {

    /** Every band at zero — the starting point for a count, and the whole of an empty one. */
    public static Map<FindingQuery.SeverityBand, Integer> zeroedBands() {
        Map<FindingQuery.SeverityBand, Integer> bands = new EnumMap<>(FindingQuery.SeverityBand.class);
        for (FindingQuery.SeverityBand band : FindingQuery.SeverityBand.values()) {
            bands.put(band, 0);
        }
        return bands;
    }

    /** For an SBOM the scanner has never reached — distinct from one with nothing found. */
    public static SbomSeverity notScanned() {
        return new SbomSeverity(0, zeroedBands());
    }
}
