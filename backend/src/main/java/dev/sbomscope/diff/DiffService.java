package dev.sbomscope.diff;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.springframework.stereotype.Service;

import dev.sbomscope.diff.DiffRow.Change;
import dev.sbomscope.diff.DiffRow.Side;
import dev.sbomscope.export.AdvisoryLinks;
import dev.sbomscope.scanner.FindingQuery;
import dev.sbomscope.scanner.FindingRow;
import dev.sbomscope.scanner.InvalidFilterPatternException;
import dev.sbomscope.scanner.VersionOrder;
import dev.sbomscope.scanner.VulnerabilityRepository;

@Service
public class DiffService {

    private static final Comparator<String> TEXT_ORDER = Comparator.nullsLast(
            String.CASE_INSENSITIVE_ORDER.thenComparing(Comparator.naturalOrder()));
    private static final Comparator<String> VERSION_ORDER = Comparator.nullsLast(
            VersionOrder.INSTANCE.thenComparing(Comparator.naturalOrder()));

    private final VulnerabilityRepository findings;

    DiffService(VulnerabilityRepository findings) {
        this.findings = findings;
    }

    public record DiffResult(List<DiffRow> rows, Summary summary) {}

    public record Summary(Map<Change, Integer> changes, int cveIdsGained, int cveIdsLost) {}

    public enum DiffSort {
        /** Group, then artifact — the reading order of a coordinate. */
        COORDINATES,
        /** The kind of change, with coordinates ascending inside each kind. */
        CHANGE
    }

    public DiffResult compare(UUID leftId, UUID rightId, String filter, boolean regex,
                              boolean negate) {
        return compare(leftId, rightId, filter, regex, negate, DiffSort.COORDINATES, true);
    }

    public DiffResult compare(UUID leftId, UUID rightId, String filter, boolean regex,
                              boolean negate, DiffSort sort, boolean ascending) {
        Predicate<String> textMatch = textMatch(filter, regex);

        List<FindingRow> leftRows = findings.rowsForSbom(leftId, FindingQuery.everything());
        List<FindingRow> rightRows = findings.rowsForSbom(rightId, FindingQuery.everything());

        Map<Identity, IdentityVersions> left = group(leftRows);
        Map<Identity, IdentityVersions> right = group(rightRows);
        List<DiffRow> allRows = pair(left, right, sort, ascending);

        // Summarised before the filter, so the totals describe the whole comparison however the
        // rows are narrowed — the same choice the severity chips make, and for the same reason:
        // a number that moved with the filter could not be used to judge what the filter hid.
        // Whatever presents this has to say so, or it reads as a count of what is on screen.
        Summary summary = summarize(allRows);

        if (textMatch == null) {
            return new DiffResult(allRows, summary);
        }

        // The filter contract is coordinates, both versions and both sides' cveIds. Purls and
        // finding details are deliberately not searched, because they are not diff-row fields.
        List<DiffRow> filtered = allRows.stream()
                .filter(row -> negate != matches(row, textMatch))
                .toList();
        return new DiffResult(filtered, summary);
    }

    private Map<Identity, IdentityVersions> group(List<FindingRow> rows) {
        Map<Identity, IdentityVersions> grouped = new HashMap<>();
        for (FindingRow row : rows) {
            Identity identity = new Identity(row.group(), row.name());
            grouped.computeIfAbsent(identity, ignored -> new IdentityVersions(row.coordinates()))
                    .add(row);
        }
        return grouped;
    }

    private List<DiffRow> pair(Map<Identity, IdentityVersions> left,
                               Map<Identity, IdentityVersions> right,
                               DiffSort sort, boolean ascending) {
        Set<Identity> identities = new HashSet<>(left.keySet());
        identities.addAll(right.keySet());

        List<DiffRow> rows = new ArrayList<>();
        for (Identity identity : identities) {
            IdentityVersions leftVersions = left.get(identity);
            IdentityVersions rightVersions = right.get(identity);
            Map<String, Side> leftSides = sides(leftVersions);
            Map<String, Side> rightSides = sides(rightVersions);
            String coordinates = leftVersions != null
                    ? leftVersions.coordinates()
                    : rightVersions.coordinates();

            // Where one side holds a single version, every version on the other side has an
            // unambiguous counterpart, so each one pairs into a change.
            //
            // **Widened 2026-09-07 from "one version on each side", after using the view.** The
            // narrow rule was defended as refusing to guess, and for the case it was written for —
            // several versions on *both* sides — it still is. But the common real shape is a
            // consolidation: two versions coexisting become one, and the old rule reported that as
            // two removals and an addition scattered through the table, which is where an upgrade
            // becomes hard to see. Two rows both arriving at 1.5.34 is not a guess and not a double
            // count: it is what happened to each version that was there, and everything that had
            // 1.2.6 does now have 1.5.34. The same holds mirrored, for one version becoming several.
            if (!leftSides.isEmpty() && !rightSides.isEmpty()
                    && (leftSides.size() == 1 || rightSides.size() == 1)) {
                boolean singleOnLeft = leftSides.size() == 1;
                Side single = (singleOnLeft ? leftSides : rightSides).values().iterator().next();
                for (Side counterpart : (singleOnLeft ? rightSides : leftSides).values()) {
                    Side leftSide = singleOnLeft ? single : counterpart;
                    Side rightSide = singleOnLeft ? counterpart : single;
                    Change change = Objects.equals(leftSide.version(), rightSide.version())
                            ? Change.UNCHANGED
                            : Change.VERSION_CHANGED;
                    rows.add(new DiffRow(coordinates, identity.group(), identity.name(),
                            leftSide, rightSide, change));
                }
                continue;
            }

            // Several versions on both sides genuinely is ambiguous — nothing says which of the
            // old ones became which of the new — so each keeps its own row rather than being
            // paired by guesswork. A side with no versions at all lands here too, as a whole
            // library arriving or leaving.
            Set<String> versions = new HashSet<>(leftSides.keySet());
            versions.addAll(rightSides.keySet());
            for (String version : versions) {
                Side leftSide = leftSides.get(version);
                Side rightSide = rightSides.get(version);
                Change change = leftSide == null
                        ? Change.ADDED
                        : rightSide == null ? Change.REMOVED : Change.UNCHANGED;
                rows.add(new DiffRow(coordinates, identity.group(), identity.name(),
                        leftSide, rightSide, change));
            }
        }

        rows.sort(rowOrder(sort, ascending));
        return List.copyOf(rows);
    }

    private Comparator<DiffRow> rowOrder(DiffSort sort, boolean ascending) {
        Comparator<DiffRow> coordinates = Comparator.comparing(DiffRow::group,
                        ascending ? TEXT_ORDER : Comparator.nullsLast(TEXT_ORDER.reversed()))
                .thenComparing(DiffRow::name,
                        ascending ? TEXT_ORDER : Comparator.nullsLast(TEXT_ORDER.reversed()));
        Comparator<DiffRow> versions = Comparator.comparing(DiffService::versionOf, VERSION_ORDER)
                .thenComparing(row -> row.right() == null ? null : row.right().version(), VERSION_ORDER);

        if (sort == DiffSort.COORDINATES) {
            return coordinates.thenComparing(versions);
        }

        // The declaration order is the summary's order (ADDED, REMOVED, VERSION_CHANGED,
        // UNCHANGED), so ordinal states that shared rank rather than relying on spelling.
        Comparator<DiffRow> changes = Comparator.comparingInt(row -> row.change().ordinal());
        if (!ascending) {
            changes = changes.reversed();
        }
        // Direction reverses the change groups only. Coordinates remain readable within each.
        return changes.thenComparing(Comparator.comparing(DiffRow::group, TEXT_ORDER)
                .thenComparing(DiffRow::name, TEXT_ORDER))
                .thenComparing(versions);
    }

    private Map<String, Side> sides(IdentityVersions versions) {
        if (versions == null) {
            return Map.of();
        }
        Map<String, Side> result = new HashMap<>();
        versions.versions().forEach((version, side) -> result.put(version, side.toSide(version)));
        return result;
    }

    private Summary summarize(List<DiffRow> rows) {
        EnumMap<Change, Integer> changes = new EnumMap<>(Change.class);
        for (Change change : Change.values()) {
            changes.put(change, 0);
        }

        Set<String> leftIds = new HashSet<>();
        Set<String> rightIds = new HashSet<>();
        for (DiffRow row : rows) {
            changes.merge(row.change(), 1, Integer::sum);
            if (row.left() != null) {
                leftIds.addAll(row.left().cveIds());
            }
            if (row.right() != null) {
                rightIds.addAll(row.right().cveIds());
            }
        }

        Set<String> gained = new HashSet<>(rightIds);
        gained.removeAll(leftIds);
        Set<String> lost = new HashSet<>(leftIds);
        lost.removeAll(rightIds);
        return new Summary(Collections.unmodifiableMap(changes), gained.size(), lost.size());
    }

    private Predicate<String> textMatch(String filter, boolean regex) {
        if (filter == null || filter.isBlank()) {
            return null;
        }
        if (!regex) {
            String needle = filter.trim().toLowerCase(Locale.ROOT);
            return value -> value != null && value.toLowerCase(Locale.ROOT).contains(needle);
        }
        try {
            Pattern pattern = Pattern.compile(filter, Pattern.CASE_INSENSITIVE);
            return value -> value != null && pattern.matcher(value).find();
        } catch (PatternSyntaxException e) {
            throw new InvalidFilterPatternException(filter, e);
        }
    }

    private boolean matches(DiffRow row, Predicate<String> textMatch) {
        if (textMatch.test(row.coordinates())) {
            return true;
        }
        return matches(row.left(), textMatch) || matches(row.right(), textMatch);
    }

    private boolean matches(Side side, Predicate<String> textMatch) {
        return side != null && (textMatch.test(side.version())
                || side.cveIds().stream().anyMatch(textMatch));
    }

    private static String versionOf(DiffRow row) {
        return row.left() != null ? row.left().version() : row.right().version();
    }

    private record Identity(String group, String name) {}

    private static final class IdentityVersions {

        private final String coordinates;
        private final Map<String, SideAccumulator> versions = new HashMap<>();

        private IdentityVersions(String coordinates) {
            this.coordinates = coordinates;
        }

        private void add(FindingRow row) {
            versions.computeIfAbsent(row.version(), ignored -> new SideAccumulator()).add(row);
        }

        private String coordinates() {
            return coordinates;
        }

        private Map<String, SideAccumulator> versions() {
            return versions;
        }
    }

    private static final class SideAccumulator {

        private final TreeSet<String> purls = new TreeSet<>();
        private final EnumMap<FindingQuery.SeverityBand, Integer> counts =
                new EnumMap<>(FindingQuery.SeverityBand.class);
        private final TreeSet<String> cveIds = new TreeSet<>();
        private final TreeMap<String, String> advisoryUrls = new TreeMap<>();

        private SideAccumulator() {
            for (FindingQuery.SeverityBand band : FindingQuery.SeverityBand.values()) {
                counts.put(band, 0);
            }
        }

        private void add(FindingRow row) {
            if (row.purl() != null) {
                purls.add(row.purl());
            }
            // The shared classifier, not a local copy of the thresholds: the diff must call a
            // row critical exactly when the findings table does.
            counts.merge(FindingQuery.SeverityBand.of(row.hasFinding(), row.severityScore()),
                    1, Integer::sum);

            if (row.hasFinding()) {
                boolean hasCve = row.cveId() != null && !row.cveId().isBlank();
                String identifier = hasCve ? row.cveId() : row.osvId();
                if (identifier != null && !identifier.isBlank()) {
                    cveIds.add(identifier);
                    // Whichever kind it is, the destination comes from AdvisoryLinks rather
                    // than from a template written here — the same rule the findings table and
                    // the workbook already read.
                    String url = hasCve
                            ? AdvisoryLinks.cveUrl(identifier)
                            : AdvisoryLinks.osvUrl(identifier);
                    if (url != null) {
                        advisoryUrls.put(identifier, url);
                    }
                }
            }
        }

        private Side toSide(String version) {
            return new Side(purls.isEmpty() ? null : purls.first(), version,
                    Collections.unmodifiableMap(new EnumMap<>(counts)), List.copyOf(cveIds),
                    Map.copyOf(advisoryUrls));
        }
    }
}
