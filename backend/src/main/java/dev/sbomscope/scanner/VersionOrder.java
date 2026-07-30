package dev.sbomscope.scanner;

import java.util.Comparator;

/**
 * Orders version strings well enough to decide which advisory branch a component sits on.
 *
 * <p>Needed because an advisory routinely describes several parallel release lines, and only
 * one of them says anything about the version actually in use. The Angular advisory that
 * prompted this lists four ranges for one package — fixes on 22.x, 21.x and 20.x, and a 19.x
 * line with no fix at all. Reading them in file order tells someone on 19.2.17 to upgrade to
 * 22.0.1, crossing three major versions to reach a branch their advisory never mentioned.
 *
 * <p>Deliberately not a full version implementation. It handles dotted numeric releases with
 * an optional pre-release suffix, which is what OSV's {@code SEMVER} ranges are made of, and
 * is a fair approximation for Maven's dotted versions. Maven's own qualifier rules are more
 * elaborate, so {@link OsvReportParser} prefers an advisory's explicit {@code versions[]}
 * enumeration where one exists — around 90% of the Maven set — and only falls back to this.
 *
 * <p>Public because the Maven probe (Tier 2) needs the same ordering to walk a tier's
 * versions ascending — a second implementation would drift the same way two "is this version
 * affected" statements would.
 */
public final class VersionOrder implements Comparator<String> {

    public static final VersionOrder INSTANCE = new VersionOrder();

    private VersionOrder() {}

    @Override
    public int compare(String left, String right) {
        Parsed a = Parsed.of(left);
        Parsed b = Parsed.of(right);

        int releases = Math.max(a.release.length, b.release.length);
        for (int index = 0; index < releases; index++) {
            // A missing part is zero, so 1.2 and 1.2.0 are the same version.
            int comparison = Long.compare(a.partAt(index), b.partAt(index));
            if (comparison != 0) {
                return comparison;
            }
        }

        // 22.0.0-next.0 precedes 22.0.0: a pre-release is on the way to the release, not past
        // it. This is what places 22.0.0-next.0 below a 19.x version's branch boundary rather
        // than making the ranges overlap.
        if (a.preRelease == null && b.preRelease == null) {
            return 0;
        }
        if (a.preRelease == null) {
            return 1;
        }
        if (b.preRelease == null) {
            return -1;
        }
        return a.preRelease.compareTo(b.preRelease);
    }

    /** Release numbers, plus whatever followed the first {@code -}. */
    private record Parsed(long[] release, String preRelease) {

        static Parsed of(String version) {
            if (version == null || version.isBlank()) {
                return new Parsed(new long[0], null);
            }
            String value = version.trim();
            // Build metadata never affects ordering.
            int plus = value.indexOf('+');
            if (plus >= 0) {
                value = value.substring(0, plus);
            }

            int dash = value.indexOf('-');
            String numbers = dash >= 0 ? value.substring(0, dash) : value;
            String preRelease = dash >= 0 ? value.substring(dash + 1) : null;

            String[] parts = numbers.split("\\.");
            long[] release = new long[parts.length];
            for (int index = 0; index < parts.length; index++) {
                release[index] = parseOrZero(parts[index]);
            }
            return new Parsed(release, preRelease);
        }

        long partAt(int index) {
            return index < release.length ? release[index] : 0L;
        }

        /**
         * Anything non-numeric contributes nothing to the release ordering rather than
         * failing: it is better to place an odd version approximately than to abandon the
         * comparison and fall back to file order, which is what this exists to replace.
         */
        private static long parseOrZero(String part) {
            StringBuilder digits = new StringBuilder();
            for (char character : part.toCharArray()) {
                if (!Character.isDigit(character)) {
                    break;
                }
                digits.append(character);
            }
            if (digits.isEmpty()) {
                return 0L;
            }
            try {
                return Long.parseLong(digits.toString());
            } catch (NumberFormatException e) {
                return 0L;
            }
        }
    }
}
