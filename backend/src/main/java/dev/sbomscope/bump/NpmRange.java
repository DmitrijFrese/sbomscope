package dev.sbomscope.bump;

import java.math.BigInteger;

/** The deliberately narrow npm range grammar this first pass can edit without guessing. */
public final class NpmRange {

    private NpmRange() {}

    /** Does this declared range already permit {@code version}? */
    public static boolean admits(String literal, String version) {
        Range range = parse(literal);
        SemverOrder.Parsed candidate = SemverOrder.parse(version);
        if (range == null || candidate == null) {
            return false;
        }
        int fromLower = SemverOrder.INSTANCE.compare(version, range.version());
        if (range.operator().isEmpty()) {
            return fromLower == 0;
        }
        if (fromLower < 0 || excludedPrerelease(range.parsed(), candidate)) {
            return false;
        }
        return switch (range.operator()) {
            case ">=" -> true;
            case "~" -> before(candidate, range.parsed().major(),
                    range.parsed().minor().add(BigInteger.ONE), BigInteger.ZERO);
            case "^" -> beforeCaretUpper(candidate, range.parsed());
            default -> false;
        };
    }

    /** The literal rewritten to {@code version}, preserving its supported operator. */
    public static String rewrite(String literal, String version) {
        Range range = parse(literal);
        if (range == null || SemverOrder.parse(version) == null) {
            throw new IllegalArgumentException("Unsupported npm range or version");
        }
        return range.operator() + version;
    }

    /** False for any literal outside the exact, caret, tilde and greater-than-or-equal grammar. */
    public static boolean isSupported(String literal) {
        return parse(literal) != null;
    }

    private static Range parse(String literal) {
        if (literal == null || literal.isEmpty() || !literal.equals(literal.trim())) {
            return null;
        }
        String operator = literal.startsWith(">=") ? ">="
                : literal.startsWith("^") ? "^"
                : literal.startsWith("~") ? "~" : "";
        String version = literal.substring(operator.length());
        SemverOrder.Parsed parsed = SemverOrder.parse(version);
        return parsed == null ? null : new Range(operator, version, parsed);
    }

    private static boolean beforeCaretUpper(SemverOrder.Parsed candidate,
                                             SemverOrder.Parsed lower) {
        if (lower.major().signum() > 0) {
            return before(candidate, lower.major().add(BigInteger.ONE), BigInteger.ZERO,
                    BigInteger.ZERO);
        }
        if (lower.minor().signum() > 0) {
            return before(candidate, BigInteger.ZERO, lower.minor().add(BigInteger.ONE),
                    BigInteger.ZERO);
        }
        return before(candidate, BigInteger.ZERO, BigInteger.ZERO,
                lower.patch().add(BigInteger.ONE));
    }

    private static boolean before(SemverOrder.Parsed candidate, BigInteger major,
                                  BigInteger minor, BigInteger patch) {
        SemverOrder.Parsed upper = new SemverOrder.Parsed(major, minor, patch,
                java.util.List.of());
        int comparison = candidate.major().compareTo(upper.major());
        if (comparison == 0) {
            comparison = candidate.minor().compareTo(upper.minor());
        }
        if (comparison == 0) {
            comparison = candidate.patch().compareTo(upper.patch());
        }
        return comparison < 0;
    }

    private static boolean excludedPrerelease(SemverOrder.Parsed lower,
                                              SemverOrder.Parsed candidate) {
        return !candidate.prerelease().isEmpty()
                && (lower.prerelease().isEmpty() || !candidate.sameCore(lower));
    }

    private record Range(String operator, String version, SemverOrder.Parsed parsed) {}
}
