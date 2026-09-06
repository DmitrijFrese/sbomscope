package dev.sbomscope.bump;

import java.math.BigInteger;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Semantic-version precedence, deliberately separate from Maven's version ordering. */
public final class SemverOrder implements Comparator<String> {

    public static final SemverOrder INSTANCE = new SemverOrder();

    private static final Pattern VERSION = Pattern.compile(
            "(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)"
                    + "(?:-([0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*))?"
                    + "(?:\\+([0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*))?");

    @Override
    public int compare(String left, String right) {
        Parsed first = parse(left);
        Parsed second = parse(right);
        if (first == null || second == null) {
            return Comparator.nullsFirst(String::compareTo).compare(left, right);
        }
        int core = first.major().compareTo(second.major());
        if (core == 0) {
            core = first.minor().compareTo(second.minor());
        }
        if (core == 0) {
            core = first.patch().compareTo(second.patch());
        }
        if (core != 0) {
            return core;
        }
        if (first.prerelease().isEmpty() || second.prerelease().isEmpty()) {
            return Boolean.compare(first.prerelease().isEmpty(), second.prerelease().isEmpty());
        }
        for (int index = 0; index < Math.min(first.prerelease().size(),
                second.prerelease().size()); index++) {
            int identifier = compareIdentifier(first.prerelease().get(index),
                    second.prerelease().get(index));
            if (identifier != 0) {
                return identifier;
            }
        }
        return Integer.compare(first.prerelease().size(), second.prerelease().size());
    }

    static Parsed parse(String version) {
        if (version == null) {
            return null;
        }
        Matcher matcher = VERSION.matcher(version);
        if (!matcher.matches()) {
            return null;
        }
        List<String> prerelease = matcher.group(4) == null ? List.of()
                : List.of(matcher.group(4).split("\\."));
        if (prerelease.stream().anyMatch(SemverOrder::invalidNumericIdentifier)) {
            return null;
        }
        return new Parsed(new BigInteger(matcher.group(1)), new BigInteger(matcher.group(2)),
                new BigInteger(matcher.group(3)), prerelease);
    }

    private static int compareIdentifier(String left, String right) {
        boolean leftNumeric = left.chars().allMatch(Character::isDigit);
        boolean rightNumeric = right.chars().allMatch(Character::isDigit);
        if (leftNumeric && rightNumeric) {
            return new BigInteger(left).compareTo(new BigInteger(right));
        }
        if (leftNumeric != rightNumeric) {
            return leftNumeric ? -1 : 1;
        }
        return left.compareTo(right);
    }

    private static boolean invalidNumericIdentifier(String value) {
        return value.length() > 1 && value.charAt(0) == '0'
                && value.chars().allMatch(Character::isDigit);
    }

    record Parsed(BigInteger major, BigInteger minor, BigInteger patch,
                  List<String> prerelease) {
        boolean sameCore(Parsed other) {
            return major.equals(other.major) && minor.equals(other.minor) && patch.equals(other.patch);
        }
    }
}
