package dev.sbomscope.scanner;

import java.util.regex.PatternSyntaxException;

/**
 * The text filter was switched to regular-expression mode and does not compile.
 *
 * <p><b>This is normal input, not a fault.</b> A filter field is typed into one character at a
 * time, so {@code ^(org\.spring} exists on the way to every pattern that starts that way — a
 * half-written regex is the common case, not the exceptional one. It has to produce a readable
 * message and a 400, never a 500 with a stack trace.
 *
 * <p>Its own type rather than {@code IllegalArgumentException} for the reason AGENTS.md records
 * twice about exception handling: the handler should key on what this <em>is</em>, not on
 * something it happens to extend. Thrown before the pattern reaches SQL, so the message is
 * {@link PatternSyntaxException}'s own — which names the offending index — rather than whatever
 * a JDBC layer wrapped it in by the time it came back.
 */
public class InvalidFilterPatternException extends RuntimeException {

    private final String pattern;

    public InvalidFilterPatternException(String pattern, PatternSyntaxException cause) {
        super(readableMessage(cause), cause);
        this.pattern = pattern;
    }

    public String pattern() {
        return pattern;
    }

    /**
     * Java's own text, with the caret diagram flattened onto one line.
     *
     * <p>{@code PatternSyntaxException.getMessage()} is three lines — description, the pattern,
     * and a caret under the offending character. That is exactly right in a terminal and wrong
     * in a JSON error field rendered into a sentence, where the newlines are lost and the caret
     * lands under nothing. {@code getDescription()} and {@code getIndex()} carry the same
     * information in a form that survives.
     */
    private static String readableMessage(PatternSyntaxException cause) {
        String description = cause.getDescription();
        if (description == null || description.isBlank()) {
            return "That is not a valid regular expression.";
        }
        return cause.getIndex() < 0
                ? description + "."
                : "%s at position %d.".formatted(description, cause.getIndex());
    }
}
