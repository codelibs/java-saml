package org.codelibs.saml2.core.util;

/**
 * Utility class providing argument precondition checks.
 */
public final class Preconditions {
    /**
     * Throws a IllegalArgumentException if {@code t} is null.
     *
     * @param <T>     the type of the value being checked
     * @param t       the value to check for null
     * @param message the message to include in the thrown exception
     *
     * @return T
     *
     * @throws IllegalArgumentException if {@code t} is null
     */
    public static <T> T checkNotNull(final T t, final String message) {
        if (t == null) {
            throw new IllegalArgumentException(message);
        }
        return t;
    }

    private Preconditions() {
    }
}
