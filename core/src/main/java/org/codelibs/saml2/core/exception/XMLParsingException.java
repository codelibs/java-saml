package org.codelibs.saml2.core.exception;

/**
 * Exception thrown when XML parsing fails.
 */
public class XMLParsingException extends SAMLException {

    /** Serial version UID. */
    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new {@code XMLParsingException} with the given message and cause.
     *
     * @param message the detail message
     * @param cause the underlying cause of the parsing failure
     */
    public XMLParsingException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
