package org.codelibs.saml2.core.exception;

/**
 * Exception thrown when a SAML signature operation fails.
 */
public class SAMLSignatureException extends SAMLException {

    /** Serial version UID. */
    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new {@code SAMLSignatureException} wrapping the given exception.
     *
     * @param e the underlying exception
     */
    public SAMLSignatureException(Exception e) {
        super(e);
    }

}
