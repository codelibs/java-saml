package org.codelibs.saml2.core.exception;

import java.security.spec.InvalidKeySpecException;

/**
 * Runtime exception wrapping an {@link InvalidKeySpecException}.
 */
public class InvalidKeySpecRuntimeException extends RuntimeException {

    /** Serial version UID. */
    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new {@code InvalidKeySpecRuntimeException} wrapping the given key spec exception.
     *
     * @param e the underlying invalid key spec exception
     */
    public InvalidKeySpecRuntimeException(InvalidKeySpecException e) {
        super(e);
    }
}
