package org.codelibs.saml2.core.exception;

import java.security.spec.InvalidKeySpecException;

public class InvalidKeySpecRuntimeException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public InvalidKeySpecRuntimeException(InvalidKeySpecException e) {
        super(e);
    }
}
