package org.codelibs.saml2.core.exception;

import java.security.cert.CertificateException;

/**
 * Exception thrown when an X.509 certificate cannot be processed.
 */
public class X509CertificateException extends SAMLException {

    /** Serial version UID. */
    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new {@code X509CertificateException} wrapping the given certificate exception.
     *
     * @param e the underlying certificate exception
     */
    public X509CertificateException(final CertificateException e) {
        super(e);
    }

}
