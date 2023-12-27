package org.codelibs.saml2.core.exception;

import java.security.cert.CertificateException;

public class X509CertificateException extends SAMLException {

    private static final long serialVersionUID = 1L;

    public X509CertificateException(CertificateException e) {
        super(e);
    }

}
