package org.codelibs.saml2.core.exception;

/**
 * Exception thrown when a severe, non-recoverable SAML error occurs.
 * Each instance carries an error code identifying the specific severe condition.
 */
public class SAMLSevereException extends SAMLException {

    /** Serialization version identifier. */
    private static final long serialVersionUID = 1L;

    /** Error code indicating that the settings file could not be found. */
    public static final int SETTINGS_FILE_NOT_FOUND = 1;
    /** Error code indicating that the service provider metadata is invalid. */
    public static final int METADATA_SP_INVALID = 2;
    /** Error code indicating that the SAML response was not found. */
    public static final int SAML_RESPONSE_NOT_FOUND = 3;
    /** Error code indicating that the SAML logout message was not found. */
    public static final int SAML_LOGOUTMESSAGE_NOT_FOUND = 4;
    /** Error code indicating that the SAML logout request is invalid. */
    public static final int SAML_LOGOUTREQUEST_INVALID = 5;
    /** Error code indicating that the SAML logout response is invalid. */
    public static final int SAML_LOGOUTRESPONSE_INVALID = 6;
    /** Error code indicating that single logout is not supported. */
    public static final int SAML_SINGLE_LOGOUT_NOT_SUPPORTED = 7;

    /** The error code identifying the specific severe condition. */
    private final int errorCode;

    /**
     * Constructs a new severe exception with the given message and error code.
     *
     * @param message the detail message describing the error
     * @param errorCode the error code identifying the severe condition
     */
    public SAMLSevereException(final String message, final int errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    /**
     * Constructs a new severe exception with the given message, error code, and cause.
     *
     * @param message the detail message describing the error
     * @param errorCode the error code identifying the severe condition
     * @param cause the underlying cause of this exception
     */
    public SAMLSevereException(final String message, final int errorCode, final Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    /**
     * Returns the error code identifying the specific severe condition.
     *
     * @return the error code
     */
    public int getErrorCode() {
        return errorCode;
    }

}
