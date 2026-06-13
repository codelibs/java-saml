package org.codelibs.saml2.core.exception;

/**
 * Exception thrown when an error related to SAML settings configuration occurs.
 * Each instance carries an error code identifying the specific settings problem.
 */
public class SettingsException extends SAMLException {

    /** Serialization version identifier. */
    private static final long serialVersionUID = 1L;

    /** Error code indicating that the settings syntax is invalid. */
    public static final int SETTINGS_INVALID_SYNTAX = 1;
    /** Error code indicating that the settings are invalid. */
    public static final int SETTINGS_INVALID = 2;
    /** Error code indicating that a certificate could not be found. */
    public static final int CERT_NOT_FOUND = 3;
    /** Error code indicating that a private key could not be found. */
    public static final int PRIVATE_KEY_NOT_FOUND = 4;
    /** Error code indicating that the public certificate file could not be found. */
    public static final int PUBLIC_CERT_FILE_NOT_FOUND = 5;
    /** Error code indicating that the private key file could not be found. */
    public static final int PRIVATE_KEY_FILE_NOT_FOUND = 6;

    /** The error code identifying the specific settings problem. */
    private final int errorCode;

    /**
     * Constructs a new settings exception with the given message and error code.
     *
     * @param message the detail message describing the error
     * @param errorCode the error code identifying the settings problem
     */
    public SettingsException(final String message, final int errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    /**
     * Returns the error code identifying the specific settings problem.
     *
     * @return the error code
     */
    public int getErrorCode() {
        return errorCode;
    }

}
