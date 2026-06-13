package org.codelibs.saml2.core.exception;

/**
 * Exception thrown when SAML validation fails, carrying a specific error code.
 */
public class ValidationException extends SAMLException {

    /** Serial version UID. */
    private static final long serialVersionUID = 1L;

    /** Error code indicating an unsupported SAML version. */
    public static final int UNSUPPORTED_SAML_VERSION = 0;
    /** Error code indicating a missing ID. */
    public static final int MISSING_ID = 1;
    /** Error code indicating a wrong number of assertions. */
    public static final int WRONG_NUMBER_OF_ASSERTIONS = 2;
    /** Error code indicating a missing status element. */
    public static final int MISSING_STATUS = 3;
    /** Error code indicating a missing status code. */
    public static final int MISSING_STATUS_CODE = 4;
    /** Error code indicating the status code is not success. */
    public static final int STATUS_CODE_IS_NOT_SUCCESS = 5;
    /** Error code indicating a wrong signed element. */
    public static final int WRONG_SIGNED_ELEMENT = 6;
    /** Error code indicating the ID was not found in the signed element. */
    public static final int ID_NOT_FOUND_IN_SIGNED_ELEMENT = 7;
    /** Error code indicating a duplicated ID in the signed elements. */
    public static final int DUPLICATED_ID_IN_SIGNED_ELEMENTS = 8;
    /** Error code indicating an invalid signed element. */
    public static final int INVALID_SIGNED_ELEMENT = 9;
    /** Error code indicating a duplicated reference in the signed elements. */
    public static final int DUPLICATED_REFERENCE_IN_SIGNED_ELEMENTS = 10;
    /** Error code indicating unexpected signed elements. */
    public static final int UNEXPECTED_SIGNED_ELEMENTS = 11;
    /** Error code indicating a wrong number of signatures in the response. */
    public static final int WRONG_NUMBER_OF_SIGNATURES_IN_RESPONSE = 12;
    /** Error code indicating a wrong number of signatures in the assertion. */
    public static final int WRONG_NUMBER_OF_SIGNATURES_IN_ASSERTION = 13;
    /** Error code indicating an invalid XML format. */
    public static final int INVALID_XML_FORMAT = 14;
    /** Error code indicating a wrong InResponseTo value. */
    public static final int WRONG_INRESPONSETO = 15;
    /** Error code indicating no encrypted assertion was found. */
    public static final int NO_ENCRYPTED_ASSERTION = 16;
    /** Error code indicating no encrypted NameID was found. */
    public static final int NO_ENCRYPTED_NAMEID = 17;
    /** Error code indicating missing conditions. */
    public static final int MISSING_CONDITIONS = 18;
    /** Error code indicating the assertion is not yet valid (too early). */
    public static final int ASSERTION_TOO_EARLY = 19;
    /** Error code indicating the assertion has expired. */
    public static final int ASSERTION_EXPIRED = 20;
    /** Error code indicating a wrong number of authentication statements. */
    public static final int WRONG_NUMBER_OF_AUTHSTATEMENTS = 21;
    /** Error code indicating no attribute statement was found. */
    public static final int NO_ATTRIBUTESTATEMENT = 22;
    /** Error code indicating encrypted attributes were found. */
    public static final int ENCRYPTED_ATTRIBUTES = 23;
    /** Error code indicating a wrong destination. */
    public static final int WRONG_DESTINATION = 24;
    /** Error code indicating an empty destination. */
    public static final int EMPTY_DESTINATION = 25;
    /** Error code indicating a wrong audience. */
    public static final int WRONG_AUDIENCE = 26;
    /** Error code indicating multiple issuers in the response. */
    public static final int ISSUER_MULTIPLE_IN_RESPONSE = 27;
    /** Error code indicating the issuer was not found in the assertion. */
    public static final int ISSUER_NOT_FOUND_IN_ASSERTION = 28;
    /** Error code indicating a wrong issuer. */
    public static final int WRONG_ISSUER = 29;
    /** Error code indicating the session has expired. */
    public static final int SESSION_EXPIRED = 30;
    /** Error code indicating a wrong subject confirmation. */
    public static final int WRONG_SUBJECTCONFIRMATION = 31;
    /** Error code indicating no signed message was found. */
    public static final int NO_SIGNED_MESSAGE = 32;
    /** Error code indicating no signed assertion was found. */
    public static final int NO_SIGNED_ASSERTION = 33;
    /** Error code indicating no signature was found. */
    public static final int NO_SIGNATURE_FOUND = 34;
    /** Error code indicating KeyInfo was not found in the encrypted data. */
    public static final int KEYINFO_NOT_FOUND_IN_ENCRYPTED_DATA = 35;
    /** Error code indicating a children node was not found in KeyInfo. */
    public static final int CHILDREN_NODE_NOT_FOUND_IN_KEYINFO = 36;
    /** Error code indicating an unsupported retrieval method. */
    public static final int UNSUPPORTED_RETRIEVAL_METHOD = 37;
    /** Error code indicating no NameID was found. */
    public static final int NO_NAMEID = 38;
    /** Error code indicating an empty NameID. */
    public static final int EMPTY_NAMEID = 39;
    /** Error code indicating a mismatch in the SPNameQualifier of the NameID. */
    public static final int SP_NAME_QUALIFIER_NAME_MISMATCH = 40;
    /** Error code indicating a duplicated attribute name was found. */
    public static final int DUPLICATED_ATTRIBUTE_NAME_FOUND = 41;
    /** Error code indicating an invalid signature. */
    public static final int INVALID_SIGNATURE = 42;
    /** Error code indicating a wrong number of signatures. */
    public static final int WRONG_NUMBER_OF_SIGNATURES = 43;
    /** Error code indicating the response has expired. */
    public static final int RESPONSE_EXPIRED = 44;
    /** Error code indicating an unexpected reference. */
    public static final int UNEXPECTED_REFERENCE = 45;
    /** Error code indicating the operation is not supported. */
    public static final int NOT_SUPPORTED = 46;
    /** Error code indicating a key algorithm error. */
    public static final int KEY_ALGORITHM_ERROR = 47;
    /** Error code indicating a missing encrypted element. */
    public static final int MISSING_ENCRYPTED_ELEMENT = 48;
    /** Error code indicating an invalid IssueInstant format. */
    public static final int INVALID_ISSUE_INSTANT_FORMAT = 49;

    /** The error code associated with this validation failure. */
    private final int errorCode;

    /**
     * Constructs a new {@code ValidationException} with the given message and error code.
     *
     * @param message the detail message
     * @param errorCode the error code identifying the validation failure
     */
    public ValidationException(final String message, final int errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    /**
     * Returns the error code associated with this validation failure.
     *
     * @return the error code
     */
    public int getErrorCode() {
        return errorCode;
    }

}
