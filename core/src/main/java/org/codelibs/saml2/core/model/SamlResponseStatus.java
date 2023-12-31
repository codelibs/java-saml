package org.codelibs.saml2.core.model;

/**
 * SamlResponseStatus class of Java Toolkit.
 *
 * A class that stores the SAML response status info
 */
public class SamlResponseStatus {
    /**
     * Status code
     */
    private String statusCode;

    /**
     * Status code second level
     */
    private String subStatusCode;

    /**
     * Status Message
     */
    private String statusMessage;

    /**
     * Constructor
     *
     * @param statusCode
     *              String. Status code
     */
    public SamlResponseStatus(final String statusCode) {
        this.statusCode = statusCode;
    }

    /**
     * Constructor
     *
     * @param statusCode
     *              String. Status code
     * @param statusMessage
     *				String. Status message
     */
    public SamlResponseStatus(final String statusCode, final String statusMessage) {
        this.statusCode = statusCode;
        this.statusMessage = statusMessage;
    }

    /**
     * @return string the status code
     */
    public String getStatusCode() {
        return statusCode;
    }

    /**
     * Set the status code
     *
     * @param statusCode
     *              String. Status code
     */
    public void setStatusCode(final String statusCode) {
        this.statusCode = statusCode;
    }

    /**
     * @return string the second-level status code
     */
    public String getSubStatusCode() {
        return subStatusCode;
    }

    /**
     * Set the second-level status code
     *
     * @param subStatusCode
     *              String. second-level status code
     */
    public void setSubStatusCode(final String subStatusCode) {
        this.subStatusCode = subStatusCode;
    }

    /**
     * @return string the status message
     */
    public String getStatusMessage() {
        return statusMessage;
    }

    /**
     * Set the status message
     *
     * @param statusMessage
     *              String. Status message
     */
    public void setStatusMessage(final String statusMessage) {
        this.statusMessage = statusMessage;
    }

    /**
     * Compare the status code
     *
     * @param status
     *              String. Status code
     *
     * @return boolean checks the status code
     */
    public boolean is(final String status) {
        return statusCode != null && !statusCode.isEmpty() && statusCode.equals(status);
    }

}
