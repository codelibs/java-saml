package org.codelibs.saml2.core.settings;

import java.net.URL;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;
import org.codelibs.saml2.core.model.Contact;
import org.codelibs.saml2.core.model.Organization;
import org.codelibs.saml2.core.model.hsm.HSM;
import org.codelibs.saml2.core.util.Constants;
import org.codelibs.saml2.core.util.SchemaFactory;
import org.codelibs.saml2.core.util.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Saml2Settings class of Java Toolkit.
 *
 * A class that implements the settings handler
 */
public class Saml2Settings {
    /**
     * Private property to construct a logger for this class.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(Saml2Settings.class);

    // Toolkit settings
    private boolean strict = true;
    private boolean debug = false;

    // SP
    private String spEntityId = "";
    private URL spAssertionConsumerServiceUrl = null;
    private String spAssertionConsumerServiceBinding = Constants.BINDING_HTTP_POST;
    private URL spSingleLogoutServiceUrl = null;
    private String spSingleLogoutServiceBinding = Constants.BINDING_HTTP_REDIRECT;
    private String spNameIDFormat = Constants.NAMEID_UNSPECIFIED;
    private X509Certificate spX509cert = null;
    private X509Certificate spX509certNew = null;
    private PrivateKey spPrivateKey = null;
    private HSM hsm = null;

    // IdP
    private String idpEntityId = "";
    private URL idpSingleSignOnServiceUrl = null;
    private String idpSingleSignOnServiceBinding = Constants.BINDING_HTTP_REDIRECT;
    private URL idpSingleLogoutServiceUrl = null;
    private URL idpSingleLogoutServiceResponseUrl = null;
    private String idpSingleLogoutServiceBinding = Constants.BINDING_HTTP_REDIRECT;
    private X509Certificate idpx509cert = null;
    private List<X509Certificate> idpx509certMulti = null;
    private String idpCertFingerprint = null;
    private String idpCertFingerprintAlgorithm = "sha1";

    // Security
    private boolean nameIdEncrypted = false;
    private boolean authnRequestsSigned = false;
    private boolean logoutRequestSigned = false;
    private boolean logoutResponseSigned = false;
    private boolean wantMessagesSigned = false;
    private boolean wantAssertionsSigned = false;
    private boolean wantAssertionsEncrypted = false;
    private boolean wantNameId = true;
    private boolean wantNameIdEncrypted = false;
    private boolean signMetadata = false;
    private List<String> requestedAuthnContext = new ArrayList<>();
    private String requestedAuthnContextComparison = "exact";
    private boolean wantXMLValidation = true;
    private String signatureAlgorithm = Constants.RSA_SHA256;
    private String digestAlgorithm = Constants.SHA256;
    private boolean rejectUnsolicitedResponsesWithInResponseTo = false;
    private boolean allowRepeatAttributeName = false;
    private boolean rejectDeprecatedAlg = false;
    private String uniqueIDPrefix = null;
    private long clockDrift = Constants.ALOWED_CLOCK_DRIFT;

    // Compress
    private boolean compressRequest = true;
    private boolean compressResponse = true;

    // Parsing
    private boolean trimNameIds = false;
    private boolean trimAttributeValues = false;

    // Misc
    private List<Contact> contacts = new LinkedList<>();
    private Organization organization = null;

    private boolean spValidationOnly = false;

    /**
     * @return the strict setting value
     */
    public final boolean isStrict() {
        return strict;
    }

    /**
     * @return the spEntityId setting value
     */
    public final String getSpEntityId() {
        return spEntityId;
    }

    /**
     * @return the spAssertionConsumerServiceUrl
     */
    public final URL getSpAssertionConsumerServiceUrl() {
        return spAssertionConsumerServiceUrl;
    }

    /**
     * @return the spAssertionConsumerServiceBinding setting value
     */
    public final String getSpAssertionConsumerServiceBinding() {
        return spAssertionConsumerServiceBinding;
    }

    /**
     * @return the spSingleLogoutServiceUrl setting value
     */
    public final URL getSpSingleLogoutServiceUrl() {
        return spSingleLogoutServiceUrl;
    }

    /**
     * @return the spSingleLogoutServiceBinding setting value
     */
    public final String getSpSingleLogoutServiceBinding() {
        return spSingleLogoutServiceBinding;
    }

    /**
     * @return the spNameIDFormat setting value
     */
    public final String getSpNameIDFormat() {
        return spNameIDFormat;
    }

    /**
     * @return the allowRepeatAttributeName setting value
     */
    public boolean isAllowRepeatAttributeName() {
        return allowRepeatAttributeName;
    }

    /**
     * @return the rejectDeprecatedAlg setting value
     */
    public boolean getRejectDeprecatedAlg() {
        return rejectDeprecatedAlg;
    }

    /**
     * @return the spX509cert setting value
     */
    public final X509Certificate getSPcert() {
        return spX509cert;
    }

    /**
     * @return the spX509certNew setting value
     */
    public final X509Certificate getSPcertNew() {
        return spX509certNew;
    }

    /**
     * @return the spPrivateKey setting value
     */
    public final PrivateKey getSPkey() {
        return spPrivateKey;
    }

    /**
     * @return the idpEntityId setting value
     */
    public final String getIdpEntityId() {
        return idpEntityId;
    }

    /**
     * @return the idpSingleSignOnServiceUrl setting value
     */
    public final URL getIdpSingleSignOnServiceUrl() {
        return idpSingleSignOnServiceUrl;
    }

    /**
     * @return the idpSingleSignOnServiceBinding setting value
     */
    public final String getIdpSingleSignOnServiceBinding() {
        return idpSingleSignOnServiceBinding;
    }

    /**
     * @return the idpSingleLogoutServiceUrl setting value
     */
    public final URL getIdpSingleLogoutServiceUrl() {
        return idpSingleLogoutServiceUrl;
    }

    /**
     * @return the idpSingleLogoutServiceResponseUrl setting value
     */
    public final URL getIdpSingleLogoutServiceResponseUrl() {
        if (idpSingleLogoutServiceResponseUrl == null) {
            return getIdpSingleLogoutServiceUrl();
        }

        return idpSingleLogoutServiceResponseUrl;
    }

    /**
     * @return the idpSingleLogoutServiceBinding setting value
     */
    public final String getIdpSingleLogoutServiceBinding() {
        return idpSingleLogoutServiceBinding;
    }

    /**
     * @return the idpx509cert setting value
     */
    public final X509Certificate getIdpx509cert() {
        return idpx509cert;
    }

    /**
     * @return the idpCertFingerprint setting value
     * @deprecated Certificate fingerprint validation is vulnerable to collision attacks.
     *             Use full X.509 certificate validation via {@link #getIdpx509cert()} instead.
     */
    @Deprecated
    public final String getIdpCertFingerprint() {
        if (idpCertFingerprint != null) {
            LOGGER.warn("SECURITY WARNING: Using certificate fingerprint validation which is vulnerable to collision attacks. "
                    + "It is strongly recommended to use full X.509 certificate validation instead.");
        }
        return idpCertFingerprint;
    }

    /**
     * @return the idpCertFingerprintAlgorithm setting value
     * @deprecated Certificate fingerprint validation is vulnerable to collision attacks.
     *             Use full X.509 certificate validation via {@link #getIdpx509cert()} instead.
     */
    @Deprecated
    public final String getIdpCertFingerprintAlgorithm() {
        return idpCertFingerprintAlgorithm;
    }

    /**
     * @return the idpx509certMulti setting value
     */
    public List<X509Certificate> getIdpx509certMulti() {
        return idpx509certMulti;
    }

    /**
     * @return the nameIdEncrypted setting value
     */
    public boolean getNameIdEncrypted() {
        return nameIdEncrypted;
    }

    /**
     * @return the authnRequestsSigned setting value
     */
    public boolean getAuthnRequestsSigned() {
        return authnRequestsSigned;
    }

    /**
     * @return the logoutRequestSigned setting value
     */
    public boolean getLogoutRequestSigned() {
        return logoutRequestSigned;
    }

    /**
     * @return the logoutResponseSigned setting value
     */
    public boolean getLogoutResponseSigned() {
        return logoutResponseSigned;
    }

    /**
     * @return the wantMessagesSigned setting value
     */
    public boolean getWantMessagesSigned() {
        return wantMessagesSigned;
    }

    /**
     * @return the wantAssertionsSigned setting value
     */
    public boolean getWantAssertionsSigned() {
        return wantAssertionsSigned;
    }

    /**
     * @return the wantAssertionsEncrypted setting value
     */
    public boolean getWantAssertionsEncrypted() {
        return wantAssertionsEncrypted;
    }

    /**
     * @return the wantNameId setting value
     */
    public boolean getWantNameId() {
        return wantNameId;
    }

    /**
     * @return the wantNameIdEncrypted setting value
     */
    public boolean getWantNameIdEncrypted() {
        return wantNameIdEncrypted;
    }

    /**
     * @return the signMetadata setting value
     */
    public boolean getSignMetadata() {
        return signMetadata;
    }

    /**
     * @return the requestedAuthnContext setting value
     */
    public List<String> getRequestedAuthnContext() {
        return requestedAuthnContext;
    }

    /**
     * @return the requestedAuthnContextComparison setting value
     */
    public String getRequestedAuthnContextComparison() {
        return requestedAuthnContextComparison;
    }

    /**
     * @return the wantXMLValidation setting value
     */
    public boolean getWantXMLValidation() {
        return wantXMLValidation;
    }

    /**
     * @return the signatureAlgorithm setting value
     */
    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    /**
     * @return the digestAlgorithm setting value
     */
    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * @return SP Contact info
     */
    public List<Contact> getContacts() {
        return this.contacts;
    }

    /**
     * @return SP Organization info
     */
    public Organization getOrganization() {
        return this.organization;
    }

    /**
     * @return Unique ID prefix
     */
    public String getUniqueIDPrefix() {
        return this.uniqueIDPrefix;
    }

    /**
     * @return The HSM setting value.
     */
    public HSM getHsm() {
        return this.hsm;
    }

    /**
     * @return if the debug is active or not
     */
    public boolean isDebugActive() {
        return this.debug;
    }

    /**
     * @return the clock drift in seconds
     */
    public long getClockDrift() {
        return this.clockDrift;
    }

    /**
     * Set the clock drift value in seconds. This value is added/subtracted to current time
     * in time condition validations to account for clock synchronization differences.
     *
     * @param clockDrift the clock drift value in seconds to be set
     */
    public void setClockDrift(final long clockDrift) {
        this.clockDrift = clockDrift;
    }

    /**
     * Set the strict setting value
     *
     * @param strict
     *            the strict to be set
     */
    public void setStrict(final boolean strict) {
        this.strict = strict;
    }

    /**
     * Set the debug setting value
     *
     * @param debug
     *            the debug mode to be set
     */
    public void setDebug(final boolean debug) {
        this.debug = debug;
    }

    /**
     * Sets the HSM setting value.
     *
     * @param hsm The HSM object to be set.
     */
    public void setHsm(final HSM hsm) {
        this.hsm = hsm;
    }

    /**
     * Set the spEntityId setting value
     *
     * @param spEntityId
     *            the spEntityId value to be set
     */
    protected final void setSpEntityId(final String spEntityId) {
        this.spEntityId = spEntityId;
    }

    /**
     * Set the spAssertionConsumerServiceUrl setting value
     *
     * @param spAssertionConsumerServiceUrl
     *            the spAssertionConsumerServiceUrl value to be set
     */
    protected final void setSpAssertionConsumerServiceUrl(final URL spAssertionConsumerServiceUrl) {
        this.spAssertionConsumerServiceUrl = spAssertionConsumerServiceUrl;
    }

    /**
     * Set the spAssertionConsumerServiceBinding setting value
     *
     * @param spAssertionConsumerServiceBinding
     *            the spAssertionConsumerServiceBinding value to be set
     */
    protected final void setSpAssertionConsumerServiceBinding(final String spAssertionConsumerServiceBinding) {
        this.spAssertionConsumerServiceBinding = spAssertionConsumerServiceBinding;
    }

    /**
     * Set the spSingleLogoutServiceUrl setting value
     *
     * @param spSingleLogoutServiceUrl
     *            the spSingleLogoutServiceUrl value to be set
     */
    protected final void setSpSingleLogoutServiceUrl(final URL spSingleLogoutServiceUrl) {
        this.spSingleLogoutServiceUrl = spSingleLogoutServiceUrl;
    }

    /**
     * Set the spSingleLogoutServiceBinding setting value
     *
     * @param spSingleLogoutServiceBinding
     *            the spSingleLogoutServiceBinding value to be set
     */
    protected final void setSpSingleLogoutServiceBinding(final String spSingleLogoutServiceBinding) {
        this.spSingleLogoutServiceBinding = spSingleLogoutServiceBinding;
    }

    /**
     * Set the spNameIDFormat setting value
     *
     * @param spNameIDFormat
     *            the spNameIDFormat value to be set
     */
    protected final void setSpNameIDFormat(final String spNameIDFormat) {
        this.spNameIDFormat = spNameIDFormat;
    }

    /**
     * Set the allowRepeatAttributeName setting value
     *
     * @param allowRepeatAttributeName
     *        the allowRepeatAttributeName value to be set
     */
    public void setAllowRepeatAttributeName(final boolean allowRepeatAttributeName) {
        this.allowRepeatAttributeName = allowRepeatAttributeName;
    }

    /**
     * Set the rejectDeprecatedAlg setting value
     *
     * @param rejectDeprecatedAlg
     *        the rejectDeprecatedAlg value to be set
     */
    public void setRejectDeprecatedAlg(final boolean rejectDeprecatedAlg) {
        this.rejectDeprecatedAlg = rejectDeprecatedAlg;
    }

    /**
     * Set the spX509cert setting value provided as X509Certificate object
     *
     * @param spX509cert
     *            the spX509cert value to be set in X509Certificate format
     */
    protected final void setSpX509cert(final X509Certificate spX509cert) {
        this.spX509cert = spX509cert;
    }

    /**
     * Set the spX509certNew setting value provided as X509Certificate object
     *
     * @param spX509certNew
     *            the spX509certNew value to be set in X509Certificate format
     */
    protected final void setSpX509certNew(final X509Certificate spX509certNew) {
        this.spX509certNew = spX509certNew;
    }

    /**
     * Set the spPrivateKey setting value provided as a PrivateKey object
     *
     * @param spPrivateKey
     *            the spprivateKey value to be set in PrivateKey format
     */
    protected final void setSpPrivateKey(final PrivateKey spPrivateKey) {
        this.spPrivateKey = spPrivateKey;
    }

    /**
     * Set the uniqueIDPrefix setting value
     *
     * @param uniqueIDPrefix
     *            the Unique ID prefix used when generating Unique ID
     */
    protected final void setUniqueIDPrefix(final String uniqueIDPrefix) {
        this.uniqueIDPrefix = uniqueIDPrefix;
    }

    /**
     * Set the idpEntityId setting value
     *
     * @param idpEntityId
     *            the idpEntityId value to be set
     */
    protected final void setIdpEntityId(final String idpEntityId) {
        this.idpEntityId = idpEntityId;
    }

    /**
     * Set the idpSingleSignOnServiceUrl setting value
     *
     * @param idpSingleSignOnServiceUrl
     *            the idpSingleSignOnServiceUrl value to be set
     */
    protected final void setIdpSingleSignOnServiceUrl(final URL idpSingleSignOnServiceUrl) {
        this.idpSingleSignOnServiceUrl = idpSingleSignOnServiceUrl;
    }

    /**
     * Set the idpSingleSignOnServiceBinding setting value
     *
     * @param idpSingleSignOnServiceBinding
     *            the idpSingleSignOnServiceBinding value to be set
     */
    protected final void setIdpSingleSignOnServiceBinding(final String idpSingleSignOnServiceBinding) {
        this.idpSingleSignOnServiceBinding = idpSingleSignOnServiceBinding;
    }

    /**
     * Set the idpSingleLogoutServiceUrl setting value
     *
     * @param idpSingleLogoutServiceUrl
     *            the idpSingleLogoutServiceUrl value to be set
     */
    protected final void setIdpSingleLogoutServiceUrl(final URL idpSingleLogoutServiceUrl) {
        this.idpSingleLogoutServiceUrl = idpSingleLogoutServiceUrl;
    }

    /**
     * Set the idpSingleLogoutServiceUrl setting value
     *
     * @param idpSingleLogoutServiceResponseUrl
     *            the idpSingleLogoutServiceUrl value to be set
     */
    protected final void setIdpSingleLogoutServiceResponseUrl(final URL idpSingleLogoutServiceResponseUrl) {
        this.idpSingleLogoutServiceResponseUrl = idpSingleLogoutServiceResponseUrl;
    }

    /**
     * Set the idpSingleLogoutServiceBinding setting value
     *
     * @param idpSingleLogoutServiceBinding
     *            the idpSingleLogoutServiceBinding value to be set
     */
    protected final void setIdpSingleLogoutServiceBinding(final String idpSingleLogoutServiceBinding) {
        this.idpSingleLogoutServiceBinding = idpSingleLogoutServiceBinding;
    }

    /**
     * Set the idpX509cert setting value provided as a X509Certificate object
     *
     * @param idpX509cert
     *            the idpX509cert value to be set in X509Certificate format
     */
    protected final void setIdpx509cert(final X509Certificate idpX509cert) {
        this.idpx509cert = idpX509cert;
    }

    /**
     * Set the idpCertFingerprint setting value
     *
     * @param idpCertFingerprint
     *            the idpCertFingerprint value to be set
     * @deprecated Certificate fingerprint validation is vulnerable to collision attacks.
     *             Use full X.509 certificate validation via {@link #setIdpx509cert(X509Certificate)} instead.
     */
    @Deprecated
    protected final void setIdpCertFingerprint(final String idpCertFingerprint) {
        if (idpCertFingerprint != null) {
            LOGGER.warn("SECURITY WARNING: Setting certificate fingerprint for validation. "
                    + "Fingerprint validation is vulnerable to collision attacks. "
                    + "Use full X.509 certificate validation instead.");
        }
        this.idpCertFingerprint = idpCertFingerprint;
    }

    /**
     * Set the idpCertFingerprintAlgorithm setting value
     *
     * @param idpCertFingerprintAlgorithm
     *            the idpCertFingerprintAlgorithm value to be set.
     * @deprecated Certificate fingerprint validation is vulnerable to collision attacks.
     *             Use full X.509 certificate validation via {@link #setIdpx509cert(X509Certificate)} instead.
     */
    @Deprecated
    protected final void setIdpCertFingerprintAlgorithm(final String idpCertFingerprintAlgorithm) {
        this.idpCertFingerprintAlgorithm = idpCertFingerprintAlgorithm;
    }

    /**
     * Set the idpx509certMulti setting value
     *
     * @param idpx509certMulti the idpx509certMulti to set
     */
    public void setIdpx509certMulti(final List<X509Certificate> idpx509certMulti) {
        this.idpx509certMulti = idpx509certMulti;
    }

    /**
     * Set the nameIdEncrypted setting value
     *
     * @param nameIdEncrypted
     *            the nameIdEncrypted value to be set. Based on it the SP will encrypt the NameID or not
     */
    public void setNameIdEncrypted(final boolean nameIdEncrypted) {
        this.nameIdEncrypted = nameIdEncrypted;
    }

    /**
     * Set the authnRequestsSigned setting value
     *
     * @param authnRequestsSigned
     *            the authnRequestsSigned value to be set. Based on it the SP will sign Logout Request or not
     */
    public void setAuthnRequestsSigned(final boolean authnRequestsSigned) {
        this.authnRequestsSigned = authnRequestsSigned;
    }

    /**
     * Set the logoutRequestSigned setting value
     *
     * @param logoutRequestSigned
     *            the logoutRequestSigned value to be set. Based on it the SP will sign Logout Request or not
     */
    public void setLogoutRequestSigned(final boolean logoutRequestSigned) {
        this.logoutRequestSigned = logoutRequestSigned;
    }

    /**
     * Set the logoutResponseSigned setting value
     *
     * @param logoutResponseSigned
     *            the logoutResponseSigned value to be set. Based on it the SP will sign Logout Response or not
     */
    public void setLogoutResponseSigned(final boolean logoutResponseSigned) {
        this.logoutResponseSigned = logoutResponseSigned;
    }

    /**
     * Set the wantMessagesSigned setting value
     *
     * @param wantMessagesSigned
     *            the wantMessagesSigned value to be set. Based on it the SP expects the SAML Messages to be signed or not
     */
    public void setWantMessagesSigned(final boolean wantMessagesSigned) {
        this.wantMessagesSigned = wantMessagesSigned;
    }

    /**
     * Set the wantAssertionsSigned setting value
     *
     * @param wantAssertionsSigned
     *            the wantAssertionsSigned value to be set. Based on it the SP expects the SAML Assertions to be signed or not
     */
    public void setWantAssertionsSigned(final boolean wantAssertionsSigned) {
        this.wantAssertionsSigned = wantAssertionsSigned;
    }

    /**
     * Set the wantAssertionsEncrypted setting value
     *
     * @param wantAssertionsEncrypted
     *            the wantAssertionsEncrypted value to be set. Based on it the SP expects the SAML Assertions to be encrypted or not
     */
    public void setWantAssertionsEncrypted(final boolean wantAssertionsEncrypted) {
        this.wantAssertionsEncrypted = wantAssertionsEncrypted;
    }

    /**
     * Set the wantNameId setting value
     *
     * @param wantNameId
     *            the wantNameId value to be set. Based on it the SP expects a NameID
     */
    public void setWantNameId(final boolean wantNameId) {
        this.wantNameId = wantNameId;
    }

    /**
     * Set the wantNameIdEncrypted setting value
     *
     * @param wantNameIdEncrypted
     *            the wantNameIdEncrypted value to be set. Based on it the SP expects the NameID to be encrypted or not
     */
    public void setWantNameIdEncrypted(final boolean wantNameIdEncrypted) {
        this.wantNameIdEncrypted = wantNameIdEncrypted;
    }

    /**
     * Set the signMetadata setting value
     *
     * @param signMetadata
     *            the signMetadata value to be set. Based on it the SP will sign or not the metadata with the SP PrivateKey/Certificate
     */
    public void setSignMetadata(final boolean signMetadata) {
        this.signMetadata = signMetadata;
    }

    /**
     * Set the requestedAuthnContext setting value
     *
     * @param requestedAuthnContext
     *            the requestedAuthnContext value to be set on the AuthNRequest.
     */
    public void setRequestedAuthnContext(final List<String> requestedAuthnContext) {
        if (requestedAuthnContext != null) {
            this.requestedAuthnContext = requestedAuthnContext;
        }
    }

    /**
     * Set the requestedAuthnContextComparison setting value
     *
     * @param requestedAuthnContextComparison
     *            the requestedAuthnContextComparison value to be set.
     */
    public void setRequestedAuthnContextComparison(final String requestedAuthnContextComparison) {
        this.requestedAuthnContextComparison = requestedAuthnContextComparison;
    }

    /**
     * Set the wantXMLValidation setting value
     *
     * @param wantXMLValidation
     *            the wantXMLValidation value to be set. Based on it the SP will validate SAML messages against the XML scheme
     */
    public void setWantXMLValidation(final boolean wantXMLValidation) {
        this.wantXMLValidation = wantXMLValidation;
    }

    /**
     * Set the signatureAlgorithm setting value
     *
     * @param signatureAlgorithm
     *            the signatureAlgorithm value to be set.
     */
    public void setSignatureAlgorithm(final String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    /**
     * Set the digestAlgorithm setting value
     *
     * @param digestAlgorithm
     *            the digestAlgorithm value to be set.
     */
    public void setDigestAlgorithm(final String digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    /**
     * Controls if unsolicited Responses are rejected if they contain an InResponseTo value.
     *
     * If false using a validate method {@link org.codelibs.saml2.core.authn.SamlResponse#isValid(String)} with a null argument will
     * accept messages with any (or none) InResponseTo value.
     *
     * If true using these methods with a null argument will only accept messages with no InRespoonseTo value,
     * and reject messages where the value is set.
     *
     * In all cases using validate with a specified request ID will only accept responses that have the same
     * InResponseTo id set.
     *
     * @param rejectUnsolicitedResponsesWithInResponseTo whether to strictly check the InResponseTo attribute
     */
    public void setRejectUnsolicitedResponsesWithInResponseTo(final boolean rejectUnsolicitedResponsesWithInResponseTo) {
        this.rejectUnsolicitedResponsesWithInResponseTo = rejectUnsolicitedResponsesWithInResponseTo;
    }

    public boolean isRejectUnsolicitedResponsesWithInResponseTo() {
        return rejectUnsolicitedResponsesWithInResponseTo;
    }

    /**
     * Set the compressRequest setting value
     *
     * @param compressRequest
     *            the compressRequest value to be set.
     */
    public void setCompressRequest(final boolean compressRequest) {
        this.compressRequest = compressRequest;
    }

    /**
     * @return the compressRequest setting value
     */
    public boolean isCompressRequestEnabled() {
        return compressRequest;
    }

    /**
     * Set the compressResponse setting value
     *
     * @param compressResponse
     *            the compressResponse value to be set.
     */
    public void setCompressResponse(final boolean compressResponse) {
        this.compressResponse = compressResponse;
    }

    /**
     * @return the compressResponse setting value
     */
    public boolean isCompressResponseEnabled() {
        return compressResponse;
    }

    /**
     * Sets whether Name IDs in parsed SAML messages should be trimmed.
     * <p>
     * Default is <code>false</code>, that is Name IDs are kept intact, as the SAML
     * specification prescribes.
     *
     * @param trimNameIds
     *              set to <code>true</code> to trim parsed Name IDs, set to
     *              <code>false</code> to keep them intact
     */
    public void setTrimNameIds(final boolean trimNameIds) {
        this.trimNameIds = trimNameIds;
    }

    /**
     * Determines whether Name IDs should trimmed when extracting them from parsed
     * SAML messages.
     * <p>
     * Default is <code>false</code>, that is Name IDs are kept intact, as the SAML
     * specification prescribes.
     *
     * @return <code>true</code> if Name IDs should be trimmed, <code>false</code>
     *         otherwise
     */
    public boolean isTrimNameIds() {
        return trimNameIds;
    }

    /**
     * Sets whether attribute values in parsed SAML messages should be trimmed.
     * <p>
     * Default is <code>false</code>.
     *
     * @param trimAttributeValues
     *              set to <code>true</code> to trim parsed attribute values, set to
     *              <code>false</code> to keep them intact
     */
    public void setTrimAttributeValues(final boolean trimAttributeValues) {
        this.trimAttributeValues = trimAttributeValues;
    }

    /**
     * Determines whether attribute values should be trimmed when extracting them
     * from parsed SAML messages.
     * <p>
     * Default is <code>false</code>.
     *
     * @return <code>true</code> if attribute values should be trimmed,
     *         <code>false</code> otherwise
     */
    public boolean isTrimAttributeValues() {
        return trimAttributeValues;
    }

    /**
     * Set contacts info that will be listed on the Service Provider metadata
     *
     * @param contacts
     *            the contacts to set
     */
    protected final void setContacts(final List<Contact> contacts) {
        this.contacts = contacts;
    }

    /**
     * Set the organization info that will be published on the Service Provider metadata
     *
     * @param organization
     *            the organization to set
     */
    protected final void setOrganization(final Organization organization) {
        this.organization = organization;
    }

    /**
     * Checks the settings .
     *
     * @return errors found on the settings data
     */
    public List<String> checkSettings() {
        final List<String> errors = new ArrayList<>(this.checkSPSettings());
        if (!spValidationOnly) {
            errors.addAll(this.checkIdPSettings());
        }

        return errors;
    }

    /**
     * Checks the IdP settings .
     *
     * @return errors found on the IdP settings data
     */
    public List<String> checkIdPSettings() {
        final List<String> errors = new ArrayList<>();
        String errorMsg;

        if (!checkRequired(getIdpEntityId())) {
            errorMsg = "idp_entityId_not_found";
            errors.add(errorMsg);
            LOGGER.warn(errorMsg);
        }

        if (!checkRequired(this.getIdpSingleSignOnServiceUrl())) {
            errorMsg = "idp_sso_url_invalid";
            errors.add(errorMsg);
            LOGGER.warn(errorMsg);
        }

        if (!checkIdpx509certRequired() && !checkRequired(this.getIdpCertFingerprint())) {
            errorMsg = "idp_cert_or_fingerprint_not_found_and_required";
            errors.add(errorMsg);
            LOGGER.warn(errorMsg);
        }

        if (!checkIdpx509certRequired() && this.getNameIdEncrypted()) {
            errorMsg = "idp_cert_not_found_and_required";
            errors.add(errorMsg);
            LOGGER.warn(errorMsg);
        }

        return errors;
    }

    /**
     * Auxiliary method to check Idp certificate is configured.
     *
     * @return true if the Idp Certificate settings are valid
     */
    private boolean checkIdpx509certRequired() {
        if (this.getIdpx509cert() != null) {
            return true;
        }

        return this.getIdpx509certMulti() != null && !this.getIdpx509certMulti().isEmpty();
    }

    /**
     * Checks the SP settings .
     *
     * @return errors found on the SP settings data
     */
    public List<String> checkSPSettings() {
        final List<String> errors = new ArrayList<>();
        String errorMsg;

        if (!checkRequired(getSpEntityId())) {
            errorMsg = "sp_entityId_not_found";
            errors.add(errorMsg);
            LOGGER.warn(errorMsg);
        }

        if (!checkRequired(getSpAssertionConsumerServiceUrl())) {
            errorMsg = "sp_acs_not_found";
            errors.add(errorMsg);
            LOGGER.warn(errorMsg);
        }

        if (this.getHsm() == null && (this.getAuthnRequestsSigned() || this.getLogoutRequestSigned() || this.getLogoutResponseSigned()
                || this.getWantAssertionsEncrypted() || this.getWantNameIdEncrypted()) && !this.checkSPCerts()) {
            errorMsg = "sp_cert_not_found_and_required";
            errors.add(errorMsg);
            LOGGER.warn(errorMsg);
        }

        final List<Contact> contacts = this.getContacts();
        if (!contacts.isEmpty()) {
            final Set<String> validTypes = new HashSet<>();
            validTypes.add(Constants.CONTACT_TYPE_TECHNICAL);
            validTypes.add(Constants.CONTACT_TYPE_SUPPORT);
            validTypes.add(Constants.CONTACT_TYPE_ADMINISTRATIVE);
            validTypes.add(Constants.CONTACT_TYPE_BILLING);
            validTypes.add(Constants.CONTACT_TYPE_OTHER);
            for (final Contact contact : contacts) {
                if (!validTypes.contains(contact.getContactType())) {
                    errorMsg = "contact_type_invalid";
                    errors.add(errorMsg);
                    LOGGER.warn(errorMsg);
                }
                if ((contact.getEmailAddresses().isEmpty() || contact.getEmailAddresses().stream().allMatch(StringUtils::isEmpty))
                        && (contact.getTelephoneNumbers().isEmpty()
                                || contact.getTelephoneNumbers().stream().allMatch(StringUtils::isEmpty))
                        && StringUtils.isEmpty(contact.getCompany()) && StringUtils.isEmpty(contact.getGivenName())
                        && StringUtils.isEmpty(contact.getSurName())) {
                    errorMsg = "contact_not_enough_data";
                    errors.add(errorMsg);
                    LOGGER.warn(errorMsg);
                }
            }
        }

        final Organization org = this.getOrganization();
        if (org != null && (org.getOrgDisplayName().isEmpty() || org.getOrgName().isEmpty() || org.getOrgUrl().isEmpty())) {
            errorMsg = "organization_not_enough_data";
            errors.add(errorMsg);
            LOGGER.warn(errorMsg);
        }

        if (this.getHsm() != null && this.getSPkey() != null) {
            errorMsg = "use_either_hsm_or_private_key";
            errors.add(errorMsg);
            LOGGER.warn(errorMsg);
        }

        return errors;
    }

    /**
     * Checks the x509 certficate/private key SP settings .
     *
     * @return true if the SP settings are valid
     */
    public boolean checkSPCerts() {
        final X509Certificate cert = getSPcert();
        final PrivateKey key = getSPkey();

        return (cert != null && key != null);
    }

    /**
     * Auxiliary method to check required properties.
     *
     * @param value
     *            the current value of the property to be checked
     *
     *
     * @return true if the SP settings are valid
     */
    private boolean checkRequired(final Object value) {
        if ((value == null) || (value instanceof String && ((String) value).isEmpty())) {
            return false;
        }

        if (value instanceof List && ((List<?>) value).isEmpty()) {
            return false;
        }
        return true;
    }

    /**
     * Set the spValidationOnly value, used to check IdP data on checkSettings method
     *
     * @param spValidationOnly
     *            the spValidationOnly value to be set
     */
    public void setSPValidationOnly(final boolean spValidationOnly) {
        this.spValidationOnly = spValidationOnly;
    }

    /**
     * @return the spValidationOnly value
     */
    public boolean getSPValidationOnly() {
        return this.spValidationOnly;
    }

    /**
     * Gets the SP metadata. The XML representation.
     *
     * @return the SP metadata (xml)
     *
     */
    public String getSPMetadata() {
        final Metadata metadataObj = new Metadata(this);
        String metadataString = metadataObj.getMetadataString();

        // Check if must be signed
        final boolean signMetadata = this.getSignMetadata();
        if (signMetadata) {
            // Note: Currently only SP privateKey/certificate are supported for metadata signing.
            // Future enhancement: Support signing with custom key/certificate pairs for more flexible
            // key management scenarios (e.g., separate metadata signing keys, key rotation).
            // This would require adding new settings parameters and updating the Metadata.signMetadata API.
            try {
                metadataString = Metadata.signMetadata(metadataString, this.getSPkey(), this.getSPcert(), this.getSignatureAlgorithm(),
                        this.getDigestAlgorithm());
            } catch (final Exception e) {
                LOGGER.debug("Failed to get SP metadata.", e);
            }
        }

        return metadataString;
    }

    /**
     * Validates an XML SP Metadata.
     *
     * @param metadataString Metadata's XML that will be validate
     *
     * @return Array The list of found errors
     *
     */
    public static List<String> validateMetadata(String metadataString) {

        metadataString = metadataString.replace("<?xml version=\"1.0\"?>", "");

        final Document metadataDocument = Util.loadXML(metadataString);

        final List<String> errors = new ArrayList<>();

        if (!Util.validateXML(metadataDocument, SchemaFactory.SAML_SCHEMA_METADATA_2_0)) {
            errors.add("Invalid SAML Metadata. Not match the saml-schema-metadata-2.0.xsd");
        } else {
            final Element rootElement = metadataDocument.getDocumentElement();
            if (!"EntityDescriptor".equals(rootElement.getLocalName())) {
                errors.add("noEntityDescriptor_xml");
            } else if (rootElement.getElementsByTagNameNS(Constants.NS_MD, "SPSSODescriptor").getLength() != 1) {
                errors.add("onlySPSSODescriptor_allowed_xml");
            } else {
                String validUntil = null;
                String cacheDuration = null;

                if (rootElement.hasAttribute("cacheDuration")) {
                    cacheDuration = rootElement.getAttribute("cacheDuration");
                }

                if (rootElement.hasAttribute("validUntil")) {
                    validUntil = rootElement.getAttribute("validUntil");
                }

                final long expireTime = Util.getExpireTime(cacheDuration, validUntil);

                if (expireTime != 0 && Util.getCurrentTimeStamp() > expireTime) {
                    errors.add("expired_xml");
                }
            }
        }

        // Note: Metadata signature validation is not currently implemented.
        // Future enhancement: Add signature validation for SP metadata to ensure integrity.
        // Implementation considerations:
        // - Need to determine which certificate to use for validation (SP cert or dedicated metadata cert)
        // - Should validation be mandatory or optional based on configuration?
        // - Use Util.validateMetadataSign() or similar validation method
        // - Add appropriate error messages to the errors list if validation fails
        // Security recommendation: Metadata signatures should be validated when received from external sources.

        return errors;
    }
}
