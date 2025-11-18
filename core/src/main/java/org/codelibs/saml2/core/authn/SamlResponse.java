package org.codelibs.saml2.core.authn;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.apache.commons.lang3.StringUtils;
import org.codelibs.saml2.core.exception.SAMLException;
import org.codelibs.saml2.core.exception.SettingsException;
import org.codelibs.saml2.core.exception.ValidationException;
import org.codelibs.saml2.core.exception.XMLParsingException;
import org.codelibs.saml2.core.http.HttpRequest;
import org.codelibs.saml2.core.model.SamlResponseStatus;
import org.codelibs.saml2.core.model.SubjectConfirmationIssue;
import org.codelibs.saml2.core.model.hsm.HSM;
import org.codelibs.saml2.core.settings.Saml2Settings;
import org.codelibs.saml2.core.util.Constants;
import org.codelibs.saml2.core.util.SchemaFactory;
import org.codelibs.saml2.core.util.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * SamlResponse class of Java Toolkit.
 *
 * A class that implements SAML 2 Authentication Response parser/validator
 */
public class SamlResponse {
    /**
     * Private property to construct a logger for this class.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(SamlResponse.class);

    /**
     * Settings data.
     */
    private final Saml2Settings settings;

    /**
     * The decoded, unprocessed XML response provided to the constructor.
     */
    private String samlResponseString;

    /**
     * A DOMDocument object loaded from the SAML Response.
     */
    private Document samlResponseDocument;

    /**
     * A DOMDocument object loaded from the SAML Response (Decrypted).
     */
    private Document decryptedDocument;

    /**
     * NameID Data
     */
    private Map<String, String> nameIdData = null;

    /**
     * URL of the current host + current view
     */
    private String currentUrl;

    /**
     * Mark if the response contains an encrypted assertion.
     */
    private Boolean encrypted = false;

    /**
     * After validation, if it fails this property has the cause of the problem
     */
    private Exception validationException;

    /**
     * The respone status code and messages
     */
    private SamlResponseStatus responseStatus;

    /**
     * Constructor to have a Response object fully built and ready to validate the saml response.
     *
     * @param settings
     *              Saml2Settings object. Setting data
     * @param currentUrl
     *              URL of the current host + current view
     *
     * @param samlResponse
     *              A string containting the base64 encoded response from the IdP
     *
     */
    public SamlResponse(final Saml2Settings settings, final String currentUrl, final String samlResponse) {
        this.settings = settings;
        this.currentUrl = currentUrl;
        loadXmlFromBase64(samlResponse);
    }

    /**
     * Constructor to have a Response object fully built and ready to validate the saml response.
     *
     * @param settings
     *              Saml2Settings object. Setting data
     * @param request
     *				the HttpRequest object to be processed (Contains GET and POST parameters, request URL, ...).
     *
     */
    public SamlResponse(final Saml2Settings settings, final HttpRequest request) {
        this(settings, request.getRequestURL(), request.getParameter("SAMLResponse"));
    }

    /**
     * Load a XML base64encoded SAMLResponse
     *
     * @param responseStr
     *              Saml2Settings object. Setting data
     *
     */
    public void loadXmlFromBase64(final String responseStr) {
        try {
            samlResponseString = new String(Util.base64decoder(responseStr), "UTF-8");
            samlResponseDocument = Util.loadXML(samlResponseString);

            if (samlResponseDocument == null) {
                throw new ValidationException("SAML Response could not be processed", ValidationException.INVALID_XML_FORMAT);
            }

            final NodeList encryptedAssertionNodes = samlResponseDocument.getElementsByTagNameNS(Constants.NS_SAML, "EncryptedAssertion");

            if (encryptedAssertionNodes.getLength() != 0) {
                decryptedDocument = Util.copyDocument(samlResponseDocument);
                encrypted = true;
                decryptedDocument = this.decryptAssertion(decryptedDocument);
            }
        } catch (SAMLException e) {
            throw e;
        } catch (IOException e) {
            throw new XMLParsingException("Failed to load XML data.", e);
        }
    }

    /**
     * Determines if the SAML Response is valid using the certificate.
     *
     * @param requestId The ID of the AuthNRequest sent by this SP to the IdP
     *
     * @return if the response is valid or not
     */
    public boolean isValid(final String requestId) {
        validationException = null;

        try {
            if (samlResponseDocument == null) {
                throw new Exception("SAML Response is not loaded");
            }

            if (this.currentUrl == null || this.currentUrl.isEmpty()) {
                throw new Exception("The URL of the current host was not established");
            }

            final Element rootElement = samlResponseDocument.getDocumentElement();
            rootElement.normalize();

            // Check SAML version on the response
            if (!"2.0".equals(rootElement.getAttribute("Version"))) {
                throw new ValidationException("Unsupported SAML Version on Response.", ValidationException.UNSUPPORTED_SAML_VERSION);
            }

            // Check ID in the response
            if (!rootElement.hasAttribute("ID")) {
                throw new ValidationException("Missing ID attribute on SAML Response.", ValidationException.MISSING_ID);
            }

            this.checkStatus();

            if (!this.validateNumAssertions()) {
                throw new ValidationException("SAML Response must contain 1 Assertion.", ValidationException.WRONG_NUMBER_OF_ASSERTIONS);
            }

            final List<String> signedElements = processSignedElements();

            final String responseTag = "{" + Constants.NS_SAMLP + "}Response";
            final String assertionTag = "{" + Constants.NS_SAML + "}Assertion";

            final boolean hasSignedResponse = signedElements.contains(responseTag);
            final boolean hasSignedAssertion = signedElements.contains(assertionTag);

            if (settings.isStrict()) {
                if (settings.getWantXMLValidation()) {
                    if (!Util.validateXML(samlResponseDocument, SchemaFactory.SAML_SCHEMA_PROTOCOL_2_0)) {
                        throw new ValidationException("Invalid SAML Response. Not match the saml-schema-protocol-2.0.xsd",
                                ValidationException.INVALID_XML_FORMAT);
                    }

                    // If encrypted, check also the decrypted document
                    if (encrypted && !Util.validateXML(decryptedDocument, SchemaFactory.SAML_SCHEMA_PROTOCOL_2_0)) {
                        throw new ValidationException("Invalid decrypted SAML Response. Not match the saml-schema-protocol-2.0.xsd",
                                ValidationException.INVALID_XML_FORMAT);
                    }
                }

                final String responseInResponseTo =
                        rootElement.hasAttribute("InResponseTo") ? rootElement.getAttribute("InResponseTo") : null;
                if (requestId == null && responseInResponseTo != null && settings.isRejectUnsolicitedResponsesWithInResponseTo()) {
                    throw new ValidationException(
                            "The Response has an InResponseTo attribute: " + responseInResponseTo + " while no InResponseTo was expected",
                            ValidationException.WRONG_INRESPONSETO);
                }

                // Check if the InResponseTo of the Response matches the ID of the AuthNRequest (requestId) if provided
                if (requestId != null && !Objects.equals(responseInResponseTo, requestId)) {
                    throw new ValidationException(
                            "The InResponseTo of the Response: " + responseInResponseTo
                                    + ", does not match the ID of the AuthNRequest sent by the SP: " + requestId,
                            ValidationException.WRONG_INRESPONSETO);
                }

                // Check SAML version on the assertion
                final NodeList assertions = queryAssertion("");
                final Node versionAttribute = assertions.item(0).getAttributes().getNamedItem("Version");
                if (versionAttribute == null || !"2.0".equals(versionAttribute.getNodeValue())) {
                    throw new ValidationException("Unsupported SAML Version on Assertion.", ValidationException.UNSUPPORTED_SAML_VERSION);
                }

                if (!this.encrypted && settings.getWantAssertionsEncrypted()) {
                    throw new ValidationException("The assertion of the Response is not encrypted and the SP requires it",
                            ValidationException.NO_ENCRYPTED_ASSERTION);
                }

                if (settings.getWantNameIdEncrypted()) {
                    final NodeList encryptedNameIdNodes = this.queryAssertion("/saml:Subject/saml:EncryptedID/xenc:EncryptedData");
                    if (encryptedNameIdNodes.getLength() == 0) {
                        throw new ValidationException("The NameID of the Response is not encrypted and the SP requires it",
                                ValidationException.NO_ENCRYPTED_NAMEID);
                    }
                }

                // Validate Conditions element exists
                if (!this.checkOneCondition()) {
                    throw new ValidationException("The Assertion must include a Conditions element",
                            ValidationException.MISSING_CONDITIONS);
                }

                // Validate Assertion timestamps
                if (!this.validateTimestamps()) {
                    throw new Exception("Timing issues (please check your clock settings)");
                }

                // Validate AuthnStatement element exists and is unique
                if (!this.checkOneAuthnStatement()) {
                    throw new ValidationException("The Assertion must include an AuthnStatement element",
                            ValidationException.WRONG_NUMBER_OF_AUTHSTATEMENTS);
                }

                // EncryptedAttributes are not supported
                final NodeList encryptedAttributeNodes = this.queryAssertion("/saml:AttributeStatement/saml:EncryptedAttribute");
                if (encryptedAttributeNodes.getLength() > 0) {
                    throw new ValidationException("There is an EncryptedAttribute in the Response and this SP does not support them",
                            ValidationException.ENCRYPTED_ATTRIBUTES);
                }

                // Check destination
                validateDestination(rootElement);

                // Check Audiences
                validateAudiences();

                // Check the issuers
                final List<String> issuers = this.getIssuers();
                for (final String issuer : issuers) {
                    if (issuer.isEmpty() || !issuer.equals(settings.getIdpEntityId())) {
                        throw new ValidationException(String.format("Invalid issuer in the Assertion/Response. Was '%s', but expected '%s'",
                                issuer, settings.getIdpEntityId()), ValidationException.WRONG_ISSUER);
                    }
                }

                // Check the session Expiration
                Instant sessionExpiration = this.getSessionNotOnOrAfter();
                if (sessionExpiration != null) {
                    sessionExpiration = ChronoUnit.SECONDS.addTo(sessionExpiration, settings.getClockDrift());
                    if (Util.isEqualNow(sessionExpiration) || Util.isBeforeNow(sessionExpiration)) {
                        throw new ValidationException(
                                "The attributes have expired, based on the SessionNotOnOrAfter of the AttributeStatement of this Response",
                                ValidationException.SESSION_EXPIRED);
                    }
                }

                validateSubjectConfirmation(responseInResponseTo);

                if (settings.getWantAssertionsSigned() && !hasSignedAssertion) {
                    throw new ValidationException("The Assertion of the Response is not signed and the SP requires it",
                            ValidationException.NO_SIGNED_ASSERTION);
                }

                if (settings.getWantMessagesSigned() && !hasSignedResponse) {
                    throw new ValidationException("The Message of the Response is not signed and the SP requires it",
                            ValidationException.NO_SIGNED_MESSAGE);
                }
            }

            if (signedElements.isEmpty() || (!hasSignedAssertion && !hasSignedResponse)) {
                throw new ValidationException("No Signature found. SAML Response rejected", ValidationException.NO_SIGNATURE_FOUND);
            }
            final X509Certificate cert = settings.getIdpx509cert();
            final List<X509Certificate> certList = new ArrayList<>();
            final List<X509Certificate> multipleCertList = settings.getIdpx509certMulti();

            if (multipleCertList != null && !multipleCertList.isEmpty()) {
                certList.addAll(multipleCertList);
            }

            if (cert != null && !certList.contains(cert)) {
                certList.add(0, cert);
            }

            final String fingerprint = settings.getIdpCertFingerprint();
            final String alg = settings.getIdpCertFingerprintAlgorithm();

            final Boolean rejectDeprecatedAlg = settings.getRejectDeprecatedAlg();

            if (hasSignedResponse && !Util.validateSign(samlResponseDocument, certList, fingerprint, alg, Util.RESPONSE_SIGNATURE_XPATH,
                    rejectDeprecatedAlg)) {
                throw new ValidationException("Signature validation failed. SAML Response rejected", ValidationException.INVALID_SIGNATURE);
            }

            final Document documentToCheckAssertion = encrypted ? decryptedDocument : samlResponseDocument;
            if (hasSignedAssertion && !Util.validateSign(documentToCheckAssertion, certList, fingerprint, alg,
                    Util.ASSERTION_SIGNATURE_XPATH, rejectDeprecatedAlg)) {
                throw new ValidationException("Signature validation failed. SAML Response rejected", ValidationException.INVALID_SIGNATURE);
            }

            LOGGER.debug("SAMLResponse validated --> {}", samlResponseString);
            return true;
        } catch (final Exception e) {
            validationException = e;
            LOGGER.debug("SAMLResponse invalid --> {}", samlResponseString);
            LOGGER.warn(validationException.getMessage());
            return false;
        }
    }

    /**
     * Check SubjectConfirmation, at least one SubjectConfirmation must be valid
     *
     * @param responseInResponseTo
     *     The InResponseTo value of the SAML Response
     *
     */
    private void validateSubjectConfirmation(final String responseInResponseTo) {
        final List<SubjectConfirmationIssue> validationIssues = new ArrayList<>();
        boolean validSubjectConfirmation = false;
        final NodeList subjectConfirmationNodes = this.queryAssertion("/saml:Subject/saml:SubjectConfirmation");
        for (int i = 0; i < subjectConfirmationNodes.getLength(); i++) {
            final Node scn = subjectConfirmationNodes.item(i);

            final Node method = scn.getAttributes().getNamedItem("Method");
            if (method != null && !Constants.CM_BEARER.equals(method.getNodeValue())) {
                continue;
            }

            final NodeList subjectConfirmationDataNodes = scn.getChildNodes();
            for (int c = 0; c < subjectConfirmationDataNodes.getLength(); c++) {
                if (subjectConfirmationDataNodes.item(c).getLocalName() != null
                        && "SubjectConfirmationData".equals(subjectConfirmationDataNodes.item(c).getLocalName())) {

                    final Node recipient = subjectConfirmationDataNodes.item(c).getAttributes().getNamedItem("Recipient");
                    final SubjectConfirmationIssue issue = validateRecipient(recipient, i);
                    if (issue != null) {
                        validationIssues.add(issue);
                        continue;
                    }

                    final Node inResponseTo = subjectConfirmationDataNodes.item(c).getAttributes().getNamedItem("InResponseTo");
                    if (inResponseTo == null && responseInResponseTo != null
                            || inResponseTo != null && !inResponseTo.getNodeValue().equals(responseInResponseTo)) {
                        validationIssues.add(new SubjectConfirmationIssue(i, "SubjectConfirmationData has an invalid InResponseTo value"));
                        continue;
                    }

                    final Node notOnOrAfter = subjectConfirmationDataNodes.item(c).getAttributes().getNamedItem("NotOnOrAfter");
                    if (notOnOrAfter == null) {
                        validationIssues
                                .add(new SubjectConfirmationIssue(i, "SubjectConfirmationData doesn't contain a NotOnOrAfter attribute"));
                        continue;
                    }

                    Instant noa = Util.parseDateTime(notOnOrAfter.getNodeValue());
                    noa = ChronoUnit.SECONDS.addTo(noa, settings.getClockDrift());
                    if (Util.isEqualNow(noa) || Util.isBeforeNow(noa)) {
                        validationIssues.add(new SubjectConfirmationIssue(i, "SubjectConfirmationData is no longer valid"));
                        continue;
                    }

                    final Node notBefore = subjectConfirmationDataNodes.item(c).getAttributes().getNamedItem("NotBefore");
                    if (notBefore != null) {
                        Instant nb = Util.parseDateTime(notBefore.getNodeValue());
                        nb = ChronoUnit.SECONDS.addTo(nb, settings.getClockDrift() * -1);
                        if (Util.isAfterNow(nb)) {
                            validationIssues.add(new SubjectConfirmationIssue(i, "SubjectConfirmationData is not yet valid"));
                            continue;
                        }
                    }
                    validSubjectConfirmation = true;
                }
            }
        }

        if (!validSubjectConfirmation) {
            throw new ValidationException(SubjectConfirmationIssue.prettyPrintIssues(validationIssues),
                    ValidationException.WRONG_SUBJECTCONFIRMATION);
        }
    }

    /**
     * Determines if the SAML Response is valid using the certificate.
     *
     * @return if the response is valid or not
     */
    public boolean isValid() {
        return isValid(null);
    }

    /**
     * Gets the NameID provided from the SAML Response Document.
     *
     * @return the Name ID Data (Value, Format, NameQualifier, SPNameQualifier)
     *
     */
    public Map<String, String> getNameIdData() {
        if (this.nameIdData != null) {
            return this.nameIdData;
        }
        try {
            final Map<String, String> nameIdData = new HashMap<>();

            final NodeList encryptedIDNodes = this.queryAssertion("/saml:Subject/saml:EncryptedID");
            NodeList nameIdNodes;
            Element nameIdElem;
            if (encryptedIDNodes.getLength() == 1) {
                final NodeList encryptedDataNodes = this.queryAssertion("/saml:Subject/saml:EncryptedID/xenc:EncryptedData");
                if (encryptedDataNodes.getLength() == 1) {
                    final Element encryptedData = (Element) encryptedDataNodes.item(0);
                    final PrivateKey key = settings.getSPkey();
                    if (key == null) {
                        throw new SettingsException("Key is required in order to decrypt the NameID",
                                SettingsException.PRIVATE_KEY_NOT_FOUND);
                    }

                    Util.decryptElement(encryptedData, key);
                }
                nameIdNodes = this.queryAssertion("/saml:Subject/saml:EncryptedID/saml:NameID|/saml:Subject/saml:NameID");

                if (nameIdNodes == null || nameIdNodes.getLength() == 0) {
                    throw new SAMLException("Not able to decrypt the EncryptedID and get a NameID");
                }
            } else {
                nameIdNodes = this.queryAssertion("/saml:Subject/saml:NameID");
            }

            if (nameIdNodes != null && nameIdNodes.getLength() == 1) {
                nameIdElem = (Element) nameIdNodes.item(0);

                if (nameIdElem != null) {
                    String value = nameIdElem.getTextContent();
                    if (value != null && settings.isTrimNameIds()) {
                        value = value.trim();
                    }
                    if (settings.isStrict() && StringUtils.isEmpty(value)) {
                        throw new ValidationException("An empty NameID value found", ValidationException.EMPTY_NAMEID);
                    }

                    nameIdData.put("Value", value);

                    if (nameIdElem.hasAttribute("Format")) {
                        nameIdData.put("Format", nameIdElem.getAttribute("Format"));
                    }
                    if (nameIdElem.hasAttribute("SPNameQualifier")) {
                        final String spNameQualifier = nameIdElem.getAttribute("SPNameQualifier");
                        validateSpNameQualifier(spNameQualifier);
                        nameIdData.put("SPNameQualifier", spNameQualifier);
                    }
                    if (nameIdElem.hasAttribute("NameQualifier")) {
                        nameIdData.put("NameQualifier", nameIdElem.getAttribute("NameQualifier"));
                    }
                }
            } else if (settings.getWantNameId()) {
                throw new ValidationException("No name id found in Document.", ValidationException.NO_NAMEID);
            }
            this.nameIdData = nameIdData;
            return nameIdData;
        } catch (SAMLException e) {
            throw e;
        } catch (DOMException e) {
            throw new XMLParsingException("Failed to get NameID.", e);
        }
    }

    /**
     * Gets the NameID value provided from the SAML Response String.
     *
     * @return string Name ID Value
     *
     */
    public String getNameId() {
        final Map<String, String> nameIdData = getNameIdData();
        String nameID = null;
        if (!nameIdData.isEmpty()) {
            LOGGER.debug("SAMLResponse has NameID --> {}", nameIdData.get("Value"));
            nameID = nameIdData.get("Value");
        }
        return nameID;
    }

    /**
     * Gets the NameID Format provided from the SAML Response String.
     *
     * @return string NameID Format
     *
     */
    public String getNameIdFormat() {
        final Map<String, String> nameIdData = getNameIdData();
        String nameidFormat = null;
        if (!nameIdData.isEmpty() && nameIdData.containsKey("Format")) {
            LOGGER.debug("SAMLResponse has NameID Format --> {}", nameIdData.get("Format"));
            nameidFormat = nameIdData.get("Format");
        }
        return nameidFormat;
    }

    /**
     * Gets the NameID NameQualifier provided from the SAML Response String.
     *
     * @return string NameQualifier
     *
     */
    public String getNameIdNameQualifier() {
        final Map<String, String> nameIdData = getNameIdData();
        String nameQualifier = null;
        if (!nameIdData.isEmpty() && nameIdData.containsKey("NameQualifier")) {
            LOGGER.debug("SAMLResponse has NameID NameQualifier --> " + nameIdData.get("NameQualifier"));
            nameQualifier = nameIdData.get("NameQualifier");
        }
        return nameQualifier;
    }

    /**
     * Gets the NameID SP NameQualifier provided from the SAML Response String.
     *
     * @return string SP NameQualifier
     *
     */
    public String getNameIdSPNameQualifier() {
        final Map<String, String> nameIdData = getNameIdData();
        String spNameQualifier = null;
        if (!nameIdData.isEmpty() && nameIdData.containsKey("SPNameQualifier")) {
            LOGGER.debug("SAMLResponse has NameID NameQualifier --> " + nameIdData.get("SPNameQualifier"));
            spNameQualifier = nameIdData.get("SPNameQualifier");
        }
        return spNameQualifier;
    }

    /**
     * Gets the Attributes from the AttributeStatement element.
     *
     * @return the attributes of the SAML Assertion
     *
     *
     */
    public Map<String, List<String>> getAttributes() {
        final Map<String, List<String>> attributes = new LinkedHashMap<>();

        final NodeList nodes = this.queryAssertion("/saml:AttributeStatement/saml:Attribute");

        if (nodes.getLength() != 0) {
            for (int i = 0; i < nodes.getLength(); i++) {
                final NamedNodeMap attrName = nodes.item(i).getAttributes();
                final String attName = attrName.getNamedItem("Name").getNodeValue();
                if (attributes.containsKey(attName) && !settings.isAllowRepeatAttributeName()) {
                    throw new ValidationException("Found an Attribute element with duplicated Name",
                            ValidationException.DUPLICATED_ATTRIBUTE_NAME_FOUND);
                }

                final NodeList childrens = nodes.item(i).getChildNodes();

                List<String> attrValues = null;
                if (attributes.containsKey(attName) && settings.isAllowRepeatAttributeName()) {
                    attrValues = attributes.get(attName);
                } else {
                    attrValues = new ArrayList<>();
                }
                for (int j = 0; j < childrens.getLength(); j++) {
                    if ("AttributeValue".equals(childrens.item(j).getLocalName())) {
                        String attrValue = childrens.item(j).getTextContent();
                        if (attrValue != null && settings.isTrimAttributeValues()) {
                            attrValue = attrValue.trim();
                        }
                        attrValues.add(attrValue);
                    }
                }

                attributes.put(attName, attrValues);
            }
            LOGGER.debug("SAMLResponse has attributes: {}", attributes.toString());
        } else {
            LOGGER.debug("SAMLResponse has no attributes");
        }
        return attributes;
    }

    /**
     * Returns the ResponseStatus object
     *
     * @return
     */
    public SamlResponseStatus getResponseStatus() {
        return this.responseStatus;
    }

    /**
     * Checks the Status
     *
     * If status is not success
     */
    public void checkStatus() {
        this.responseStatus = getStatus(samlResponseDocument);
        if (!this.responseStatus.is(Constants.STATUS_SUCCESS)) {
            StringBuilder statusExceptionMsg =
                    new StringBuilder("The status code of the Response was not Success, was ").append(this.responseStatus.getStatusCode());
            if (this.responseStatus.getStatusMessage() != null) {
                statusExceptionMsg.append(" -> ").append(this.responseStatus.getStatusMessage());
            }
            throw new ValidationException(statusExceptionMsg.toString(), ValidationException.STATUS_CODE_IS_NOT_SUCCESS);
        }
    }

    /**
     * Get Status from a Response
     *
     * @param dom
     *            The Response as XML
     *
     * @return SamlResponseStatus
     *
     */
    public static SamlResponseStatus getStatus(final Document dom) {
        final String statusXpath = "/samlp:Response/samlp:Status";
        return Util.getStatus(statusXpath, dom);
    }

    /**
     * Checks that the samlp:Response/saml:Assertion/saml:Conditions element exists and is unique.
     *
     * @return true if the Conditions element exists and is unique
     *
     *
     */
    public Boolean checkOneCondition() {
        final NodeList entries = this.queryAssertion("/saml:Conditions");
        if (entries.getLength() == 1) {
            return true;
        }
        return false;
    }

    /**
     * Checks that the samlp:Response/saml:Assertion/saml:AuthnStatement element exists and is unique.
     *
     * @return true if the AuthnStatement element exists and is unique
     *
     *
     */
    public Boolean checkOneAuthnStatement() {
        final NodeList entries = this.queryAssertion("/saml:AuthnStatement");
        if (entries.getLength() == 1) {
            return true;
        }
        return false;
    }

    /**
     * Gets the audiences.
     *
     * @return the audiences of the response
     *
     *
     */
    public List<String> getAudiences() {
        final List<String> audiences = new ArrayList<>();

        final NodeList entries = this.queryAssertion("/saml:Conditions/saml:AudienceRestriction/saml:Audience");

        for (int i = 0; i < entries.getLength(); i++) {
            if (entries.item(i) != null) {
                String value = entries.item(i).getTextContent();
                if (value != null) {
                    value = value.trim();
                }
                if (!StringUtils.isEmpty(value)) {
                    audiences.add(value);
                }
            }
        }
        return audiences;
    }

    /**
     * Gets the Response Issuer.
     *
     * @return the Response Issuer, or <code>null</code> if not specified
     *
     *
     *
     *               if multiple Response issuers were found
     * @see #getAssertionIssuer()
     * @see #getIssuers()
     */
    public String getResponseIssuer() {
        final NodeList responseIssuer = Util.query(samlResponseDocument, "/samlp:Response/saml:Issuer");
        if (responseIssuer.getLength() > 0) {
            if (responseIssuer.getLength() != 1) {
                throw new ValidationException("Issuer of the Response is multiple.", ValidationException.ISSUER_MULTIPLE_IN_RESPONSE);
            }
            String value = responseIssuer.item(0).getTextContent();
            if (value != null && settings.isTrimNameIds()) {
                value = value.trim();
            }
            return value;
        }
        return null;
    }

    /**
     * Gets the Assertion Issuer.
     *
     * @return the Assertion Issuer
     *
     *
     *
     *               if no Assertion Issuer could be found, or if multiple Assertion
     *               issuers were found
     * @see #getResponseIssuer()
     * @see #getIssuers()
     */
    public String getAssertionIssuer() {
        final NodeList assertionIssuer = this.queryAssertion("/saml:Issuer");
        if (assertionIssuer.getLength() != 1) {
            throw new ValidationException("Issuer of the Assertion not found or multiple.",
                    ValidationException.ISSUER_NOT_FOUND_IN_ASSERTION);
        }
        String value = assertionIssuer.item(0).getTextContent();
        if (value != null && settings.isTrimNameIds()) {
            value = value.trim();
        }
        return value;
    }

    /**
     * Gets the Issuers (from Response and Assertion). If the same issuer appears
     * both in the Response and in the Assertion (as it should), the returned list
     * will contain it just once. Hence, the returned list should always return one
     * element and in particular:
     * <ul>
     * <li>it will never contain zero elements (it means an Assertion Issuer could
     * not be found, hence a {@link ValidationException} will be thrown instead)
     * <li>if it contains more than one element, it means that the response is
     * invalid and one of the returned issuers won't pass the check performed by
     * {@link #isValid(String)} (which requires both issuers to be equal to the
     * Identity Provider entity id)
     * </ul>
     * <p>
     * Warning: as a consequence of the above, if this response status code is not a
     * successful one, this method will throw a {@link ValidationException} because it
     * won't find any Assertion Issuer. In this case, if you need to retrieve the
     * Response Issuer any way, you must use {@link #getResponseIssuer()} instead.
     *
     * @return the issuers of the assertion/response
     *
     *
     *
     *               if multiple Response Issuers or multiple Assertion Issuers were
     *               found, or if no Assertion Issuer could be found
     * @see #getResponseIssuer()
     * @see #getAssertionIssuer()
     * @deprecated use {@link #getResponseIssuer()} and/or
     *             {@link #getAssertionIssuer()}; the contract of this method is
     *             quite controversial
     */
    @Deprecated
    public List<String> getIssuers() {
        final List<String> issuers = new ArrayList<>();
        final String responseIssuer = getResponseIssuer();
        if (responseIssuer != null) {
            issuers.add(responseIssuer);
        }
        final String assertionIssuer = getAssertionIssuer();
        if (!issuers.contains(assertionIssuer)) {
            issuers.add(assertionIssuer);
        }
        return issuers;
    }

    /**
     * Gets the SessionNotOnOrAfter from the AuthnStatement. Could be used to
     * set the local session expiration
     *
     * @return the SessionNotOnOrAfter value
     *
     */
    public Instant getSessionNotOnOrAfter() {
        String notOnOrAfter = null;
        final NodeList entries = this.queryAssertion("/saml:AuthnStatement[@SessionNotOnOrAfter]");
        if (entries.getLength() > 0) {
            notOnOrAfter = entries.item(0).getAttributes().getNamedItem("SessionNotOnOrAfter").getNodeValue();
            return Util.parseDateTime(notOnOrAfter);
        }
        return null;
    }

    /**
     * Gets the SessionIndex from the AuthnStatement.
     * Could be used to be stored in the local session in order
     * to be used in a future Logout Request that the SP could
     * send to the SP, to set what specific session must be deleted
     *
     * @return the SessionIndex value
     *
     */
    public String getSessionIndex() {
        String sessionIndex = null;
        final NodeList entries = this.queryAssertion("/saml:AuthnStatement[@SessionIndex]");
        if (entries.getLength() > 0) {
            sessionIndex = entries.item(0).getAttributes().getNamedItem("SessionIndex").getNodeValue();
        }
        return sessionIndex;
    }

    /**
     * @return the ID of the Response
     */
    public String getId() {
        return samlResponseDocument.getDocumentElement().getAttributes().getNamedItem("ID").getNodeValue();
    }

    /**
     * @return the ID of the assertion in the Response
     *
     */
    public String getAssertionId() {
        if (!validateNumAssertions()) {
            throw new IllegalArgumentException("SAML Response must contain 1 Assertion.");
        }
        final NodeList assertionNode = queryAssertion("");
        return assertionNode.item(0).getAttributes().getNamedItem("ID").getNodeValue();
    }

    /**
     * @return a list of NotOnOrAfter values from SubjectConfirmationData nodes in this Response
     *
     */
    public List<Instant> getAssertionNotOnOrAfter() {
        final NodeList notOnOrAfterNodes = queryAssertion("/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData");
        final ArrayList<Instant> notOnOrAfters = new ArrayList<>();
        for (int i = 0; i < notOnOrAfterNodes.getLength(); i++) {
            final Node notOnOrAfterAttribute = notOnOrAfterNodes.item(i).getAttributes().getNamedItem("NotOnOrAfter");
            if (notOnOrAfterAttribute != null) {
                notOnOrAfters.add(Instant.parse(notOnOrAfterAttribute.getNodeValue()));
            }
        }
        return notOnOrAfters;
    }

    /**
     * Verifies that the document only contains a single Assertion (encrypted or not).
     *
     * @return true if the document passes.
     *
     */
    public boolean validateNumAssertions() {
        final NodeList encryptedAssertionNodes = samlResponseDocument.getElementsByTagNameNS(Constants.NS_SAML, "EncryptedAssertion");
        final NodeList assertionNodes = samlResponseDocument.getElementsByTagNameNS(Constants.NS_SAML, "Assertion");

        boolean valid = assertionNodes.getLength() + encryptedAssertionNodes.getLength() == 1;

        if (encrypted) {
            valid = valid && decryptedDocument.getElementsByTagNameNS(Constants.NS_SAML, "Assertion").getLength() == 1;
        }

        return valid;
    }

    /**
     * Verifies the signature nodes:
     * - Checks that are Response or Assertion
     * - Check that IDs and reference URI are unique and consistent.
     *
     * @return array Signed element tags
     *
     */
    public ArrayList<String> processSignedElements() {
        final ArrayList<String> signedElements = new ArrayList<>();
        final ArrayList<String> verifiedSeis = new ArrayList<>();
        final ArrayList<String> verifiedIds = new ArrayList<>();

        final NodeList signNodes = query("//ds:Signature", null);
        for (int i = 0; i < signNodes.getLength(); i++) {
            final Node signNode = signNodes.item(i);
            final String signedElement = "{" + signNode.getParentNode().getNamespaceURI() + "}" + signNode.getParentNode().getLocalName();

            final String responseTag = "{" + Constants.NS_SAMLP + "}Response";
            final String assertionTag = "{" + Constants.NS_SAML + "}Assertion";

            if (!responseTag.equals(signedElement) && !assertionTag.equals(signedElement)) {
                throw new ValidationException("Invalid Signature Element " + signedElement + " SAML Response rejected",
                        ValidationException.WRONG_SIGNED_ELEMENT);
            }

            // Check that reference URI matches the parent ID and no duplicate References or IDs
            final Node idNode = signNode.getParentNode().getAttributes().getNamedItem("ID");
            if (idNode == null || idNode.getNodeValue() == null || idNode.getNodeValue().isEmpty()) {
                throw new ValidationException("Signed Element must contain an ID. SAML Response rejected",
                        ValidationException.ID_NOT_FOUND_IN_SIGNED_ELEMENT);
            }

            final String idValue = idNode.getNodeValue();
            if (verifiedIds.contains(idValue)) {
                throw new ValidationException("Duplicated ID. SAML Response rejected",
                        ValidationException.DUPLICATED_ID_IN_SIGNED_ELEMENTS);
            }
            verifiedIds.add(idValue);

            final NodeList refNodes = Util.query(null, "ds:SignedInfo/ds:Reference", signNode);
            if (refNodes.getLength() != 1) {
                // Signatures MUST contain a single <ds:Reference> containing a same-document reference to the ID
                // attribute value of the root element of the assertion or protocol message being signed
                throw new ValidationException("Unexpected number of Reference nodes found for signature. SAML Response rejected.",
                        ValidationException.UNEXPECTED_REFERENCE);
            }
            final Node refNode = refNodes.item(0);
            final Node seiNode = refNode.getAttributes().getNamedItem("URI");
            if (seiNode != null && seiNode.getNodeValue() != null && !seiNode.getNodeValue().isEmpty()) {
                final String sei = seiNode.getNodeValue().substring(1);
                if (!sei.equals(idValue)) {
                    throw new ValidationException("Found an invalid Signed Element. SAML Response rejected",
                            ValidationException.INVALID_SIGNED_ELEMENT);
                }

                if (verifiedSeis.contains(sei)) {
                    throw new ValidationException("Duplicated Reference URI. SAML Response rejected",
                            ValidationException.DUPLICATED_REFERENCE_IN_SIGNED_ELEMENTS);
                }
                verifiedSeis.add(sei);
            }

            signedElements.add(signedElement);
        }
        if (!signedElements.isEmpty() && !validateSignedElements(signedElements)) {
            throw new ValidationException("Found an unexpected Signature Element. SAML Response rejected",
                    ValidationException.UNEXPECTED_SIGNED_ELEMENTS);
        }
        return signedElements;
    }

    /**
     * Verifies that the document has the expected signed nodes.
     *
     * @param signedElements
     *				the elements to be validated
     * @return true if is valid
     *
     */
    public boolean validateSignedElements(final ArrayList<String> signedElements) {
        if (signedElements.size() > 2) {
            return false;
        }

        final Map<String, Integer> occurrences = new HashMap<>();
        for (final String e : signedElements) {
            if (occurrences.containsKey(e)) {
                occurrences.put(e, occurrences.get(e).intValue() + 1);
            } else {
                occurrences.put(e, 1);
            }
        }

        final String responseTag = "{" + Constants.NS_SAMLP + "}Response";
        final String assertionTag = "{" + Constants.NS_SAML + "}Assertion";

        if ((occurrences.containsKey(responseTag) && occurrences.get(responseTag) > 1)
                || (occurrences.containsKey(assertionTag) && occurrences.get(assertionTag) > 1)
                || !occurrences.containsKey(responseTag) && !occurrences.containsKey(assertionTag)) {
            return false;
        }

        // check that the signed elements found here, are the ones that will be verified
        // by org.codelibs.saml2.core.core.util.Util.validateSign()
        if (occurrences.containsKey(responseTag)) {
            final NodeList expectedSignatureNode = query(Util.RESPONSE_SIGNATURE_XPATH, null);
            if (expectedSignatureNode.getLength() != 1) {
                throw new ValidationException("Unexpected number of Response signatures found. SAML Response rejected.",
                        ValidationException.WRONG_NUMBER_OF_SIGNATURES_IN_RESPONSE);
            }
        }

        if (occurrences.containsKey(assertionTag)) {
            final NodeList expectedSignatureNode = query(Util.ASSERTION_SIGNATURE_XPATH, null);
            if (expectedSignatureNode.getLength() != 1) {
                throw new ValidationException("Unexpected number of Assertion signatures found. SAML Response rejected.",
                        ValidationException.WRONG_NUMBER_OF_SIGNATURES_IN_ASSERTION);
            }
        }

        return true;
    }

    /**
     * Verifies that the document is still valid according Conditions Element.
     *
     * @return true if still valid
     *
     */
    public boolean validateTimestamps() {
        final NodeList timestampNodes = samlResponseDocument.getElementsByTagNameNS("*", "Conditions");
        if (timestampNodes.getLength() != 0) {
            for (int i = 0; i < timestampNodes.getLength(); i++) {
                final NamedNodeMap attrName = timestampNodes.item(i).getAttributes();
                final Node nbAttribute = attrName.getNamedItem("NotBefore");
                final Node naAttribute = attrName.getNamedItem("NotOnOrAfter");
                // validate NotOnOrAfter
                if (naAttribute != null) {
                    Instant notOnOrAfterDate = Util.parseDateTime(naAttribute.getNodeValue());
                    notOnOrAfterDate = ChronoUnit.SECONDS.addTo(notOnOrAfterDate, settings.getClockDrift());
                    if (Util.isEqualNow(notOnOrAfterDate) || Util.isBeforeNow(notOnOrAfterDate)) {
                        throw new ValidationException("Could not validate timestamp: expired. Check system clock.",
                                ValidationException.ASSERTION_EXPIRED);
                    }
                }
                // validate NotBefore
                if (nbAttribute != null) {
                    Instant notBeforeDate = Util.parseDateTime(nbAttribute.getNodeValue());
                    notBeforeDate = ChronoUnit.SECONDS.addTo(notBeforeDate, settings.getClockDrift() * -1);
                    if (Util.isAfterNow(notBeforeDate)) {
                        throw new ValidationException("Could not validate timestamp: not yet valid. Check system clock.",
                                ValidationException.ASSERTION_TOO_EARLY);
                    }
                }
            }
        }
        return true;
    }

    /**
     * Aux method to set the destination url
     *
     * @param url
     *				the url to set as currentUrl
     */
    public void setDestinationUrl(final String url) {
        currentUrl = url;
    }

    /**
     * After execute a validation process, if fails this method returns the cause
     *
     * @return the cause of the validation error as a string
     */
    public String getError() {
        if (validationException != null) {
            return validationException.getMessage();
        }
        return null;
    }

    /**
     * After execute a validation process, if fails this method returns the Exception object
     *
     * @return the cause of the validation error
     */
    public Exception getValidationException() {
        return validationException;
    }

    /**
     * Sets the validation exception that this {@link SamlResponse} should return
     * when a validation error occurs.
     *
     * @param validationException
     *              the validation exception to set
     */
    protected void setValidationException(final Exception validationException) {
        this.validationException = validationException;
    }

    /**
     * Extracts a node from the DOMDocument (Assertion).
     *
     * @param assertionXpath
     *				Xpath Expression
     *
     * @return the queried node
     *
     *
     */
    protected NodeList queryAssertion(final String assertionXpath) {
        final String assertionExpr = "/saml:Assertion";
        final String signatureExpr = "ds:Signature/ds:SignedInfo/ds:Reference";

        String nameQuery;
        final String signedAssertionQuery = "/samlp:Response" + assertionExpr + "/" + signatureExpr;
        NodeList nodeList = query(signedAssertionQuery, null);
        if (nodeList.getLength() == 0) {
            // let see if the whole response signed?
            final String signedMessageQuery = "/samlp:Response/" + signatureExpr;
            nodeList = query(signedMessageQuery, null);
            if (nodeList.getLength() == 1) {
                final Node responseReferenceNode = nodeList.item(0);
                String responseId = responseReferenceNode.getAttributes().getNamedItem("URI").getNodeValue();
                if (responseId != null && !responseId.isEmpty()) {
                    responseId = responseId.substring(1);
                } else {
                    responseId = responseReferenceNode.getParentNode().getParentNode().getParentNode().getAttributes().getNamedItem("ID")
                            .getNodeValue();
                }
                nameQuery = "/samlp:Response[@ID='" + responseId + "']";
            } else {
                // On this case there is no element signed, the query will work but
                // the response validation will throw and error.
                nameQuery = "/samlp:Response";
            }
            nameQuery += assertionExpr;
        } else { // there is a signed assertion
            final Node assertionReferenceNode = nodeList.item(0);
            String assertionId = assertionReferenceNode.getAttributes().getNamedItem("URI").getNodeValue();
            if (assertionId != null && !assertionId.isEmpty()) {
                assertionId = assertionId.substring(1);
            } else {
                assertionId = assertionReferenceNode.getParentNode().getParentNode().getParentNode().getAttributes().getNamedItem("ID")
                        .getNodeValue();
            }
            nameQuery = "/samlp:Response/" + assertionExpr + "[@ID='" + assertionId + "']";
        }
        nameQuery += assertionXpath;

        return query(nameQuery, null);
    }

    /**
     * Extracts nodes that match the query from the DOMDocument (Response Message)
     *
     * @param nameQuery
     *				Xpath Expression
     * @param context
     *              The context node
     *
     * @return DOMNodeList The queried nodes
     */
    protected NodeList query(final String nameQuery, final Node context) {
        // LOGGER.debug("Executing query " + nameQuery);
        return Util.query(getSAMLResponseDocument(), nameQuery, context);
    }

    /**
     * Decrypt assertion.
     *
     * @param dom
     *            Encrypted assertion
     *
     * @return Decrypted Assertion.
     *
     */
    private Document decryptAssertion(final Document dom) {
        final PrivateKey key = settings.getSPkey();

        final HSM hsm = this.settings.getHsm();

        if (hsm == null && key == null) {
            throw new SettingsException("No private key available for decrypt, check settings", SettingsException.PRIVATE_KEY_NOT_FOUND);
        }

        final NodeList encryptedDataNodes = Util.query(dom, "/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData");
        if (encryptedDataNodes.getLength() == 0) {
            throw new ValidationException("No /samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData element found",
                    ValidationException.MISSING_ENCRYPTED_ELEMENT);
        }
        final Element encryptedData = (Element) encryptedDataNodes.item(0);

        if (hsm != null) {
            Util.decryptUsingHsm(encryptedData, hsm);
        } else {
            Util.decryptElement(encryptedData, key);
        }

        // We need to Remove the saml:EncryptedAssertion Node
        final NodeList AssertionDataNodes = Util.query(dom, "/samlp:Response/saml:EncryptedAssertion/saml:Assertion");
        if (encryptedDataNodes.getLength() == 0) {
            throw new ValidationException("No /samlp:Response/saml:EncryptedAssertion/saml:Assertion element found",
                    ValidationException.MISSING_ENCRYPTED_ELEMENT);
        }
        final Node assertionNode = AssertionDataNodes.item(0);
        assertionNode.getParentNode().getParentNode().replaceChild(assertionNode, assertionNode.getParentNode());

        // In order to avoid Signature Validation errors we need to rebuild the dom.
        // https://groups.google.com/forum/#!topic/opensaml-users/gpXvwaZ53NA
        final String xmlStr = Util.convertDocumentToString(dom);

        // LOGGER.debug("Decrypted SAMLResponse --> " + xmlStr);
        return Util.convertStringToDocument(xmlStr);
    }

    /**
     * @return the SAMLResponse XML, If the Assertion of the SAMLResponse was encrypted,
     *         returns the XML with the assertion decrypted
     */
    public String getSAMLResponseXml() {
        String xml;
        if (encrypted) {
            xml = Util.convertDocumentToString(decryptedDocument);
        } else {
            xml = samlResponseString;
        }
        return xml;
    }

    /**
     * @return the SAMLResponse Document, If the Assertion of the SAMLResponse was encrypted,
     *         returns the Document with the assertion decrypted
     */
    protected Document getSAMLResponseDocument() {
        Document doc;
        if (encrypted) {
            doc = decryptedDocument;
        } else {
            doc = samlResponseDocument;
        }
        return doc;
    }

    /**
     * Validates the audiences.
     *
     *
     *
     */
    protected void validateAudiences() {
        final List<String> validAudiences = getAudiences();
        if (!validAudiences.isEmpty() && !validAudiences.contains(settings.getSpEntityId())) {
            throw new ValidationException(settings.getSpEntityId() + " is not a valid audience for this Response",
                    ValidationException.WRONG_AUDIENCE);
        }
    }

    /**
     * Validate the destination.
     *
     * @param element element with the destination attribute
     *
     */
    protected void validateDestination(final Element element) {
        if (element.hasAttribute("Destination")) {
            final String destinationUrl = element.getAttribute("Destination");
            if (destinationUrl != null) {
                if (destinationUrl.isEmpty()) {
                    throw new ValidationException("The response has an empty Destination value", ValidationException.EMPTY_DESTINATION);
                }
                if (!destinationUrl.equals(currentUrl)) {
                    throw new ValidationException("The response was received at " + currentUrl + " instead of " + destinationUrl,
                            ValidationException.WRONG_DESTINATION);
                }
            }
        }
    }

    /**
     * Validate a subject confirmation recipient.
     *
     * @param recipient recipient node
     * @param index index of the subject confirmation node
     * @return a subject confirmation issue or null
     */
    protected SubjectConfirmationIssue validateRecipient(final Node recipient, final int index) {
        if (recipient == null) {
            return new SubjectConfirmationIssue(index, "SubjectConfirmationData doesn't contain a Recipient");
        }

        if (!recipient.getNodeValue().equals(currentUrl)) {
            return new SubjectConfirmationIssue(index, "SubjectConfirmationData doesn't match a valid Recipient");
        }

        return null;
    }

    /**
     * Validates a SPNameQualifier.
     *
     * @param spNameQualifier the SPNameQualifier
     *
     */
    protected void validateSpNameQualifier(final String spNameQualifier) {
        if (settings.isStrict() && !spNameQualifier.equals(settings.getSpEntityId())) {
            throw new ValidationException("The SPNameQualifier value mismatch the SP entityID value.",
                    ValidationException.SP_NAME_QUALIFIER_NAME_MISMATCH);
        }
    }

    /**
     * Returns the issue instant of this message.
     *
     * @return a new {@link Calendar} instance carrying the issue instant of this message
     *
     *             if the found IssueInstant attribute is not in the expected
     *             UTC form of ISO-8601 format
     */
    public Calendar getResponseIssueInstant() {
        final Element rootElement = getSAMLResponseDocument().getDocumentElement();
        final String issueInstantString = rootElement.hasAttribute("IssueInstant") ? rootElement.getAttribute("IssueInstant") : null;
        if (issueInstantString == null) {
            return null;
        }
        final Calendar result = Calendar.getInstance();
        try {
            result.setTimeInMillis(Util.parseDateTime(issueInstantString).toEpochMilli());
        } catch (final IllegalArgumentException e) {
            throw new ValidationException("The Response IssueInstant attribute is not in the expected UTC form of ISO-8601 format",
                    ValidationException.INVALID_ISSUE_INSTANT_FORMAT);
        }
        return result;
    }
}
