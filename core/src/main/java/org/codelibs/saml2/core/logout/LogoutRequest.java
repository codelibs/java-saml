package org.codelibs.saml2.core.logout;

import java.net.URL;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.text.StringSubstitutor;
import org.codelibs.saml2.core.exception.SAMLException;
import org.codelibs.saml2.core.exception.SettingsException;
import org.codelibs.saml2.core.exception.ValidationException;
import org.codelibs.saml2.core.exception.XMLParsingException;
import org.codelibs.saml2.core.http.HttpRequest;
import org.codelibs.saml2.core.settings.Saml2Settings;
import org.codelibs.saml2.core.util.Constants;
import org.codelibs.saml2.core.util.SchemaFactory;
import org.codelibs.saml2.core.util.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * LogoutRequest class of Java Toolkit.
 *
 * A class that implements SAML 2 Logout Request builder/parser/validator
 */
public class LogoutRequest {
    /**
     * Private property to construct a logger for this class.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(LogoutRequest.class);

    /**
     * SAML LogoutRequest string
     */
    private final String logoutRequestString;

    /**
     * SAML LogoutRequest ID.
     */
    public String id;

    /**
     * Settings data.
     */
    private final Saml2Settings settings;

    /**
     * HttpRequest object to be processed (Contains GET and POST parameters, request URL, ...).
     */
    private final HttpRequest request;

    /**
     * URL of the current host + current view
     */
    private String currentUrl;

    /**
     * Time when the Logout Request was created
     */
    private Calendar issueInstant;

    /**
     * After validation, if it fails this property has the cause of the problem
     */
    private Exception validationException;

    /**
     * Constructs the LogoutRequest object.
     *
     * @param settings
     *              OneLogin_Saml2_Settings
     * @param request
     *              the HttpRequest object to be processed (Contains GET and POST
     *              parameters, request URL, ...).
     * @param nameId
     *              The NameID that will be set in the LogoutRequest.
     * @param sessionIndex
     *              The SessionIndex (taken from the SAML Response in the SSO
     *              process).
     * @param nameIdFormat
     *              The nameIdFormat that will be set in the LogoutRequest.
     * @param nameIdNameQualifier
     *              The NameID NameQualifier that will be set in the LogoutRequest.
     * @param nameIdSPNameQualifier
     *              The SP Name Qualifier that will be set in the LogoutRequest.
     *
     * @deprecated use {@link #LogoutRequest(Saml2Settings, HttpRequest)} to build a
     *             received request from the HTTP request, or
     *             {@link #LogoutRequest(Saml2Settings, LogoutRequestParams)} with
     *             {@link LogoutRequestParams#LogoutRequestParams(String, String, String, String, String)}
     *             to build a new request to be sent
     */
    @Deprecated
    public LogoutRequest(final Saml2Settings settings, final HttpRequest request, final String nameId, final String sessionIndex,
            final String nameIdFormat, final String nameIdNameQualifier, final String nameIdSPNameQualifier) {
        this.settings = settings;
        this.request = request;

        String samlLogoutRequest = null;

        if (request != null) {
            samlLogoutRequest = request.getParameter("SAMLRequest");
            currentUrl = request.getRequestURL();
        }

        if (samlLogoutRequest == null) {
            final LogoutRequestParams params =
                    new LogoutRequestParams(sessionIndex, nameId, nameIdFormat, nameIdNameQualifier, nameIdSPNameQualifier);
            id = Util.generateUniqueID(settings.getUniqueIDPrefix());
            issueInstant = Calendar.getInstance();

            final StringSubstitutor substitutor = generateSubstitutor(params, settings);
            logoutRequestString = postProcessXml(substitutor.replace(getLogoutRequestTemplate()), params, settings);
        } else {
            logoutRequestString = Util.base64decodedInflated(samlLogoutRequest);
            final Document doc = Util.loadXML(logoutRequestString);
            id = getId(doc);
            issueInstant = getIssueInstant(doc);
        }
    }

    /**
     * Constructs the LogoutRequest object.
     *
     * @param settings
     *              OneLogin_Saml2_Settings
     * @param request
     *              the HttpRequest object to be processed (Contains GET and POST
     *              parameters, request URL, ...).
     * @param nameId
     *              The NameID that will be set in the LogoutRequest.
     * @param sessionIndex
     *              The SessionIndex (taken from the SAML Response in the SSO
     *              process).
     * @param nameIdFormat
     *              The nameIdFormat that will be set in the LogoutRequest.
     * @param nameIdNameQualifier
     *              The NameID NameQualifier will be set in the LogoutRequest.
     *
     * @deprecated use {@link #LogoutRequest(Saml2Settings, HttpRequest)} to build a
     *             received request from the HTTP request, or
     *             {@link #LogoutRequest(Saml2Settings, LogoutRequestParams)} with
     *             {@link LogoutRequestParams#LogoutRequestParams(String, String, String, String)}
     *             to build a new request to be sent
     */
    @Deprecated
    public LogoutRequest(final Saml2Settings settings, final HttpRequest request, final String nameId, final String sessionIndex,
            final String nameIdFormat, final String nameIdNameQualifier) {
        this(settings, request, nameId, sessionIndex, nameIdFormat, nameIdNameQualifier, null);
    }

    /**
     * Constructs the LogoutRequest object.
     *
     * @param settings
     *              OneLogin_Saml2_Settings
     * @param request
     *              the HttpRequest object to be processed (Contains GET and POST
     *              parameters, request URL, ...).
     * @param nameId
     *              The NameID that will be set in the LogoutRequest.
     * @param sessionIndex
     *              The SessionIndex (taken from the SAML Response in the SSO
     *              process).
     * @param nameIdFormat
     *              The nameIdFormat that will be set in the LogoutRequest.
     *
     * @deprecated use {@link #LogoutRequest(Saml2Settings, HttpRequest)} to build a
     *             received request from the HTTP request, or
     *             {@link #LogoutRequest(Saml2Settings, LogoutRequestParams)} with
     *             {@link LogoutRequestParams#LogoutRequestParams(String, String, String)}
     *             to build a new request to be sent
     */
    @Deprecated
    public LogoutRequest(final Saml2Settings settings, final HttpRequest request, final String nameId, final String sessionIndex,
            final String nameIdFormat) {
        this(settings, request, nameId, sessionIndex, nameIdFormat, null);
    }

    /**
     * Constructs the LogoutRequest object.
     *
     * @param settings
     *              OneLogin_Saml2_Settings
     * @param request
     *              the HttpRequest object to be processed (Contains GET and POST
     *              parameters, request URL, ...).
     * @param nameId
     *              The NameID that will be set in the LogoutRequest.
     * @param sessionIndex
     *              The SessionIndex (taken from the SAML Response in the SSO
     *              process).
     *
     * @deprecated use {@link #LogoutRequest(Saml2Settings, HttpRequest)} to build a
     *             received request from the HTTP request, or
     *             {@link #LogoutRequest(Saml2Settings, LogoutRequestParams)} with
     *             {@link LogoutRequestParams#LogoutRequestParams(String, String)}
     *             to build a new request to be sent
     */
    @Deprecated
    public LogoutRequest(final Saml2Settings settings, final HttpRequest request, final String nameId, final String sessionIndex) {
        this(settings, request, nameId, sessionIndex, null);
    }

    /**
     * Constructs a LogoutRequest object when a new request should be generated and
     * sent.
     *
     * @param settings
     *              OneLogin_Saml2_Settings
     *
     * @see #LogoutRequest(Saml2Settings, LogoutRequestParams)
     */
    public LogoutRequest(final Saml2Settings settings) {
        this(settings, new LogoutRequestParams());
    }

    /**
     * Constructs the LogoutRequest object when a received request should be
     * extracted from the HTTP request and parsed.
     *
     * @param settings
     *              OneLogin_Saml2_Settings
     * @param request
     *              the HttpRequest object to be processed (Contains GET and POST
     *              parameters, request URL, ...).
     */
    public LogoutRequest(final Saml2Settings settings, final HttpRequest request) {
        this(settings, request, null, null);
    }

    /**
     * Constructs the LogoutRequest object when a new request should be generated
     * and sent.
     *
     * @param settings
     *              OneLogin_Saml2_Settings
     * @param params
     *              a set of logout request input parameters that shape the
     *              request to create
     */
    public LogoutRequest(final Saml2Settings settings, final LogoutRequestParams params) {
        this.settings = settings;
        this.request = null;
        id = Util.generateUniqueID(settings.getUniqueIDPrefix());
        issueInstant = Calendar.getInstance();

        final StringSubstitutor substitutor = generateSubstitutor(params, settings);
        logoutRequestString = postProcessXml(substitutor.replace(getLogoutRequestTemplate()), params, settings);
    }

    /**
     * Allows for an extension class to post-process the LogoutRequest XML generated
     * for this request, in order to customize the result.
     * <p>
     * This method is invoked at construction time when no existing LogoutRequest
     * message is found in the HTTP request (and hence in the logout request sending
     * scenario only), after all the other fields of this class have already been
     * initialised. Its default implementation simply returns the input XML as-is,
     * with no change.
     *
     * @param logoutRequestXml
     *              the XML produced for this LogoutRequest by the standard
     *              implementation provided by {@link LogoutRequest}
     * @param params
     *              the logout request input parameters
     * @param settings
     *              the settings
     * @return the post-processed XML for this LogoutRequest, which will then be
     *         returned by any call to {@link #getLogoutRequestXml()}
     */
    protected String postProcessXml(final String logoutRequestXml, final LogoutRequestParams params, final Saml2Settings settings) {
        return logoutRequestXml;
    }

    /**
     * @return the base64 encoded unsigned Logout Request (deflated or not)
     *
     * @param deflated
     *				If deflated or not the encoded Logout Request
     *
     */
    public String getEncodedLogoutRequest(Boolean deflated) {
        String encodedLogoutRequest;
        if (deflated == null) {
            deflated = settings.isCompressRequestEnabled();
        }
        if (deflated) {
            encodedLogoutRequest = Util.deflatedBase64encoded(getLogoutRequestXml());
        } else {
            encodedLogoutRequest = Util.base64encoder(getLogoutRequestXml());
        }
        return encodedLogoutRequest;
    }

    /**
     * @return the base64 encoded unsigned Logout Request (deflated or not)
     *
     */
    public String getEncodedLogoutRequest() {
        return getEncodedLogoutRequest(null);
    }

    /**
     * @return the plain XML Logout Request
     */
    public String getLogoutRequestXml() {
        return logoutRequestString;
    }

    /**
     * Substitutes LogoutRequest variables within a string by values.
     *
     * @param params
     *              the logout request input parameters
     * @param settings
     *              Saml2Settings object. Setting data
     *
     * @return the StringSubstitutor object of the LogoutRequest
     */
    private StringSubstitutor generateSubstitutor(final LogoutRequestParams params, final Saml2Settings settings) {
        final Map<String, String> valueMap = new HashMap<>();

        valueMap.put("id", Util.toXml(id));

        final String issueInstantString = Util.formatDateTime(issueInstant.getTimeInMillis());
        valueMap.put("issueInstant", issueInstantString);

        String destinationStr = "";
        final URL slo = settings.getIdpSingleLogoutServiceUrl();
        if (slo != null) {
            destinationStr = " Destination=\"" + Util.toXml(slo.toString()) + "\"";
        }
        valueMap.put("destinationStr", destinationStr);

        valueMap.put("issuer", Util.toXml(settings.getSpEntityId()));

        String nameId = params.getNameId();
        final String requestedNameIdFormat = params.getNameIdFormat();
        String nameIdFormat = null;
        String spNameQualifier = params.getNameIdSPNameQualifier();
        String nameQualifier = params.getNameIdNameQualifier();
        if (nameId != null) {
            if (requestedNameIdFormat == null && !Constants.NAMEID_UNSPECIFIED.equals(settings.getSpNameIDFormat())) {
                nameIdFormat = settings.getSpNameIDFormat();
            } else {
                nameIdFormat = requestedNameIdFormat;
            }
        } else {
            nameId = settings.getIdpEntityId();
            nameIdFormat = Constants.NAMEID_ENTITY;
        }

        // From saml-core-2.0-os 8.3.6, when the entity Format is used: "The NameQualifier, SPNameQualifier, and
        // SPProvidedID attributes MUST be omitted.
        if (nameIdFormat != null && Constants.NAMEID_ENTITY.equals(nameIdFormat)) {
            nameQualifier = null;
            spNameQualifier = null;
        }

        // NameID Format UNSPECIFIED omitted
        if (nameIdFormat != null && Constants.NAMEID_UNSPECIFIED.equals(nameIdFormat)) {
            nameIdFormat = null;
        }

        X509Certificate cert = null;
        if (settings.getNameIdEncrypted()) {
            cert = settings.getIdpx509cert();
            if (cert == null) {
                final List<X509Certificate> multipleCertList = settings.getIdpx509certMulti();
                if (multipleCertList != null && !multipleCertList.isEmpty()) {
                    cert = multipleCertList.get(0);
                }
            }
        }

        final String nameIdStr = Util.generateNameId(nameId, spNameQualifier, nameIdFormat, nameQualifier, cert);
        valueMap.put("nameIdStr", nameIdStr);

        String sessionIndexStr = "";
        final String sessionIndex = params.getSessionIndex();
        if (sessionIndex != null) {
            sessionIndexStr = " <samlp:SessionIndex>" + Util.toXml(sessionIndex) + "</samlp:SessionIndex>";
        }
        valueMap.put("sessionIndexStr", sessionIndexStr);

        return new StringSubstitutor(valueMap);
    }

    /**
     * @return the LogoutRequest's template
     */
    private static StringBuilder getLogoutRequestTemplate() {
        final StringBuilder template = new StringBuilder();
        template.append(
                "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ");
        template.append("ID=\"${id}\" ");
        template.append("Version=\"2.0\" ");
        template.append("IssueInstant=\"${issueInstant}\"${destinationStr} >");
        template.append("<saml:Issuer>${issuer}</saml:Issuer>");
        template.append("${nameIdStr}${sessionIndexStr}</samlp:LogoutRequest>");
        return template;
    }

    /**
       * Determines if the SAML LogoutRequest is valid or not
       *
       * @return true if the SAML LogoutRequest is valid
       */
    public boolean isValid() {
        validationException = null;

        try {
            if (this.logoutRequestString == null || logoutRequestString.isEmpty()) {
                throw new ValidationException("SAML Logout Request is not loaded", ValidationException.INVALID_XML_FORMAT);
            }

            if (this.request == null) {
                throw new IllegalArgumentException("The HttpRequest of the current host was not established");
            }

            if (this.currentUrl == null || this.currentUrl.isEmpty()) {
                throw new IllegalArgumentException("The URL of the current host was not established");
            }

            final String signature = request.getParameter("Signature");

            final Document logoutRequestDocument = Util.loadXML(logoutRequestString);

            if (settings.isStrict()) {
                final Element rootElement = logoutRequestDocument.getDocumentElement();
                rootElement.normalize();

                if (settings.getWantXMLValidation() && !Util.validateXML(logoutRequestDocument, SchemaFactory.SAML_SCHEMA_PROTOCOL_2_0)) {
                    throw new ValidationException("Invalid SAML Logout Request. Not match the saml-schema-protocol-2.0.xsd",
                            ValidationException.INVALID_XML_FORMAT);
                }

                // Check NotOnOrAfter
                if (rootElement.hasAttribute("NotOnOrAfter")) {
                    final String notOnOrAfter = rootElement.getAttribute("NotOnOrAfter");
                    final Instant notOnOrAfterDate = Util.parseDateTime(notOnOrAfter);
                    if (Util.isEqualNow(notOnOrAfterDate) || Util.isBeforeNow(notOnOrAfterDate)) {
                        throw new ValidationException("Could not validate timestamp: expired. Check system clock.",
                                ValidationException.RESPONSE_EXPIRED);
                    }
                }

                // Check destination
                if (rootElement.hasAttribute("Destination")) {
                    final String destinationUrl = rootElement.getAttribute("Destination");
                    if ((destinationUrl != null) && (!destinationUrl.isEmpty() && !destinationUrl.equals(currentUrl))) {
                        throw new ValidationException("The LogoutRequest was received at " + currentUrl + " instead of " + destinationUrl,
                                ValidationException.WRONG_DESTINATION);
                    }
                }

                getNameId(logoutRequestDocument, settings.getSPkey(), settings.isTrimNameIds());

                // Check the issuer
                final String issuer = getIssuer(logoutRequestDocument, settings.isTrimNameIds());
                if (issuer != null && (issuer.isEmpty() || !issuer.equals(settings.getIdpEntityId()))) {
                    throw new ValidationException(String.format("Invalid issuer in the Logout Request. Was '%s', but expected '%s'", issuer,
                            settings.getIdpEntityId()), ValidationException.WRONG_ISSUER);
                }

                if (settings.getWantMessagesSigned() && (signature == null || signature.isEmpty())) {
                    throw new ValidationException("The Message of the Logout Request is not signed and the SP requires it",
                            ValidationException.NO_SIGNED_MESSAGE);
                }
            }

            if (signature != null && !signature.isEmpty()) {
                final X509Certificate cert = settings.getIdpx509cert();

                final List<X509Certificate> certList = new ArrayList<>();
                final List<X509Certificate> multipleCertList = settings.getIdpx509certMulti();

                if (multipleCertList != null && multipleCertList.size() != 0) {
                    certList.addAll(multipleCertList);
                }

                if ((cert != null) && (certList.isEmpty() || !certList.contains(cert))) {
                    certList.add(0, cert);
                }

                if (certList.isEmpty()) {
                    throw new SettingsException("In order to validate the sign on the Logout Request, the x509cert of the IdP is required",
                            SettingsException.CERT_NOT_FOUND);
                }

                String signAlg = request.getParameter("SigAlg");
                if (signAlg == null || signAlg.isEmpty()) {
                    signAlg = Constants.RSA_SHA1;
                }

                final Boolean rejectDeprecatedAlg = settings.getRejectDeprecatedAlg();
                if (Util.mustRejectDeprecatedSignatureAlgo(signAlg, rejectDeprecatedAlg)) {
                    return false;
                }

                final String relayState = request.getEncodedParameter("RelayState");

                StringBuilder signedQuery = new StringBuilder("SAMLRequest=").append(request.getEncodedParameter("SAMLRequest"));

                if (relayState != null && !relayState.isEmpty()) {
                    signedQuery.append("&RelayState=").append(relayState);
                }

                signedQuery.append("&SigAlg=").append(request.getEncodedParameter("SigAlg", signAlg));

                if (!Util.validateBinarySignature(signedQuery.toString(), Util.base64decoder(signature), certList, signAlg)) {
                    throw new ValidationException("Signature validation failed. Logout Request rejected",
                            ValidationException.INVALID_SIGNATURE);
                }
            }

            LOGGER.debug("LogoutRequest validated --> {}", logoutRequestString);
            return true;
        } catch (final Exception e) {
            validationException = e;
            LOGGER.debug("LogoutRequest invalid --> {}", logoutRequestString, e);
            LOGGER.warn(validationException.getMessage());
            return false;
        }
    }

    /**
     * Returns the ID of the Logout Request Document.
     *
     * @param samlLogoutRequestDocument
     * 				A DOMDocument object loaded from the SAML Logout Request.
     *
     * @return the ID of the Logout Request.
     */
    public static String getId(final Document samlLogoutRequestDocument) {
        String id = null;
        try {
            final Element rootElement = samlLogoutRequestDocument.getDocumentElement();
            rootElement.normalize();
            id = rootElement.getAttribute("ID");
        } catch (final Exception e) {
            LOGGER.debug("Failed to get ID.", e);
        }
        return id;
    }

    /**
     * Returns the issue instant of the Logout Request Document.
     *
     * @param samlLogoutRequestDocument
     * 				A DOMDocument object loaded from the SAML Logout Request.
     *
     * @return the issue instant of the Logout Request.
     */
    public static Calendar getIssueInstant(final Document samlLogoutRequestDocument) {
        Calendar issueInstant = null;
        try {
            final Element rootElement = samlLogoutRequestDocument.getDocumentElement();
            rootElement.normalize();
            final String issueInstantString = rootElement.hasAttribute("IssueInstant") ? rootElement.getAttribute("IssueInstant") : null;
            if (issueInstantString == null) {
                return null;
            }
            issueInstant = Calendar.getInstance();
            issueInstant.setTimeInMillis(Util.parseDateTime(issueInstantString).toEpochMilli());
        } catch (final Exception e) {
            LOGGER.debug("Failed to get an issue instant.", e);
        }
        return issueInstant;
    }

    /**
     * Returns the ID of the Logout Request String.
     *
     * @param samlLogoutRequestString
     * 				A Logout Request string.
     *
     * @return the ID of the Logout Request.
     *
     */
    public static String getId(final String samlLogoutRequestString) {
        final Document doc = Util.loadXML(samlLogoutRequestString);
        return getId(doc);
    }

    /**
     * Returns the issue instant of the Logout Request Document.
     *
     * @param samlLogoutRequestString
     * 				A DOMDocument object loaded from the SAML Logout Request.
     *
     * @return the issue instant of the Logout Request.
     */
    public static Calendar getIssueInstant(final String samlLogoutRequestString) {
        final Document doc = Util.loadXML(samlLogoutRequestString);
        return getIssueInstant(doc);
    }

    /**
     * Gets the NameID Data from the the Logout Request Document.
     *
     * @param samlLogoutRequestDocument
     *              A DOMDocument object loaded from the SAML Logout Request.
     * @param key
     *              The SP key to decrypt the NameID if encrypted
     *
     * @return the Name ID Data (Value, Format, NameQualifier, SPNameQualifier)
     *
     */
    public static Map<String, String> getNameIdData(final Document samlLogoutRequestDocument, final PrivateKey key) {
        return getNameIdData(samlLogoutRequestDocument, key, false);
    }

    /**
     * Gets the NameID Data from the the Logout Request Document.
     *
     * @param samlLogoutRequestDocument
     *              A DOMDocument object loaded from the SAML Logout Request.
     * @param key
     *              The SP key to decrypt the NameID if encrypted
     * @param trimValue
     *              whether the extracted Name ID value should be trimmed
     *
     * @return the Name ID Data (Value, Format, NameQualifier, SPNameQualifier)
     *
     */
    public static Map<String, String> getNameIdData(final Document samlLogoutRequestDocument, final PrivateKey key,
            final boolean trimValue) {
        try {
            final NodeList encryptedIDNodes = Util.query(samlLogoutRequestDocument, "/samlp:LogoutRequest/saml:EncryptedID");
            NodeList nameIdNodes;
            Element nameIdElem;

            if (encryptedIDNodes.getLength() == 1) {
                if (key == null) {
                    throw new SettingsException("Key is required in order to decrypt the NameID", SettingsException.PRIVATE_KEY_NOT_FOUND);
                }

                final Element encryptedData = (Element) encryptedIDNodes.item(0);
                Util.decryptElement(encryptedData, key);
                nameIdNodes = Util.query(samlLogoutRequestDocument, "/samlp:LogoutRequest/saml:NameID");

                if (nameIdNodes == null || nameIdNodes.getLength() != 1) {
                    throw new SAMLException("Not able to decrypt the EncryptedID and get a NameID");
                }
            } else {
                nameIdNodes = Util.query(samlLogoutRequestDocument, "/samlp:LogoutRequest/saml:NameID");
            }

            if ((nameIdNodes == null) || (nameIdNodes.getLength() != 1)) {
                throw new ValidationException("No name id found in Logout Request.", ValidationException.NO_NAMEID);
            }
            nameIdElem = (Element) nameIdNodes.item(0);

            final Map<String, String> nameIdData = new HashMap<>();

            if (nameIdElem != null) {
                String value = nameIdElem.getTextContent();
                if (value != null && trimValue) {
                    value = value.trim();
                }
                nameIdData.put("Value", value);

                if (nameIdElem.hasAttribute("Format")) {
                    nameIdData.put("Format", nameIdElem.getAttribute("Format"));
                }
                if (nameIdElem.hasAttribute("SPNameQualifier")) {
                    nameIdData.put("SPNameQualifier", nameIdElem.getAttribute("SPNameQualifier"));
                }
                if (nameIdElem.hasAttribute("NameQualifier")) {
                    nameIdData.put("NameQualifier", nameIdElem.getAttribute("NameQualifier"));
                }
            }
            return nameIdData;
        } catch (SAMLException e) {
            throw e;
        } catch (DOMException e) {
            throw new XMLParsingException("Failed to get NameID Data.", e);
        }
    }

    /**
     * Gets the NameID Data from the the Logout Request String.
     *
     * @param samlLogoutRequestString
     *              A DOMDocument object loaded from the SAML Logout Request.
     * @param key
     *              The SP key to decrypt the NameID if encrypted
     *
     * @return the Name ID Data (Value, Format, NameQualifier, SPNameQualifier)
     *
     * @
     */
    public static Map<String, String> getNameIdData(final String samlLogoutRequestString, final PrivateKey key) {
        return getNameIdData(samlLogoutRequestString, key, false);
    }

    /**
     * Gets the NameID Data from the the Logout Request String.
     *
     * @param samlLogoutRequestString
     *              A DOMDocument object loaded from the SAML Logout Request.
     * @param key
     *              The SP key to decrypt the NameID if encrypted
     * @param trimValue
     *              whether the extracted Name ID value should be trimmed
     *
     * @return the Name ID Data (Value, Format, NameQualifier, SPNameQualifier)
     *
     * @
     */
    public static Map<String, String> getNameIdData(final String samlLogoutRequestString, final PrivateKey key, final boolean trimValue) {
        final Document doc = Util.loadXML(samlLogoutRequestString);
        return getNameIdData(doc, key, trimValue);
    }

    /**
     * Gets the NameID value provided from the SAML Logout Request Document.
     *
     * @param samlLogoutRequestDocument
     *              A DOMDocument object loaded from the SAML Logout Request.
     *
     * @param key
     *              The SP key to decrypt the NameID if encrypted
     *
     * @return the Name ID value
     *
     */
    public static String getNameId(final Document samlLogoutRequestDocument, final PrivateKey key) {
        return getNameId(samlLogoutRequestDocument, key, false);
    }

    /**
     * Gets the NameID value provided from the SAML Logout Request Document.
     *
     * @param samlLogoutRequestDocument
     *              A DOMDocument object loaded from the SAML Logout Request.
     *
     * @param key
     *              The SP key to decrypt the NameID if encrypted
     *
     * @param trimValue
     *              whether the extracted Name ID value should be trimmed
     *
     * @return the Name ID value
     *
     */
    public static String getNameId(final Document samlLogoutRequestDocument, final PrivateKey key, final boolean trimValue) {
        final Map<String, String> nameIdData = getNameIdData(samlLogoutRequestDocument, key, trimValue);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("LogoutRequest has NameID --> {}", nameIdData.get("Value"));
        }
        return nameIdData.get("Value");
    }

    /**
     * Gets the NameID value provided from the SAML Logout Request Document.
     *
     * @param samlLogoutRequestDocument
     *              A DOMDocument object loaded from the SAML Logout Request.
     *
     * @return the Name ID value
     *
     */
    public static String getNameId(final Document samlLogoutRequestDocument) {
        return getNameId(samlLogoutRequestDocument, null);
    }

    /**
     * Gets the NameID value provided from the SAML Logout Request String.
     *
     * @param samlLogoutRequestString
     *              A Logout Request string.
     * @param key
     *              The SP key to decrypt the NameID if encrypted
     *
     * @return the Name ID value
     *
     */
    public static String getNameId(final String samlLogoutRequestString, final PrivateKey key) {
        return getNameId(samlLogoutRequestString, key, false);
    }

    /**
     * Gets the NameID value provided from the SAML Logout Request String.
     *
     * @param samlLogoutRequestString
     *              A Logout Request string.
     * @param key
     *              The SP key to decrypt the NameID if encrypted
     * @param trimValue
     *              whether the extracted Name ID value should be trimmed
     *
     * @return the Name ID value
     *
     */
    public static String getNameId(final String samlLogoutRequestString, final PrivateKey key, final boolean trimValue) {
        final Map<String, String> nameId = getNameIdData(samlLogoutRequestString, key, trimValue);
        return nameId.get("Value");
    }

    /**
     * Gets the NameID value provided from the SAML Logout Request String.
     *
     * @param samlLogoutRequestString
     *              A Logout Request string.
     *
     * @return the Name ID value
     *
     */
    public static String getNameId(final String samlLogoutRequestString) {
        return getNameId(samlLogoutRequestString, null);
    }

    /**
     * Gets the Issuer from Logout Request Document.
     *
     * @param samlLogoutRequestDocument
     *              A DOMDocument object loaded from the SAML Logout Request.
     *
     * @return the issuer of the logout request
     *
     *
     */
    public static String getIssuer(final Document samlLogoutRequestDocument) {
        return getIssuer(samlLogoutRequestDocument, false);
    }

    /**
     * Gets the Issuer from Logout Request Document.
     *
     * @param samlLogoutRequestDocument
     *              A DOMDocument object loaded from the SAML Logout Request.
     * @param trim
     *              whether the extracted issuer value should be trimmed
     *
     * @return the issuer of the logout request
     *
     */
    public static String getIssuer(final Document samlLogoutRequestDocument, final boolean trim) {
        String issuer = null;

        final NodeList nodes = Util.query(samlLogoutRequestDocument, "/samlp:LogoutRequest/saml:Issuer");

        if (nodes.getLength() == 1) {
            issuer = nodes.item(0).getTextContent();
        }
        if (issuer != null && trim) {
            issuer = issuer.trim();
        }
        return issuer;
    }

    /**
     * Gets the Issuer from Logout Request String.
     *
     * @param samlLogoutRequestString
     *              A Logout Request string.
     *
     * @return the issuer of the logout request
     *
     *
     */
    public static String getIssuer(final String samlLogoutRequestString) {
        return getIssuer(samlLogoutRequestString, false);
    }

    /**
     * Gets the Issuer from Logout Request String.
     *
     * @param samlLogoutRequestString
     *              A Logout Request string.
     * @param trim
     *              whether the extracted issuer value should be trimmed
     *
     * @return the issuer of the logout request
     *
     *
     */
    public static String getIssuer(final String samlLogoutRequestString, final boolean trim) {
        final Document doc = Util.loadXML(samlLogoutRequestString);
        return getIssuer(doc, trim);
    }

    /**
     * Gets the SessionIndexes from the LogoutRequest.
     *
     * @param samlLogoutRequestDocument
     *              A DOMDocument object loaded from the SAML Logout Request.
     * @return the SessionIndexes
     *
     *
     */
    public static List<String> getSessionIndexes(final Document samlLogoutRequestDocument) {
        return getSessionIndexes(samlLogoutRequestDocument, false);
    }

    /**
     * Gets the SessionIndexes from the LogoutRequest.
     *
     * @param samlLogoutRequestDocument
     *              A DOMDocument object loaded from the SAML Logout Request.
     * @param trim
     *              whether the extracted session indexes should be trimmed
     * @return the SessionIndexes
     *
     *
     */
    public static List<String> getSessionIndexes(final Document samlLogoutRequestDocument, final boolean trim) {
        final List<String> sessionIndexes = new ArrayList<>();

        final NodeList nodes = Util.query(samlLogoutRequestDocument, "/samlp:LogoutRequest/samlp:SessionIndex");

        for (int i = 0; i < nodes.getLength(); i++) {
            String sessionIndex = nodes.item(i).getTextContent();
            if (sessionIndex != null) {
                if (trim) {
                    sessionIndex = sessionIndex.trim();
                }
                sessionIndexes.add(sessionIndex);
            }
        }

        return sessionIndexes;
    }

    /**
     * Gets the SessionIndexes from the LogoutRequest.
     *
     * @param samlLogoutRequestString
     *              A Logout Request string.
     * @return the SessionIndexes
     *
     *
     */
    public static List<String> getSessionIndexes(final String samlLogoutRequestString) {
        return getSessionIndexes(samlLogoutRequestString, false);
    }

    /**
     * Gets the SessionIndexes from the LogoutRequest.
     *
     * @param samlLogoutRequestString
     *              A Logout Request string.
     * @param trim
     *              whether the extracted session indexes should be trimmed
     * @return the SessionIndexes
     *
     *
     */
    public static List<String> getSessionIndexes(final String samlLogoutRequestString, final boolean trim) {
        final Document doc = Util.loadXML(samlLogoutRequestString);
        return getSessionIndexes(doc, trim);
    }

    /**
     * After execute a validation process, if fails this method returns the cause
     *
     * @return the cause of the validation error
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
     * Sets the validation exception that this {@link LogoutRequest} should return
     * when a validation error occurs.
     *
     * @param validationException
     *              the validation exception to set
     */
    protected void setValidationException(final Exception validationException) {
        this.validationException = validationException;
    }

    /**
     * @return the ID of the Logout Request
     */
    public String getId() {
        return id;
    }

    /**
     * Returns the issue instant of this message.
     *
     * @return a new {@link Calendar} instance carrying the issue instant of this message
     */
    public Calendar getIssueInstant() {
        return issueInstant == null ? null : (Calendar) issueInstant.clone();
    }
}
