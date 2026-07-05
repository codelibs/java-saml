package org.codelibs.saml2.core.settings;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Map;

import org.codelibs.saml2.core.exception.SAMLSevereException;
import org.codelibs.saml2.core.exception.SAMLSignatureException;
import org.codelibs.saml2.core.exception.XMLParsingException;
import org.codelibs.saml2.core.util.Constants;
import org.codelibs.saml2.core.util.Util;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

/**
 * IdPMetadataParser class of Java Toolkit.
 *
 * A class that implements the settings parser from IdP Metadata
 *
 * This class does not validate in any way the URL that is introduced,
 * make sure to validate it properly before use it in a get_metadata method.
 *
 * <p><b>Security note on {@code trustedSigningCert} overloads:</b> the overloads of
 * {@code parseXML}/{@code parseFileXML}/{@code parseRemoteXML} that accept a trailing
 * {@link X509Certificate} verify that the fetched metadata document is signed by that
 * certificate before parsing it. That certificate MUST be provisioned out-of-band
 * (e.g. from pinned configuration or a local keystore) and MUST NOT be extracted from
 * the very same metadata document being validated. Extracting the trust anchor from the
 * document under validation only protects against transport-level corruption; it does
 * nothing to detect a MITM attacker or a compromised source serving a self-consistent
 * forged document, since the attacker would simply embed their own certificate alongside
 * their own signature.
 */
public class IdPMetadataParser {

    /**
     * Default constructor.
     */
    public IdPMetadataParser() {
    }

    /**
     * Get IdP Metadata Info from XML Document
     *
     * @param xmlDocument
     *            XML document hat contains IdP metadata
     * @param entityId
     *            Entity Id of the desired IdP, if no entity Id is provided and the XML metadata contains more than one IDPSSODescriptor, the first is returned
     * @param desiredNameIdFormat
     *            If available on IdP metadata, use that nameIdFormat
     * @param desiredSSOBinding
     *            Parse specific binding SSO endpoint.
     * @param desiredSLOBinding
     *            Parse specific binding SLO endpoint.
     *
     * @return Mapped values with metadata info in Saml2Settings format
     */
    public static Map<String, Object> parseXML(final Document xmlDocument, final String entityId, final String desiredNameIdFormat,
            final String desiredSSOBinding, final String desiredSLOBinding) {
        final Map<String, Object> metadataInfo = new LinkedHashMap<>();

        String customIdpStr = "";
        if (entityId != null && !entityId.isEmpty()) {
            customIdpStr = "[@entityID=\"" + entityId + "\"]";
        }

        final String idpDescriptorXPath = "//md:EntityDescriptor" + customIdpStr + "/md:IDPSSODescriptor";

        final NodeList idpDescriptorNodes = Util.query(xmlDocument, idpDescriptorXPath);

        if (idpDescriptorNodes.getLength() > 0) {

            final Node idpDescriptorNode = idpDescriptorNodes.item(0);
            String resolvedEntityId = entityId;
            if (resolvedEntityId == null || resolvedEntityId.isEmpty()) {
                final Node entityIdNode = idpDescriptorNode.getParentNode().getAttributes().getNamedItem("entityID");
                if (entityIdNode != null) {
                    resolvedEntityId = entityIdNode.getNodeValue();
                }
            }

            if (resolvedEntityId != null && !resolvedEntityId.isEmpty()) {
                metadataInfo.put(SettingsBuilder.IDP_ENTITYID_PROPERTY_KEY, resolvedEntityId);
            }

            NodeList ssoNodes =
                    Util.query(xmlDocument, "./md:SingleSignOnService[@Binding=\"" + desiredSSOBinding + "\"]", idpDescriptorNode);
            if (ssoNodes.getLength() < 1) {
                ssoNodes = Util.query(xmlDocument, "./md:SingleSignOnService", idpDescriptorNode);
            }
            if (ssoNodes.getLength() > 0) {
                final NamedNodeMap ssoAttributes = ssoNodes.item(0).getAttributes();
                metadataInfo.put(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_URL_PROPERTY_KEY,
                        ssoAttributes.getNamedItem("Location").getNodeValue());
                metadataInfo.put(SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_BINDING_PROPERTY_KEY,
                        ssoAttributes.getNamedItem("Binding").getNodeValue());
            }

            NodeList sloNodes =
                    Util.query(xmlDocument, "./md:SingleLogoutService[@Binding=\"" + desiredSLOBinding + "\"]", idpDescriptorNode);
            if (sloNodes.getLength() < 1) {
                sloNodes = Util.query(xmlDocument, "./md:SingleLogoutService", idpDescriptorNode);
            }
            if (sloNodes.getLength() > 0) {
                final NamedNodeMap sloAttributes = sloNodes.item(0).getAttributes();
                metadataInfo.put(SettingsBuilder.IDP_SINGLE_LOGOUT_SERVICE_URL_PROPERTY_KEY,
                        sloAttributes.getNamedItem("Location").getNodeValue());
                metadataInfo.put(SettingsBuilder.IDP_SINGLE_LOGOUT_SERVICE_BINDING_PROPERTY_KEY,
                        sloAttributes.getNamedItem("Binding").getNodeValue());
                final Node responseLocationNode = sloAttributes.getNamedItem("ResponseLocation");
                if (responseLocationNode != null) {
                    metadataInfo.put(SettingsBuilder.IDP_SINGLE_LOGOUT_SERVICE_RESPONSE_URL_PROPERTY_KEY,
                            responseLocationNode.getNodeValue());
                }
            }

            final NodeList keyDescriptorCertSigningNodes = Util.query(xmlDocument,
                    "./md:KeyDescriptor[not(contains(@use, \"encryption\"))]/ds:KeyInfo/ds:X509Data/ds:X509Certificate", idpDescriptorNode);

            final NodeList keyDescriptorCertEncryptionNodes = Util.query(xmlDocument,
                    "./md:KeyDescriptor[not(contains(@use, \"signing\"))]/ds:KeyInfo/ds:X509Data/ds:X509Certificate", idpDescriptorNode);

            if (keyDescriptorCertSigningNodes.getLength() > 0 || keyDescriptorCertEncryptionNodes.getLength() > 0) {

                final boolean hasEncryptionCert = keyDescriptorCertEncryptionNodes.getLength() > 0;
                String encryptionCert = null;

                if (hasEncryptionCert) {
                    encryptionCert = keyDescriptorCertEncryptionNodes.item(0).getTextContent();
                    metadataInfo.put(SettingsBuilder.IDP_X509CERT_PROPERTY_KEY, encryptionCert);
                }

                if (keyDescriptorCertSigningNodes.getLength() > 0) {
                    int index = 0;
                    for (int i = 0; i < keyDescriptorCertSigningNodes.getLength(); i++) {
                        final String signingCert = keyDescriptorCertSigningNodes.item(i).getTextContent();
                        if (i == 0 && !hasEncryptionCert) {
                            metadataInfo.put(SettingsBuilder.IDP_X509CERT_PROPERTY_KEY, signingCert);
                        } else if (!hasEncryptionCert || !encryptionCert.equals(signingCert)) {
                            metadataInfo.put(SettingsBuilder.IDP_X509CERTMULTI_PROPERTY_KEY + "." + index, signingCert);
                            index++;
                        }
                    }
                }
            }

            final NodeList nameIdFormatNodes = Util.query(xmlDocument, "./md:NameIDFormat", idpDescriptorNode);
            for (int i = 0; i < nameIdFormatNodes.getLength(); i++) {
                final String nameIdFormat = nameIdFormatNodes.item(i).getTextContent();
                if (nameIdFormat != null && (desiredNameIdFormat == null || desiredNameIdFormat.equals(nameIdFormat))) {
                    metadataInfo.put(SettingsBuilder.SP_NAMEIDFORMAT_PROPERTY_KEY, nameIdFormat);
                    break;
                }
            }
        }

        return metadataInfo;
    }

    /**
     * Get IdP Metadata Info from XML Document, verifying beforehand that the document is signed
     * by the given trusted certificate.
     *
     * <p><b>Security note:</b> {@code trustedSigningCert} MUST be provisioned out-of-band (e.g.
     * pinned configuration or a local keystore entry), NOT extracted from the same metadata
     * document being validated here. Using a certificate embedded in the document under
     * validation only detects transport corruption, not a MITM attacker or a compromised source
     * serving a self-consistent forged document (which would simply embed its own certificate
     * alongside its own signature).
     *
     * @param xmlDocument
     *            XML document hat contains IdP metadata
     * @param entityId
     *            Entity Id of the desired IdP, if no entity Id is provided and the XML metadata contains more than one IDPSSODescriptor, the first is returned
     * @param desiredNameIdFormat
     *            If available on IdP metadata, use that nameIdFormat
     * @param desiredSSOBinding
     *            Parse specific binding SSO endpoint.
     * @param desiredSLOBinding
     *            Parse specific binding SLO endpoint.
     * @param trustedSigningCert
     *            the out-of-band trusted certificate the metadata document must be signed with; if {@code null} no signature check is performed
     *
     * @return Mapped values with metadata info in Saml2Settings format
     *
     * @throws SAMLSignatureException if {@code trustedSigningCert} is not {@code null} and the metadata document signature does not validate against it
     */
    public static Map<String, Object> parseXML(final Document xmlDocument, final String entityId, final String desiredNameIdFormat,
            final String desiredSSOBinding, final String desiredSLOBinding, final X509Certificate trustedSigningCert) {
        if (trustedSigningCert != null && !Util.validateMetadataSign(xmlDocument, trustedSigningCert, null, null)) {
            throw new SAMLSignatureException("Metadata signature validation failed (entityId=" + entityId + ")");
        }
        return parseXML(xmlDocument, entityId, desiredNameIdFormat, desiredSSOBinding, desiredSLOBinding);
    }

    /**
     * Get IdP Metadata Info from XML Document
     *
     * @param xmlDocument
     *            XML document that contains IdP metadata
     * @param entityId
     *            Entity Id of the desired IdP, if no entity Id is provided and the XML metadata contains more than one IDPSSODescriptor, the first is returned
     *
     * @return Mapped values with metadata info in Saml2Settings format
     *
     */
    public static Map<String, Object> parseXML(final Document xmlDocument, final String entityId) {
        return parseXML(xmlDocument, entityId, null, Constants.BINDING_HTTP_REDIRECT, Constants.BINDING_HTTP_REDIRECT);
    }

    /**
     * Get IdP Metadata Info from XML Document
     *
     * @param xmlDocument
     *            XML document that contains IdP metadata
     *
     * @return Mapped values with metadata info in Saml2Settings format
     *
     */
    public static Map<String, Object> parseXML(final Document xmlDocument) {
        return parseXML(xmlDocument, null);
    }

    /**
     * Get IdP Metadata Info from XML file
     *
     * @param xmlFileName
     *            Filename of the XML filename that contains IdP metadata
     * @param entityId
     *            Entity Id of the desired IdP, if no entity Id is provided and the XML metadata contains more than one IDPSSODescriptor, the first is returned
     * @param desiredNameIdFormat
     *            If available on IdP metadata, use that nameIdFormat
     * @param desiredSSOBinding
     *            Parse specific binding SSO endpoint.
     * @param desiredSLOBinding
     *            Parse specific binding SLO endpoint.
     *
     * @return Mapped values with metadata info in Saml2Settings format
     *
     */
    public static Map<String, Object> parseFileXML(final String xmlFileName, final String entityId, final String desiredNameIdFormat,
            final String desiredSSOBinding, final String desiredSLOBinding) {
        final ClassLoader classLoader = IdPMetadataParser.class.getClassLoader();
        try (InputStream inputStream = classLoader.getResourceAsStream(xmlFileName)) {
            if (inputStream != null) {
                final Document xmlDocument = Util.parseXML(new InputSource(inputStream));
                return parseXML(xmlDocument, entityId, desiredNameIdFormat, desiredSSOBinding, desiredSLOBinding);
            }
        } catch (final Exception e) {
            final String errorMsg = "XML file'" + xmlFileName + "' cannot be loaded." + e.getMessage();
            throw new SAMLSevereException(errorMsg, SAMLSevereException.SETTINGS_FILE_NOT_FOUND, e);
        }
        throw new SAMLSevereException("XML file '" + xmlFileName + "' not found in the classpath",
                SAMLSevereException.SETTINGS_FILE_NOT_FOUND);
    }

    /**
     * Get IdP Metadata Info from XML file, verifying beforehand that the document is signed by
     * the given trusted certificate.
     *
     * <p><b>Security note:</b> {@code trustedSigningCert} MUST be provisioned out-of-band (e.g.
     * pinned configuration or a local keystore entry), NOT extracted from the same metadata
     * document being validated here. See {@link #parseXML(Document, String, String, String, String, X509Certificate)}
     * for details.
     *
     * @param xmlFileName
     *            Filename of the XML filename that contains IdP metadata
     * @param entityId
     *            Entity Id of the desired IdP, if no entity Id is provided and the XML metadata contains more than one IDPSSODescriptor, the first is returned
     * @param desiredNameIdFormat
     *            If available on IdP metadata, use that nameIdFormat
     * @param desiredSSOBinding
     *            Parse specific binding SSO endpoint.
     * @param desiredSLOBinding
     *            Parse specific binding SLO endpoint.
     * @param trustedSigningCert
     *            the out-of-band trusted certificate the metadata document must be signed with; if {@code null} no signature check is performed
     *
     * @return Mapped values with metadata info in Saml2Settings format
     *
     * @throws SAMLSignatureException if {@code trustedSigningCert} is not {@code null} and the metadata document signature does not validate against it
     */
    public static Map<String, Object> parseFileXML(final String xmlFileName, final String entityId, final String desiredNameIdFormat,
            final String desiredSSOBinding, final String desiredSLOBinding, final X509Certificate trustedSigningCert) {
        final ClassLoader classLoader = IdPMetadataParser.class.getClassLoader();
        try (InputStream inputStream = classLoader.getResourceAsStream(xmlFileName)) {
            if (inputStream != null) {
                final Document xmlDocument = Util.parseXML(new InputSource(inputStream));
                return parseXML(xmlDocument, entityId, desiredNameIdFormat, desiredSSOBinding, desiredSLOBinding, trustedSigningCert);
            }
        } catch (final SAMLSignatureException e) {
            throw e;
        } catch (final Exception e) {
            final String errorMsg = "XML file'" + xmlFileName + "' cannot be loaded." + e.getMessage();
            throw new SAMLSevereException(errorMsg, SAMLSevereException.SETTINGS_FILE_NOT_FOUND, e);
        }
        throw new SAMLSevereException("XML file '" + xmlFileName + "' not found in the classpath",
                SAMLSevereException.SETTINGS_FILE_NOT_FOUND);
    }

    /**
     * Get IdP Metadata Info from XML file, verifying beforehand that the document is signed by
     * the given trusted certificate. Shorthand for
     * {@link #parseFileXML(String, String, String, String, String, X509Certificate)} with
     * {@code entityId=null}, {@code desiredNameIdFormat=null} and both bindings set to
     * {@link Constants#BINDING_HTTP_REDIRECT}.
     *
     * <p><b>Security note:</b> {@code trustedSigningCert} MUST be provisioned out-of-band, NOT
     * extracted from the same metadata document being validated here. See
     * {@link #parseXML(Document, String, String, String, String, X509Certificate)} for details.
     *
     * @param xmlFileName
     *            Filename of the XML filename that contains IdP metadata
     * @param trustedSigningCert
     *            the out-of-band trusted certificate the metadata document must be signed with; if {@code null} no signature check is performed
     *
     * @return Mapped values with metadata info in Saml2Settings format
     *
     * @throws SAMLSignatureException if {@code trustedSigningCert} is not {@code null} and the metadata document signature does not validate against it
     */
    public static Map<String, Object> parseFileXML(final String xmlFileName, final X509Certificate trustedSigningCert) {
        return parseFileXML(xmlFileName, null, null, Constants.BINDING_HTTP_REDIRECT, Constants.BINDING_HTTP_REDIRECT,
                trustedSigningCert);
    }

    /**
     * Get IdP Metadata Info from XML file
     *
     * @param xmlFileName
     *            Filename of the XML filename that contains IdP metadata
     * @param entityId
     *            Entity Id of the desired IdP, if no entity Id is provided and the XML metadata contains more than one IDPSSODescriptor, the first is returned
     *
     * @return Mapped values with metadata info in Saml2Settings format
     *
     */
    public static Map<String, Object> parseFileXML(final String xmlFileName, final String entityId) {
        return parseFileXML(xmlFileName, entityId, null, Constants.BINDING_HTTP_REDIRECT, Constants.BINDING_HTTP_REDIRECT);
    }

    /**
     * Get IdP Metadata Info from XML file
     *
     * @param xmlFileName
     *            Filename of the XML filename that contains IdP metadata
     *
     * @return Mapped values with metadata info in Saml2Settings format
     *
     */
    public static Map<String, Object> parseFileXML(final String xmlFileName) {
        return parseFileXML(xmlFileName, (String) null);
    }

    /**
     * Get IdP Metadata Info from XML file
     *
     * @param xmlURL
     *            URL to the XML document that contains IdP metadata
     * @param entityId
     *            Entity Id of the desired IdP, if no entity Id is provided and the XML metadata contains more than one IDPSSODescriptor, the first is returned
     * @param desiredNameIdFormat
     *            If available on IdP metadata, use that nameIdFormat
     * @param desiredSSOBinding
     *            Parse specific binding SSO endpoint.
     * @param desiredSLOBinding
     *            Parse specific binding SLO endpoint.
     *
     * @return Mapped values with metadata info in Saml2Settings format
     *
     */
    public static Map<String, Object> parseRemoteXML(final URL xmlURL, final String entityId, final String desiredNameIdFormat,
            final String desiredSSOBinding, final String desiredSLOBinding) {
        try (InputStream is = xmlURL.openStream()) {
            final Document xmlDocument = Util.parseXML(new InputSource(is));
            return parseXML(xmlDocument, entityId, desiredNameIdFormat, desiredSSOBinding, desiredSLOBinding);
        } catch (final IOException e) {
            throw new XMLParsingException("Failed to parse a remote XML: " + xmlURL, e);
        }
    }

    /**
     * Get IdP Metadata Info from XML file, verifying beforehand that the document is signed by
     * the given trusted certificate.
     *
     * <p><b>Security note:</b> {@code trustedSigningCert} MUST be provisioned out-of-band (e.g.
     * pinned configuration or a local keystore entry), NOT extracted from the same metadata
     * document being validated here. See {@link #parseXML(Document, String, String, String, String, X509Certificate)}
     * for details.
     *
     * @param xmlURL
     *            URL to the XML document that contains IdP metadata
     * @param entityId
     *            Entity Id of the desired IdP, if no entity Id is provided and the XML metadata contains more than one IDPSSODescriptor, the first is returned
     * @param desiredNameIdFormat
     *            If available on IdP metadata, use that nameIdFormat
     * @param desiredSSOBinding
     *            Parse specific binding SSO endpoint.
     * @param desiredSLOBinding
     *            Parse specific binding SLO endpoint.
     * @param trustedSigningCert
     *            the out-of-band trusted certificate the metadata document must be signed with; if {@code null} no signature check is performed
     *
     * @return Mapped values with metadata info in Saml2Settings format
     *
     * @throws SAMLSignatureException if {@code trustedSigningCert} is not {@code null} and the metadata document signature does not validate against it
     */
    public static Map<String, Object> parseRemoteXML(final URL xmlURL, final String entityId, final String desiredNameIdFormat,
            final String desiredSSOBinding, final String desiredSLOBinding, final X509Certificate trustedSigningCert) {
        try (InputStream is = xmlURL.openStream()) {
            final Document xmlDocument = Util.parseXML(new InputSource(is));
            return parseXML(xmlDocument, entityId, desiredNameIdFormat, desiredSSOBinding, desiredSLOBinding, trustedSigningCert);
        } catch (final IOException e) {
            throw new XMLParsingException("Failed to parse a remote XML: " + xmlURL, e);
        }
    }

    /**
     * Get IdP Metadata Info from XML file, verifying beforehand that the document is signed by
     * the given trusted certificate. Shorthand for
     * {@link #parseRemoteXML(URL, String, String, String, String, X509Certificate)} with
     * {@code entityId=null}, {@code desiredNameIdFormat=null} and both bindings set to
     * {@link Constants#BINDING_HTTP_REDIRECT}.
     *
     * <p><b>Security note:</b> {@code trustedSigningCert} MUST be provisioned out-of-band, NOT
     * extracted from the same metadata document being validated here. See
     * {@link #parseXML(Document, String, String, String, String, X509Certificate)} for details.
     *
     * @param xmlURL
     *            URL to the XML document that contains IdP metadata
     * @param trustedSigningCert
     *            the out-of-band trusted certificate the metadata document must be signed with; if {@code null} no signature check is performed
     *
     * @return Mapped values with metadata info in Saml2Settings format
     *
     * @throws SAMLSignatureException if {@code trustedSigningCert} is not {@code null} and the metadata document signature does not validate against it
     */
    public static Map<String, Object> parseRemoteXML(final URL xmlURL, final X509Certificate trustedSigningCert) {
        return parseRemoteXML(xmlURL, null, null, Constants.BINDING_HTTP_REDIRECT, Constants.BINDING_HTTP_REDIRECT, trustedSigningCert);
    }

    /**
     * Get IdP Metadata Info from XML file
     *
     * @param xmlURL
     *            URL to the XML document that contains IdP metadata
     * @param entityId
     *            Entity Id of the desired IdP, if no entity Id is provided and the XML metadata contains more than one IDPSSODescriptor, the first is returned
     *
     * @return Mapped values with metadata info in Saml2Settings format
     *
     */
    public static Map<String, Object> parseRemoteXML(final URL xmlURL, final String entityId) {
        return parseRemoteXML(xmlURL, entityId, null, Constants.BINDING_HTTP_REDIRECT, Constants.BINDING_HTTP_REDIRECT);
    }

    /**
     * Get IdP Metadata Info from XML file
     *
     * @param xmlURL
     *            URL to the XML document that contains IdP metadata
     *
     * @return Mapped values with metadata info in Saml2Settings format
     *
     */
    public static Map<String, Object> parseRemoteXML(final URL xmlURL) {
        return parseRemoteXML(xmlURL, (String) null);
    }

    /**
     * Inject metadata info into Saml2Settings
     *
     * @param settings
     *            the Saml2Settings object
     * @param metadataInfo
     *            mapped values with metadata info in Saml2Settings format
     *
     * @return the Saml2Settings object with metadata info settings loaded
     */
    public static Saml2Settings injectIntoSettings(final Saml2Settings settings, final Map<String, Object> metadataInfo) {

        final SettingsBuilder settingsBuilder = new SettingsBuilder().fromValues(metadataInfo);
        settingsBuilder.build(settings);
        return settings;
    }

}
