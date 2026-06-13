package org.codelibs.saml2.core.util;

import java.io.InputStream;
import java.net.URL;
import java.util.Locale;

import javax.xml.XMLConstants;
import javax.xml.validation.Schema;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSInput;
import org.w3c.dom.ls.LSResourceResolver;
import org.xml.sax.SAXException;

/**
 * SchemaFactory class of Java Toolkit.
 *
 * A class that read SAML schemas that will be used to validate XMLs of the Java Toolkit
 */
public abstract class SchemaFactory {

    /**
     * Private property to construct a logger for this class.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(SchemaFactory.class);

    private SchemaFactory() {
        //not called
    }

    /** URL of the SAML 2.0 metadata schema. */
    public static final URL SAML_SCHEMA_METADATA_2_0 = SchemaFactory.class.getResource("/schemas/saml-schema-metadata-2.0.xsd");
    /** URL of the SAML 2.0 protocol schema. */
    public static final URL SAML_SCHEMA_PROTOCOL_2_0 = SchemaFactory.class.getResource("/schemas/saml-schema-protocol-2.0.xsd");

    /**
     * Loads a {@link Schema} from the given URL, resolving referenced schemas and DTDs locally.
     *
     * @param schemaUrl the URL of the schema to load
     * @return the loaded schema
     * @throws SAXException if the schema cannot be parsed
     */
    public static Schema loadFromUrl(final URL schemaUrl) throws SAXException {
        final javax.xml.validation.SchemaFactory factory =
                javax.xml.validation.SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setResourceResolver(new LSResourceResolver() {

            private DOMImplementationLS ls;

            @Override
            public LSInput resolveResource(final String type, final String namespaceURI, final String publicId, final String systemId,
                    final String baseURI) {
                try {
                    if (namespaceURI != null) {
                        final LSInput result = switch (namespaceURI) {
                            case "urn:oasis:names:tc:SAML:2.0:assertion" -> getLocalResource("saml-schema-assertion-2.0.xsd");
                            case "urn:oasis:names:tc:SAML:2.0:ac" -> getLocalResource("saml-schema-authn-context-2.0.xsd");
                            case "urn:oasis:names:tc:SAML:2.0:metadata" -> getLocalResource("saml-schema-metadata-2.0.xsd");
                            case "urn:oasis:names:tc:SAML:2.0:protocol" -> getLocalResource("saml-schema-protocol-2.0.xsd");
                            case "urn:oasis:names:tc:SAML:metadata:attribute" -> getLocalResource("sstc-metadata-attr.xsd");
                            case "urn:oasis:names:tc:SAML:attribute:ext" -> getLocalResource("sstc-saml-attribute-ext.xsd");
                            case "urn:oasis:names:tc:SAML:metadata:algsupport" -> getLocalResource("sstc-saml-metadata-algsupport-v1.0.xsd");
                            case "urn:oasis:names:tc:SAML:metadata:ui" -> getLocalResource("sstc-saml-metadata-ui-v1.0.xsd");
                            case "http://www.w3.org/2001/04/xmlenc#" -> getLocalResource("xenc-schema.xsd");
                            case "http://www.w3.org/XML/1998/namespace" -> getLocalResource("xml.xsd");
                            case "http://www.w3.org/2000/09/xmldsig#" -> getLocalResource("xmldsig-core-schema.xsd");
                            default -> null;
                        };
                        if (result != null) {
                            return result;
                        }
                    }
                    if ("saml-schema-authn-context-types-2.0.xsd".equals(systemId)) {
                        return getLocalResource("saml-schema-authn-context-types-2.0.xsd");
                    }
                    if (publicId != null) {
                        final LSInput result = switch (publicId.toUpperCase(Locale.ROOT)) {
                            case "-//W3C//DTD XMLSCHEMA 200102//EN" -> getLocalResource("XMLSchema.dtd");
                            case "DATATYPES" -> getLocalResource("datatypes.dtd");
                            default -> null;
                        };
                        if (result != null) {
                            return result;
                        }
                    }
                } catch (final Throwable e) {
                    // fallback to standard behaviour in case of errors
                    LOGGER.warn("could not resolve schema or DTD locally, proceeding the standard way", e);
                }
                return null;
            }

            public LSInput getLocalResource(final String name) throws Exception {
                if (ls == null) {
                    final DOMImplementationRegistry registry = DOMImplementationRegistry.newInstance();
                    ls = (DOMImplementationLS) registry.getDOMImplementation("LS 3.0");
                }
                final InputStream inputStream = getClass().getResourceAsStream("/schemas/" + name);
                if (inputStream == null) {
                    return null;
                }
                final LSInput lsInput = ls.createLSInput();
                lsInput.setByteStream(inputStream);
                return lsInput;
            }
        });
        return factory.newSchema(schemaUrl);
    }
}
