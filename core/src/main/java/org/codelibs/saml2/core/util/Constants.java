package org.codelibs.saml2.core.util;

/**
 * Constants class of Java Toolkit.
 *
 * A class that contains several constants related to the SAML protocol
 */
public final class Constants {
    /**
     * Value added to the current time in time condition validations.
     * Default is 2 minutes (120 seconds) to balance between clock synchronization tolerance
     * and security against replay attacks.
     */
    public static final long ALLOWED_CLOCK_DRIFT = 120L; // 2 min in seconds

    /**
     * Value added to the current time in time condition validations.
     * Default is 2 minutes (120 seconds) to balance between clock synchronization tolerance
     * and security against replay attacks.
     *
     * @deprecated Typo in name. Use {@link #ALLOWED_CLOCK_DRIFT} instead.
     */
    @Deprecated
    public static final long ALOWED_CLOCK_DRIFT = ALLOWED_CLOCK_DRIFT;

    // NameID Formats
    /** SAML 1.1 email address NameID format URN. */
    public static final String NAMEID_EMAIL_ADDRESS = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
    /** SAML 1.1 X.509 subject name NameID format URN. */
    public static final String NAMEID_X509_SUBJECT_NAME = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName";
    /** SAML 1.1 Windows domain qualified name NameID format URN. */
    public static final String NAMEID_WINDOWS_DOMAIN_QUALIFIED_NAME =
            "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName";
    /** SAML 1.1 unspecified NameID format URN. */
    public static final String NAMEID_UNSPECIFIED = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
    /** SAML 2.0 Kerberos principal name NameID format URN. */
    public static final String NAMEID_KERBEROS = "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos";
    /** SAML 2.0 entity identifier NameID format URN. */
    public static final String NAMEID_ENTITY = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";
    /** SAML 2.0 transient NameID format URN. */
    public static final String NAMEID_TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
    /** SAML 2.0 persistent NameID format URN. */
    public static final String NAMEID_PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
    /** SAML 2.0 encrypted NameID format URN. */
    public static final String NAMEID_ENCRYPTED = "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted";

    // Attribute Name Formats
    /** SAML 2.0 unspecified attribute name format URN. */
    public static final String ATTRNAME_FORMAT_UNSPECIFIED = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified";
    /** SAML 2.0 URI reference attribute name format URN. */
    public static final String ATTRNAME_FORMAT_URI = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";
    /** SAML 2.0 basic attribute name format URN. */
    public static final String ATTRNAME_FORMAT_BASIC = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";

    // Namespaces
    /** XML namespace URI for SAML 2.0 assertions. */
    public static final String NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion";
    /** XML namespace URI for the SAML 2.0 protocol. */
    public static final String NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol";
    /** XML namespace URI for the SOAP envelope. */
    public static final String NS_SOAP = "http://schemas.xmlsoap.org/soap/envelope/";
    /** XML namespace URI for SAML 2.0 metadata. */
    public static final String NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    /** XML namespace URI for XML Schema. */
    public static final String NS_XS = "http://www.w3.org/2001/XMLSchema";
    /** XML namespace URI for XML Schema instances. */
    public static final String NS_XSI = "http://www.w3.org/2001/XMLSchema-instance";
    /** XML namespace URI for XML Encryption. */
    public static final String NS_XENC = "http://www.w3.org/2001/04/xmlenc#";
    /** XML namespace URI for XML Digital Signature. */
    public static final String NS_DS = "http://www.w3.org/2000/09/xmldsig#";

    // Bindings
    /** SAML 2.0 HTTP-POST binding URN. */
    public static final String BINDING_HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
    /** SAML 2.0 HTTP-Redirect binding URN. */
    public static final String BINDING_HTTP_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
    /** SAML 2.0 HTTP-Artifact binding URN. */
    public static final String BINDING_HTTP_ARTIFACT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact";
    /** SAML 2.0 SOAP binding URN. */
    public static final String BINDING_SOAP = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";
    /** SAML 2.0 DEFLATE URL-encoding binding URN. */
    public static final String BINDING_DEFLATE = "urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE";

    // Auth Context Class
    /** SAML 2.0 unspecified authentication context class URN. */
    public static final String AC_UNSPECIFIED = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";
    /** SAML 2.0 password authentication context class URN. */
    public static final String AC_PASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password";
    /** SAML 2.0 X.509 certificate authentication context class URN. */
    public static final String AC_X509 = "urn:oasis:names:tc:SAML:2.0:ac:classes:X509";
    /** SAML 2.0 smart card authentication context class URN. */
    public static final String AC_SMARTCARD = "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard";
    /** SAML 2.0 Kerberos authentication context class URN. */
    public static final String AC_KERBEROS = "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos";

    // Subject Confirmation
    /** SAML 2.0 bearer subject confirmation method URN. */
    public static final String CM_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
    /** SAML 2.0 holder-of-key subject confirmation method URN. */
    public static final String CM_HOLDER_KEY = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key";
    /** SAML 2.0 sender-vouches subject confirmation method URN. */
    public static final String CM_SENDER_VOUCHES = "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches";

    // Status Codes
    /** SAML 2.0 top-level status code indicating success. */
    public static final String STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    /** SAML 2.0 top-level status code indicating an error caused by the requester. */
    public static final String STATUS_REQUESTER = "urn:oasis:names:tc:SAML:2.0:status:Requester";
    /** SAML 2.0 top-level status code indicating an error caused by the responder. */
    public static final String STATUS_RESPONDER = "urn:oasis:names:tc:SAML:2.0:status:Responder";
    /** SAML 2.0 top-level status code indicating a SAML version mismatch. */
    public static final String STATUS_VERSION_MISMATCH = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch";

    // Status Second-level Codes
    /** SAML 2.0 second-level status code indicating authentication failure. */
    public static final String STATUS_AUTHNFAILED = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed";
    /** SAML 2.0 second-level status code indicating an invalid attribute name or value. */
    public static final String STATUS_INVALID_ATTRNAME_OR_VALUE = "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue";
    /** SAML 2.0 second-level status code indicating an invalid NameID policy. */
    public static final String STATUS_INVALID_NAMEIDPOLICY = "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy";
    /** SAML 2.0 second-level status code indicating no matching authentication context. */
    public static final String STATUS_NO_AUTHNCONTEXT = "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext";
    /** SAML 2.0 second-level status code indicating no available identity provider. */
    public static final String STATUS_NO_AVAILABLE_IDP = "urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP";
    /** SAML 2.0 second-level status code indicating passive authentication was not possible. */
    public static final String STATUS_NO_PASSIVE = "urn:oasis:names:tc:SAML:2.0:status:NoPassive";
    /** SAML 2.0 second-level status code indicating no supported identity provider. */
    public static final String STATUS_NO_SUPPORTED_IDP = "urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP";
    /** SAML 2.0 second-level status code indicating a partial logout. */
    public static final String STATUS_PARTIAL_LOGOUT = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout";
    /** SAML 2.0 second-level status code indicating the proxy count was exceeded. */
    public static final String STATUS_PROXY_COUNT_EXCEEDED = "urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded";
    /** SAML 2.0 second-level status code indicating the request was denied. */
    public static final String STATUS_REQUEST_DENIED = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied";
    /** SAML 2.0 second-level status code indicating the request is unsupported. */
    public static final String STATUS_REQUEST_UNSUPPORTED = "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported";
    /** SAML 2.0 second-level status code indicating the request version is deprecated. */
    public static final String STATUS_REQUEST_VERSION_DEPRECATED = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated";
    /** SAML 2.0 second-level status code indicating the request version is too high. */
    public static final String STATUS_REQUEST_VERSION_TOO_HIGH = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh";
    /** SAML 2.0 second-level status code indicating the request version is too low. */
    public static final String STATUS_REQUEST_VERSION_TOO_LOW = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow";
    /** SAML 2.0 second-level status code indicating the resource was not recognized. */
    public static final String STATUS_RESOURCE_NOT_RECOGNIZED = "urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized";
    /** SAML 2.0 second-level status code indicating too many responses. */
    public static final String STATUS_TOO_MANY_RESPONSES = "urn:oasis:names:tc:SAML:2.0:status:TooManyResponses";
    /** SAML 2.0 second-level status code indicating an unknown attribute profile. */
    public static final String STATUS_UNKNOWN_ATTR_PROFILE = "urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile";
    /** SAML 2.0 second-level status code indicating an unknown principal. */
    public static final String STATUS_UNKNOWN_PRINCIPAL = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal";
    /** SAML 2.0 second-level status code indicating an unsupported binding. */
    public static final String STATUS_UNSUPPORTED_BINDING = "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding";

    // Contact types
    /** Metadata contact type for technical contacts. */
    public static final String CONTACT_TYPE_TECHNICAL = "technical";
    /** Metadata contact type for support contacts. */
    public static final String CONTACT_TYPE_SUPPORT = "support";
    /** Metadata contact type for administrative contacts. */
    public static final String CONTACT_TYPE_ADMINISTRATIVE = "administrative";
    /** Metadata contact type for billing contacts. */
    public static final String CONTACT_TYPE_BILLING = "billing";
    /** Metadata contact type for other contacts. */
    public static final String CONTACT_TYPE_OTHER = "other";

    // Canonization
    /** Exclusive XML canonicalization 1.0 algorithm URI (without comments). */
    public static final String C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    /** Inclusive XML canonicalization 1.0 algorithm URI with comments. */
    public static final String C14N_WC = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
    /** Inclusive XML canonicalization 1.1 algorithm URI (without comments). */
    public static final String C14N11 = "http://www.w3.org/2006/12/xml-c14n11";
    /** Inclusive XML canonicalization 1.1 algorithm URI with comments. */
    public static final String C14N11_WC = "http://www.w3.org/2006/12/xml-c14n11#WithComments";
    /** Exclusive XML canonicalization algorithm URI (without comments). */
    public static final String C14NEXC = "http://www.w3.org/2001/10/xml-exc-c14n#";
    /** Exclusive XML canonicalization algorithm URI with comments. */
    public static final String C14NEXC_WC = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";

    // Sign & Crypt
    // https://www.w3.org/TR/xmlenc-core/#sec-Alg-MessageDigest
    // https://www.w3.org/TR/xmlsec-algorithms/#signature-method-uris
    // https://tools.ietf.org/html/rfc6931
    /** SHA-1 digest algorithm URI. */
    public static final String SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";
    /** SHA-256 digest algorithm URI. */
    public static final String SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
    /** SHA-384 digest algorithm URI. */
    public static final String SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";
    /** SHA-512 digest algorithm URI. */
    public static final String SHA512 = "http://www.w3.org/2001/04/xmlenc#sha512";

    /** DSA with SHA-1 signature algorithm URI. */
    public static final String DSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#dsa-sha1";
    /** RSA with SHA-1 signature algorithm URI. */
    public static final String RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    /** RSA with SHA-256 signature algorithm URI. */
    public static final String RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    /** RSA with SHA-384 signature algorithm URI. */
    public static final String RSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
    /** RSA with SHA-512 signature algorithm URI. */
    public static final String RSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";

    /** Triple DES in CBC mode block-encryption algorithm URI. */
    public static final String TRIPLEDES_CBC = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc";
    /** AES-128 in CBC mode block-encryption algorithm URI. */
    public static final String AES128_CBC = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
    /** AES-192 in CBC mode block-encryption algorithm URI. */
    public static final String AES192_CBC = "http://www.w3.org/2001/04/xmlenc#aes192-cbc";
    /** AES-256 in CBC mode block-encryption algorithm URI. */
    public static final String AES256_CBC = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
    /** AES-128 key wrap algorithm URI. */
    public static final String A128KW = "http://www.w3.org/2001/04/xmlenc#kw-aes128";
    /** AES-192 key wrap algorithm URI. */
    public static final String A192KW = "http://www.w3.org/2001/04/xmlenc#kw-aes192";
    /** AES-256 key wrap algorithm URI. */
    public static final String A256KW = "http://www.w3.org/2001/04/xmlenc#kw-aes256";
    /** RSA v1.5 key transport algorithm URI. */
    public static final String RSA_1_5 = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
    /** RSA-OAEP with MGF1-SHA1 key transport algorithm URI. */
    public static final String RSA_OAEP_MGF1P = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";

    /** Enveloped signature transform algorithm URI. */
    public static final String ENVSIG = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

    private Constants() {
        //not called
    }

}
