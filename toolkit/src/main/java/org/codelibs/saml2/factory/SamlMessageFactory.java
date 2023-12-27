package org.codelibs.saml2.factory;

import org.codelibs.saml2.Auth;
import org.codelibs.saml2.core.authn.AuthnRequest;
import org.codelibs.saml2.core.authn.AuthnRequestParams;
import org.codelibs.saml2.core.authn.SamlResponse;
import org.codelibs.saml2.core.http.HttpRequest;
import org.codelibs.saml2.core.logout.LogoutRequest;
import org.codelibs.saml2.core.logout.LogoutRequestParams;
import org.codelibs.saml2.core.logout.LogoutResponse;
import org.codelibs.saml2.core.logout.LogoutResponseParams;
import org.codelibs.saml2.core.settings.Saml2Settings;

/**
 * Factory which can create all kind of SAML message objects.
 * <p>
 * One such factory is used by the {@link Auth} class to orchestrate login and
 * logout operations.
 * <p>
 * Default implementations for all creation methods are provided: they create
 * instances of the standard classes provided by the library. Any extension
 * class may simply override the desired creation methods in order to return
 * instances of custom extensions of those standard classes.
 */
public interface SamlMessageFactory {

    /**
     * Creates an {@link AuthnRequest} instance.
     * 
     * @param settings
     *              the settings
     * @param params
     *              the authentication request input parameters
     * @return the created {@link AuthnRequest} instance
     */
    default AuthnRequest createAuthnRequest(final Saml2Settings settings, final AuthnRequestParams params) {
        return new AuthnRequest(settings, params);
    }

    /**
     * Creates a {@link SamlResponse} instance.
     * 
     * @param settings
     *              the settings
     * @param request
     *              the HTTP request from which the response is to be extracted and
     *              parsed
     * @return the created {@link SamlResponse} instance
     *
     *               in case some error occurred while trying to create the
     *               {@link SamlResponse} instance
     */
    default SamlResponse createSamlResponse(final Saml2Settings settings, final HttpRequest request) {
        return new SamlResponse(settings, request);
    }

    /**
     * Creates a {@link LogoutRequest} instance for an outgoing request.
     * 
     * @param settings
     *              the settings
     * @param params
     *              the logout request input parameters
     * @return the created {@link LogoutRequest} instance
     */
    default LogoutRequest createOutgoingLogoutRequest(final Saml2Settings settings, final LogoutRequestParams params) {
        return new LogoutRequest(settings, params);
    }

    /**
     * Creates a {@link LogoutRequest} instance for an incoming request.
     * 
     * @param settings
     *              the settings
     * @param request
     *              the HTTP request from which the logout request is to be
     *              extracted and parsed
     * @return the created {@link LogoutRequest} instance
     *
     *               in case some error occurred while trying to create the
     *               {@link LogoutRequest} instance
     */
    default LogoutRequest createIncomingLogoutRequest(final Saml2Settings settings, final HttpRequest request) {
        return new LogoutRequest(settings, request);
    }

    /**
     * Creates a {@link LogoutResponse} instance for an outgoing response.
     * 
     * @param settings
     *              the settings
     * @param params
     *              the logout response input parameters
     * @return the created {@link LogoutResponse} instance
     */
    default LogoutResponse createOutgoingLogoutResponse(final Saml2Settings settings, final LogoutResponseParams params) {
        return new LogoutResponse(settings, params);
    }

    /**
     * Creates a {@link LogoutRequest} instance for an incoming response.
     * 
     * @param settings
     *              the settings
     * @param request
     *              the HTTP request from which the logout response is to be
     *              extracted and parsed
     * @return the created {@link LogoutResponse} instance
     *
     *               in case some error occurred while trying to create the
     *               {@link LogoutResponse} instance
     */
    default LogoutResponse createIncomingLogoutResponse(final Saml2Settings settings, final HttpRequest request) {
        return new LogoutResponse(settings, request);
    }
}