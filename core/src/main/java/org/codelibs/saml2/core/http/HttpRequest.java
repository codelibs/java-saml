package org.codelibs.saml2.core.http;

import static java.util.Collections.unmodifiableList;
import static java.util.Collections.unmodifiableMap;
import static org.codelibs.saml2.core.util.Preconditions.checkNotNull;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.codelibs.saml2.core.util.Util;

/**
 * Framework-agnostic representation of an HTTP request.
 *
 * @since 2.0.0
 */
public final class HttpRequest {

    public static final Map<String, List<String>> EMPTY_PARAMETERS = Collections.<String, List<String>> emptyMap();

    private final String requestURL;
    private final Map<String, List<String>> parameters;
    private final String queryString;

    /**
     * Creates a new HttpRequest.
     *
     * @param requestURL the request URL (up to but not including query parameters)
     * @deprecated Not providing a queryString can cause HTTP Redirect binding to fail.
     */
    @Deprecated
    public HttpRequest(final String requestURL) {
        this(requestURL, EMPTY_PARAMETERS);
    }

    /**
     * Creates a new HttpRequest.
     *
     * @param requestURL  the request URL (up to but not including query parameters)
     * @param queryString string that is contained in the request URL after the path
     */
    public HttpRequest(final String requestURL, final String queryString) {
        this(requestURL, EMPTY_PARAMETERS, queryString);
    }

    /**
     * Creates a new HttpRequest.
     *
     * @param requestURL  the request URL (up to but not including query parameters)
     * @param parameters the request query parameters
     * @deprecated Not providing a queryString can cause HTTP Redirect binding to fail.
     */
    @Deprecated
    public HttpRequest(final String requestURL, final Map<String, List<String>> parameters) {
        this(requestURL, parameters, null);
    }

    /**
     * Creates a new HttpRequest.
     *
     * @param requestURL  the request URL (up to but not including query parameters)
     * @param parameters the request query parameters
     * @param queryString string that is contained in the request URL after the path
     */
    public HttpRequest(final String requestURL, final Map<String, List<String>> parameters, final String queryString) {
        this.requestURL = checkNotNull(requestURL, "requestURL");
        this.parameters = unmodifiableCopyOf(checkNotNull(parameters, "queryParams"));
        this.queryString = StringUtils.trimToEmpty(queryString);
    }

    /**
     * @param name  the query parameter name
     * @param value the query parameter value
     * @return a new HttpRequest with the given query parameter added
     */
    public HttpRequest addParameter(final String name, final String value) {
        checkNotNull(name, "name");
        checkNotNull(value, "value");

        final List<String> oldValues = parameters.containsKey(name) ? parameters.get(name) : new ArrayList<>();
        final List<String> newValues = new ArrayList<>(oldValues);
        newValues.add(value);
        final Map<String, List<String>> params = new HashMap<>(parameters);
        params.put(name, newValues);

        return new HttpRequest(requestURL, params, queryString);
    }

    /**
     * @param name  the query parameter name
     * @return a new HttpRequest with the given query parameter removed
     */
    public HttpRequest removeParameter(final String name) {
        checkNotNull(name, "name");

        final Map<String, List<String>> params = new HashMap<>(parameters);
        params.remove(name);

        return new HttpRequest(requestURL, params, queryString);
    }

    /**
     * The URL the client used to make the request. Includes a protocol, server name, port number, and server path, but
     * not the query string parameters.
     *
     * @return the request URL
     */
    public String getRequestURL() {
        return requestURL;
    }

    /**
     * @param name the query parameter name
     * @return the first value for the parameter, or null
     */
    public String getParameter(final String name) {
        final List<String> values = getParameters(name);
        return values.isEmpty() ? null : values.get(0);
    }

    /**
     * @param name the query parameter name
     * @return a List containing all values for the parameter
     */
    public List<String> getParameters(final String name) {
        final List<String> values = parameters.get(name);
        return values != null ? values : Collections.<String> emptyList();
    }

    /**
     * @return a map of all query parameters
     */
    public Map<String, List<String>> getParameters() {
        return parameters;
    }

    /**
     * Return an url encoded get parameter value
     * Prefer to extract the original encoded value directly from queryString since url
     * encoding is not canonical.
     *
     * @param name
     * @return the first value for the parameter, or null
     */
    public String getEncodedParameter(final String name) {
        final Matcher matcher = Pattern.compile(Pattern.quote(name) + "=([^&#]+)").matcher(queryString);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return Util.urlEncoder(getParameter(name));
    }

    /**
     * Return an url encoded get parameter value
     * Prefer to extract the original encoded value directly from queryString since url
     * encoding is not canonical.
     *
     * @param name
     * @param defaultValue
     * @return the first value for the parameter, or url encoded default value
     */
    public String getEncodedParameter(final String name, final String defaultValue) {
        final String value = getEncodedParameter(name);
        return (value != null ? value : Util.urlEncoder(defaultValue));
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }

        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        final HttpRequest that = (HttpRequest) o;
        return Objects.equals(requestURL, that.requestURL) && Objects.equals(parameters, that.parameters)
                && Objects.equals(queryString, that.queryString);
    }

    @Override
    public int hashCode() {
        return Objects.hash(requestURL, parameters, queryString);
    }

    @Override
    public String toString() {
        return "HttpRequest{" + "requestURL='" + requestURL + '\'' + ", parameters=" + parameters + ", queryString=" + queryString + '}';
    }

    private static Map<String, List<String>> unmodifiableCopyOf(final Map<String, List<String>> orig) {
        final Map<String, List<String>> copy = new HashMap<>();
        for (final Map.Entry<String, List<String>> entry : orig.entrySet()) {
            copy.put(entry.getKey(), unmodifiableList(new ArrayList<>(entry.getValue())));
        }

        return unmodifiableMap(copy);
    }

}
