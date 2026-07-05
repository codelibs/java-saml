<%@page import="java.util.List,org.codelibs.saml2.Auth,org.codelibs.saml2.core.settings.Saml2Settings" language="java" contentType="application/xhtml+xml"%><%
Auth auth = new Auth();
Saml2Settings settings = auth.getSettings();
settings.setSPValidationOnly(true);
List<String> errors = settings.checkSettings();

if (errors.isEmpty()) {
        String metadata = settings.getSPMetadata();
	out.println(metadata);
} else {
	response.setContentType("text/html; charset=UTF-8");

	for (String error : errors) {
	    out.println("<p>"+error+"</p>");
	}
}%>
