<%@page import="org.codelibs.saml2.Auth"%>
<%@page import="java.util.Objects"%>
<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
</head>
<body>
	<%
		Auth auth = new Auth(request, response);

		String nameId = Objects.toString(session.getAttribute("nameId"), null);
		String nameIdFormat = Objects.toString(session.getAttribute("nameIdFormat"), null);
		String nameidNameQualifier = Objects.toString(session.getAttribute("nameidNameQualifier"), null);
		String nameidSPNameQualifier = Objects.toString(session.getAttribute("nameidSPNameQualifier"), null);
		String sessionIndex = Objects.toString(session.getAttribute("sessionIndex"), null);
		auth.logout(null, nameId, sessionIndex, nameIdFormat, nameidNameQualifier, nameidSPNameQualifier);
	%>
</body>
</html>
