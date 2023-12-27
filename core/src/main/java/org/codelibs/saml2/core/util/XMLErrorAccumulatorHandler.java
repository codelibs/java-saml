package org.codelibs.saml2.core.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;

public class XMLErrorAccumulatorHandler extends DefaultHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(XMLErrorAccumulatorHandler.class);
    private final List<SAXParseException> errors = new ArrayList<>();

    @Override
    public void error(final SAXParseException e) throws SAXException {
        errors.add(e);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("ErrorHandler#error: parsing xml: {}", e.getMessage());
        }
    }

    @Override
    public void fatalError(final SAXParseException e) throws SAXException {
        errors.add(e);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("ErrorHandler#fatalError: parsing xml: {}", e.getMessage());
        }
    }

    @Override
    public void warning(final SAXParseException e) throws SAXException {
        errors.add(e);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("ErrorHandler#warning: parsing xml: {}", e.getMessage());
        }
    }

    public List<SAXParseException> getErrorXML() {
        return Collections.unmodifiableList(errors);
    }

    public boolean hasError() {
        return !errors.isEmpty();
    }
}