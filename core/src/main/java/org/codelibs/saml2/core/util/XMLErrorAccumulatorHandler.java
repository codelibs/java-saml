package org.codelibs.saml2.core.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;

/**
 * SAX error handler that accumulates parsing errors, fatal errors and warnings
 * encountered while parsing an XML document.
 */
public class XMLErrorAccumulatorHandler extends DefaultHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(XMLErrorAccumulatorHandler.class);
    /**
     * The most errors that are kept. A message that is checked against a schema comes from an
     * anonymous sender, and a document with tens of thousands of invalid elements would otherwise
     * keep one exception per element, with its message, for the rest of the check. The first ones
     * say what is wrong with the document; the rest add nothing.
     */
    private static final int MAX_ERRORS = 100;
    private final List<SAXParseException> errors = new ArrayList<>();

    /**
     * Default constructor.
     */
    public XMLErrorAccumulatorHandler() {
    }

    @Override
    public void error(final SAXParseException e) throws SAXException {
        add(e);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("ErrorHandler#error: parsing xml: {}", e.getMessage());
        }
    }

    @Override
    public void fatalError(final SAXParseException e) throws SAXException {
        add(e);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("ErrorHandler#fatalError: parsing xml: {}", e.getMessage());
        }
    }

    @Override
    public void warning(final SAXParseException e) throws SAXException {
        add(e);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("ErrorHandler#warning: parsing xml: {}", e.getMessage());
        }
    }

    private void add(final SAXParseException e) {
        if (errors.size() < MAX_ERRORS) {
            errors.add(e);
        }
    }

    /**
     * Returns the accumulated parsing exceptions.
     *
     * @return an unmodifiable list of the accumulated parsing exceptions
     */
    public List<SAXParseException> getErrorXML() {
        return Collections.unmodifiableList(errors);
    }

    /**
     * Indicates whether any parsing error, fatal error or warning was accumulated.
     *
     * @return {@code true} if at least one issue was accumulated, {@code false} otherwise
     */
    public boolean hasError() {
        return !errors.isEmpty();
    }
}