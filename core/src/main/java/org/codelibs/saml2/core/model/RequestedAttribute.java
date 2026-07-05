package org.codelibs.saml2.core.model;

import java.util.List;

/**
 * RequestedAttribute class of Java Toolkit.
 *
 * A class that stores RequestedAttribute of the AttributeConsumingService
 */
public class RequestedAttribute {
    /**
     * Name of the attribute
     */
    private final String name;

    /**
     * FriendlyName of the attribute
     */
    private final String friendlyName;

    /**
     * If the attribute is or not required
     */
    private final Boolean isRequired;

    /**
     * NameFormat of the attribute
     */
    private final String nameFormat;

    /**
     * Values of the attribute
     */
    private final List<String> attributeValues;

    /**
     * Constructor
     *
     * @param name
     *              String. RequestedAttribute Name
     * @param friendlyName
     *              String. RequestedAttribute FriendlyName
     * @param isRequired
     *              Boolean. RequestedAttribute isRequired value
     * @param nameFormat
     *              Boolean. RequestedAttribute NameFormat
     * @param attributeValues
     *              List. RequestedAttribute values
     */
    public RequestedAttribute(final String name, final String friendlyName, final Boolean isRequired, final String nameFormat,
            final List<String> attributeValues) {
        this.name = name;
        this.friendlyName = friendlyName;
        this.isRequired = isRequired;
        this.nameFormat = nameFormat;
        this.attributeValues = attributeValues;
    }

    /**
     * Returns the RequestedAttribute name.
     *
     * @return string the RequestedAttribute name
     */
    public final String getName() {
        return name;
    }

    /**
     * Returns the RequestedAttribute friendly name.
     *
     * @return string the RequestedAttribute friendlyName
     */
    public final String getFriendlyName() {
        return friendlyName;
    }

    /**
     * Returns whether the RequestedAttribute is required.
     *
     * @return boolean the RequestedAttribute isRequired value
     */
    public final Boolean isRequired() {
        return isRequired;
    }

    /**
     * Returns the RequestedAttribute name format.
     *
     * @return string the RequestedAttribute nameformat
     */
    public final String getNameFormat() {
        return nameFormat;
    }

    /**
     * Returns the RequestedAttribute values.
     *
     * @return string the RequestedAttribute nameformat
     */
    public final List<String> getAttributeValues() {
        return attributeValues;
    }
}
