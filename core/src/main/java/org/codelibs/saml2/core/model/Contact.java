package org.codelibs.saml2.core.model;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Contact class of Java Toolkit.
 *
 * A class that stores contact info
 */
public class Contact {
    /**
       * Contact type
       */
    private final String contactType;

    /**
     * Contact company
     */
    private final String company;

    /**
       * Contact given name
       */
    private final String givenName;

    /**
     * Contact surname
     */
    private final String surname;

    /**
       * Contact email
       */
    private final List<String> emailAddresses;

    /**
     * Contact phone number
     */
    private final List<String> telephoneNumbers;

    /**
     * Constructor to specify minimal contact data.
     * <p>
     * To maintain backward compatibility, a <code>null</code> given name and a
     * <code>null</code> e-mail address are handled as being empty strings.
     *
     * @param contactType
     *              Contact type
     * @param givenName
     *              Contact given name
     * @param emailAddress
     *              Contact e-mail
     * @deprecated use {@link #Contact(String, String, String, String, List, List)}
     */
    @Deprecated
    public Contact(final String contactType, final String givenName, final String emailAddress) {
        this(contactType, null, givenName != null ? givenName : "", null, Arrays.asList(emailAddress != null ? emailAddress : ""), null);
    }

    /**
     * Constructor
     *
     * @param contactType
     *              Contact type
     * @param givenName
     *              Contact given name
     * @param surName
     *              Contact surname
     * @param company
     *              Contact company
     * @param emailAddresses
     *              Contact e-mails
     * @param telephoneNumbers
     *              Contact phone numbers
     */
    public Contact(final String contactType, final String company, final String givenName, final String surName,
            final List<String> emailAddresses, final List<String> telephoneNumbers) {
        this.contactType = contactType != null ? contactType : "";
        this.company = company;
        this.givenName = givenName;
        this.surname = surName;
        this.emailAddresses = emailAddresses != null ? emailAddresses : Collections.emptyList();
        this.telephoneNumbers = telephoneNumbers != null ? telephoneNumbers : Collections.emptyList();
    }

    /**
     * Returns the contact type.
     *
     * @return string the contact type
     */
    public final String getContactType() {
        return contactType;
    }

    /**
     * Returns the first contact e-mail address.
     *
     * @return the contact email
     * @deprecated this returns just the first e-mail address in {@link #getEmailAddresses()}
     */
    @Deprecated
    public final String getEmailAddress() {
        return !emailAddresses.isEmpty() ? emailAddresses.get(0) : null;
    }

    /**
     * Returns the contact e-mail addresses.
     *
     * @return a list containing the contact e-mail addresses (never <code>null</code>)
     */
    public final List<String> getEmailAddresses() {
        return emailAddresses;
    }

    /**
     * Returns the contact given name.
     *
     * @return the contact given name
     */
    public final String getGivenName() {
        return givenName;
    }

    /**
     * Returns the contact surname.
     *
     * @return the contact surname
     */
    public final String getSurName() {
        return surname;
    }

    /**
     * Returns the contact company.
     *
     * @return the contact company
     */
    public final String getCompany() {
        return company;
    }

    /**
     * Returns the contact phone numbers.
     *
     * @return a list containing the contact phone numbers (never <code>null</code>)
     */
    public final List<String> getTelephoneNumbers() {
        return telephoneNumbers;
    }
}
