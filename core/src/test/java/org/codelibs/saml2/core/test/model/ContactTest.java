package org.codelibs.saml2.core.test.model;

import static org.junit.Assert.assertEquals;

import org.codelibs.saml2.core.model.Contact;
import org.junit.Test;

/**
 * Tests the org.codelibs.saml2.core.core.model.Contact class
 */
public class ContactTest {

    /**
     * Tests the Contact constructor
     *
     * @see org.codelibs.saml2.core.core.model.Contact
     */
    @Test
    public void testContact() {
        Contact contact = new Contact(null, null, null);
        assertEquals("", contact.getContactType());
        assertEquals("", contact.getGivenName());
        assertEquals("", contact.getEmailAddress());

        Contact contact2 = new Contact("", "", "");
        assertEquals("", contact2.getContactType());
        assertEquals("", contact2.getGivenName());
        assertEquals("", contact2.getEmailAddress());

        Contact contact3 = new Contact("technical", "Name", "mail@example.com");
        assertEquals("technical", contact3.getContactType());
        assertEquals("Name", contact3.getGivenName());
        assertEquals("mail@example.com", contact3.getEmailAddress());
    }
}
