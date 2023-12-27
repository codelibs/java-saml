package org.codelibs.saml2.core.test;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

import org.codelibs.saml2.core.util.Util;
import org.junit.Assert;
import org.junit.Test;

public class NaiveUrlEncodeTest {

    @Test
    public void testDemonstratingUrlEncodingNotCanonical() throws UnsupportedEncodingException {
        String theString = "Hello World!";

        String naiveEncoded = NaiveUrlEncoder.encode(theString);
        String propperEncoded = Util.urlEncoder(theString);

        Assert.assertNotEquals("Encoded versions should differ", naiveEncoded, propperEncoded);
        Assert.assertEquals("Decoded versions equal", URLDecoder.decode(naiveEncoded, "UTF-8"), URLDecoder.decode(propperEncoded, "UTF-8"));
    }

}
