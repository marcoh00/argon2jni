package de.wuthoehle.argon2jni;
/*
 * Copyright (c) Marco Huenseler
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import java.io.UnsupportedEncodingException;

import org.junit.Test;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertTrue;

/**
 * Test cases using hashtest(...), directly translated from libargon2's test.c (CC0/Apache licensed). Thanks!
 * @author Marco Huenseler
 * @version 0.1
 */
public class HashTest {
    public HashTest() {}

    @Test
    public void Version10_Small_Memory_Tests() throws UnsupportedEncodingException {
        int version = Argon2.VersionIdentifiers.VERSION_10;

        hashtest(version, 2, 16, 1, "password", "somesalt",
                "f6c4db4a54e2a370627aff3db6176b94a2a209a62c8e36152711802f7b30c694",
                "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ");
        hashtest(version, 2, 18, 1, "password", "somesalt",
                "3e689aaa3d28a77cf2bc72a51ac53166761751182f1ee292e3f677a7da4c2467",
                "$argon2i$m=262144,t=2,p=1$c29tZXNhbHQ$Pmiaqj0op3zyvHKlGsUxZnYXURgvHuKS4/Z3p9pMJGc");
        hashtest(version, 2, 8, 1, "password", "somesalt",
                "fd4dd83d762c49bdeaf57c47bdcd0c2f1babf863fdeb490df63ede9975fccf06",
                "$argon2i$m=256,t=2,p=1$c29tZXNhbHQ$/U3YPXYsSb3q9XxHvc0MLxur+GP960kN9j7emXX8zwY");
        hashtest(version, 2, 8, 2, "password", "somesalt",
                "b6c11560a6a9d61eac706b79a2f97d68b4463aa3ad87e00c07e2b01e90c564fb",
                "$argon2i$m=256,t=2,p=2$c29tZXNhbHQ$tsEVYKap1h6scGt5ovl9aLRGOqOth+AMB+KwHpDFZPs");
        hashtest(version, 1, 16, 1, "password", "somesalt",
                "81630552b8f3b1f48cdb1992c4c678643d490b2b5eb4ff6c4b3438b5621724b2",
                "$argon2i$m=65536,t=1,p=1$c29tZXNhbHQ$gWMFUrjzsfSM2xmSxMZ4ZD1JCytetP9sSzQ4tWIXJLI");
        hashtest(version, 4, 16, 1, "password", "somesalt",
                "f212f01615e6eb5d74734dc3ef40ade2d51d052468d8c69440a3a1f2c1c2847b",
                "$argon2i$m=65536,t=4,p=1$c29tZXNhbHQ$8hLwFhXm6110c03D70Ct4tUdBSRo2MaUQKOh8sHChHs");
        hashtest(version, 2, 16, 1, "differentpassword", "somesalt",
                "e9c902074b6754531a3a0be519e5baf404b30ce69b3f01ac3bf21229960109a3",
                "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ$6ckCB0tnVFMaOgvlGeW69ASzDOabPwGsO/ISKZYBCaM");
        hashtest(version, 2, 16, 1, "password", "diffsalt",
                "79a103b90fe8aef8570cb31fc8b22259778916f8336b7bdac3892569d4f1c497",
                "$argon2i$m=65536,t=2,p=1$ZGlmZnNhbHQ$eaEDuQ/orvhXDLMfyLIiWXeJFvgza3vaw4kladTxxJc");
    }

    @Test
    public void Version10_Large_Memory_Tests() throws UnsupportedEncodingException {
        int version = Argon2.VersionIdentifiers.VERSION_10;

        hashtest(version, 2, 20, 1, "password", "somesalt",
                "9690ec55d28d3ed32562f2e73ea62b02b018757643a2ae6e79528459de8106e9",
                "$argon2i$m=1048576,t=2,p=1$c29tZXNhbHQ$lpDsVdKNPtMlYvLnPqYrArAYdXZDoq5ueVKEWd6BBuk");
    }

    @Test
    public void Version13_Small_Memory_Tests() throws UnsupportedEncodingException {
        int version = Argon2.VersionIdentifiers.VERSION_13;

        hashtest(version, 2, 16, 1, "password", "somesalt",
                "c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0",
                "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA");
        hashtest(version, 2, 18, 1, "password", "somesalt",
                "296dbae80b807cdceaad44ae741b506f14db0959267b183b118f9b24229bc7cb",
                "$argon2i$v=19$m=262144,t=2,p=1$c29tZXNhbHQ$KW266AuAfNzqrUSudBtQbxTbCVkmexg7EY+bJCKbx8s");
        hashtest(version, 2, 8, 1, "password", "somesalt",
                "89e9029f4637b295beb027056a7336c414fadd43f6b208645281cb214a56452f",
                "$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8");
        hashtest(version, 2, 8, 2, "password", "somesalt",
                "4ff5ce2769a1d7f4c8a491df09d41a9fbe90e5eb02155a13e4c01e20cd4eab61",
                "$argon2i$v=19$m=256,t=2,p=2$c29tZXNhbHQ$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E");
        hashtest(version, 1, 16, 1, "password", "somesalt",
                "d168075c4d985e13ebeae560cf8b94c3b5d8a16c51916b6f4ac2da3ac11bbecf",
                "$argon2i$v=19$m=65536,t=1,p=1$c29tZXNhbHQ$0WgHXE2YXhPr6uVgz4uUw7XYoWxRkWtvSsLaOsEbvs8");
        hashtest(version, 4, 16, 1, "password", "somesalt",
                "aaa953d58af3706ce3df1aefd4a64a84e31d7f54175231f1285259f88174ce5b",
                "$argon2i$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$qqlT1YrzcGzj3xrv1KZKhOMdf1QXUjHxKFJZ+IF0zls");
        hashtest(version, 2, 16, 1, "differentpassword", "somesalt",
                "14ae8da01afea8700c2358dcef7c5358d9021282bd88663a4562f59fb74d22ee",
                "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$FK6NoBr+qHAMI1jc73xTWNkCEoK9iGY6RWL1n7dNIu4");
        hashtest(version, 2, 16, 1, "password", "diffsalt",
                "b0357cccfbef91f3860b0dba447b2348cbefecadaf990abfe9cc40726c521271",
                "$argon2i$v=19$m=65536,t=2,p=1$ZGlmZnNhbHQ$sDV8zPvvkfOGCw26RHsjSMvv7K2vmQq/6cxAcmxSEnE");
    }

    @Test
    public void Version13_Large_Memory_Tests() throws UnsupportedEncodingException {
        int version = Argon2.VersionIdentifiers.VERSION_13;

        hashtest(version, 2, 20, 1, "password", "somesalt",
                "d1587aca0922c3b5d6a83edab31bee3c4ebaef342ed6127a55d19b2351ad1f41",
                "$argon2i$v=19$m=1048576,t=2,p=1$c29tZXNhbHQ$0Vh6ygkiw7XWqD7asxvuPE667zQu1hJ6VdGbI1GtH0E");
    }

    private static void hashtest(int version, int t, int m, int p, String pwd, String salt, String hexref, String mcfref) throws UnsupportedEncodingException {
        // Build SecurityParameters
        SecurityParameters securityParameters = new SecurityParameters(t, 1 << m, p);

        // Initialize Argon2
        Argon2 testedInstance = new Argon2(securityParameters, 32, Argon2.TypeIdentifiers.ARGON2I, version);

        EncodedArgon2Result result = testedInstance.argon2_hash(
                pwd.getBytes("US-ASCII"),
                salt.getBytes("US-ASCII")
        );
        assertEquals(hexref, bytesToHex(result.getResult()));

        // Test whether the string representation is the same than specified
        if(version == Argon2.VersionIdentifiers.VERSION_13) {
            assertEquals(mcfref, result.getEncoded());
        }

        // Test whether both the generated and the reference value verify successfully
        assertTrue(testedInstance.argon2_verify(mcfref, pwd.getBytes("US-ASCII")));
        assertTrue(testedInstance.argon2_verify(result.getEncoded(), pwd.getBytes("US-ASCII")));
    }

    private static String bytesToHex(byte[] value) {
        StringBuilder wholeString = new StringBuilder();
        for(byte element : value) {
            wholeString.append(byteToHex(element));
        }
        return wholeString.toString();
    }

    private static String byteToHex(byte value) {
        // String representation of all possible values of a nibble
        // alphabet[0] = 0, ..., alphabet[15] = f
        String alphabet = "0123456789abcdef";
        String result = String.valueOf(alphabet.charAt((value >> 4) & 0xF)) +
                alphabet.charAt(value & 0xF);

        return result;
    }
}
