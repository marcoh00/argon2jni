package de.wuthoehle.argon2jni;

/*
 * Copyright (c) Marco Huenseler
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import android.support.test.runner.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertSame;
import static junit.framework.Assert.assertTrue;

@RunWith(AndroidJUnit4.class)
public class APITest {

    private static byte[] common_key = new byte[] {0, 1, 2, 4, 8, 16, 33, 127};
    private static byte[] common_salt = new byte[] {(-128), 0, 1, 2, 4, 8, 16, 33};
    private static Collection<Object[]> input_variations = data();

    private static Collection<Object[]> data() {
        Collection<Object[]> elements = new ArrayList<Object[]>();

        // Hashlen is always DefaultHashlen (= 16)
        // -------------------- SecurityParameters: OFFICIAL_DEFAULT
        // ---------- typeid: ARGON2D
        // versionid: VERSION_10
        elements.add(new Object[] {
                Argon2.SecurityParameterTemplates.OFFICIAL_DEFAULT,
                Argon2.TypeIdentifiers.ARGON2D,
                Argon2.VersionIdentifiers.VERSION_10,
                new byte[] {38, 101, 9, 83, 57, -93, -127, -126, 42, 118, 78, 12, 88, -27, -67, -88},
                "$argon2d$v=16$m=4096,t=3,p=1$gAABAgQIECE$JmUJUzmjgYIqdk4MWOW9qA"
        });
        // versionid: VERSION_13
        elements.add(new Object[] {
                Argon2.SecurityParameterTemplates.OFFICIAL_DEFAULT,
                Argon2.TypeIdentifiers.ARGON2D,
                Argon2.VersionIdentifiers.VERSION_13,
                new byte[] {94, -127, -83, 1, -37, 105, -22, 55, -39, -115, 126, 9, -31, -63, -43, 24},
                "$argon2d$v=19$m=4096,t=3,p=1$gAABAgQIECE$XoGtAdtp6jfZjX4J4cHVGA"
        });
        // ---------- typeid: ARGON2I
        // versionid: VERSION_10
        elements.add(new Object[] {
                Argon2.SecurityParameterTemplates.OFFICIAL_DEFAULT,
                Argon2.TypeIdentifiers.ARGON2I,
                Argon2.VersionIdentifiers.VERSION_10,
                new byte[] {59, -55, -15, 35, -12, 1, -74, -78, 11, -92, -64, -73, -18, 117, -53, -100},
                "$argon2i$v=16$m=4096,t=3,p=1$gAABAgQIECE$O8nxI/QBtrILpMC37nXLnA"
        });
        // versionid: VERSION_13
        elements.add(new Object[] {
                Argon2.SecurityParameterTemplates.OFFICIAL_DEFAULT,
                Argon2.TypeIdentifiers.ARGON2I,
                Argon2.VersionIdentifiers.VERSION_13,
                new byte[] {116, 7, 14, 43, -114, -4, 57, -21, 42, -125, 102, -99, -105, 15, 78, 46},
                "$argon2i$v=19$m=4096,t=3,p=1$gAABAgQIECE$dAcOK478Oesqg2adlw9OLg"
        });
        // ---------- typeid: ARGON2ID
        // versionid: VERSION_10
        elements.add(new Object[] {
                Argon2.SecurityParameterTemplates.OFFICIAL_DEFAULT,
                Argon2.TypeIdentifiers.ARGON2ID,
                Argon2.VersionIdentifiers.VERSION_10,
                new byte[] {110, -8, -28, -68, -55, 127, -113, 47, -28, -85, 103, 67, -102, -58, -47, 17},
                "$argon2id$v=16$m=4096,t=3,p=1$gAABAgQIECE$bvjkvMl/jy/kq2dDmsbREQ"
        });
        // versionid: VERSION_13
        elements.add(new Object[] {
                Argon2.SecurityParameterTemplates.OFFICIAL_DEFAULT,
                Argon2.TypeIdentifiers.ARGON2ID,
                Argon2.VersionIdentifiers.VERSION_13,
                new byte[] {-14, 102, -113, -73, -59, -33, 112, 72, 66, 116, -47, -18, 26, 74, -56, -44},
                "$argon2id$v=19$m=4096,t=3,p=1$gAABAgQIECE$8maPt8XfcEhCdNHuGkrI1A"
        });

        return elements;
    }

    public APITest() {
    }

    @Test
    public void deterministic_argon2_hash_works() {
        for(Object[] element : input_variations) {
            Argon2 obj = new Argon2((SecurityParameters) element[0],
                    Argon2.DefaultHashlen,
                    (Integer) element[1],
                    (Integer) element[2]);

            EncodedArgon2Result result = obj.argon2_hash(common_key, common_salt);
            assertTrue(Arrays.equals((byte[]) element[3], result.getResult()));
            assertEquals((String) element[4], result.getEncoded());
        }
    }

    @Test
    public void deterministic_argon2_hash_raw_works() {
        for(Object[] element : input_variations) {
            Argon2 obj = new Argon2((SecurityParameters) element[0],
                    Argon2.DefaultHashlen,
                    (Integer) element[1],
                    (Integer) element[2]);

            Argon2Result result = obj.argon2_hash_raw(common_key, common_salt);

            // BAD PRACTICE: NEVER USE THIS IN PRODUCTION!
            // You should compare the result using a constant-time comparsion function
            assertTrue(Arrays.equals((byte[]) element[3], result.getResult()));
        }
    }

    @Test
    public void nondeterministic_argon2_hash_works() {
        for(Object[] element : input_variations) {
            Argon2 obj = new Argon2((SecurityParameters) element[0],
                    Argon2.DefaultHashlen,
                    (Integer) element[1],
                    (Integer) element[2]);

            EncodedArgon2Result result = obj.argon2_hash(common_key);
            assertTrue(Argon2.isRngInitialized());
            assertSame(Argon2.DefaultHashlen, result.getResult().length);
            assertTrue(result.getEncoded().length() > 70);
        }
    }

    @Test
    public void nondeterministic_argon2_hash_raw_works() {
        for(Object[] element : input_variations) {
            Argon2 obj = new Argon2((SecurityParameters) element[0],
                    Argon2.DefaultHashlen,
                    (Integer) element[1],
                    (Integer) element[2]);

            Argon2Result result = obj.argon2_hash_raw(common_key);
            assertTrue(Argon2.isRngInitialized());
            assertSame(Argon2.DefaultHashlen, result.getResult().length);
        }
    }

    @Test
    public void argon2_quick_hash_works() {
        EncodedArgon2Result result = Argon2.argon2_quick_hash(common_key);
        assertTrue(Argon2.isRngInitialized());
        assertSame(Argon2.DefaultHashlen, result.getResult().length);
        assertTrue(result.getEncoded().length() > 70);
    }

    @Test
    public void argon2_verify_works() {
        for(Object[] element : input_variations) {
            Argon2 obj = new Argon2((SecurityParameters) element[0],
                    Argon2.DefaultHashlen,
                    (Integer) element[1],
                    (Integer) element[2]);
            assertTrue(obj.argon2_verify((String) element[4], common_key));

            StringBuilder decodableString = new StringBuilder();
            decodableString.append("$argon2");
            switch((Integer) element[1]) {
                case Argon2.TypeIdentifiers.ARGON2D:
                    decodableString.append("d");
                    break;
                case Argon2.TypeIdentifiers.ARGON2I:
                    decodableString.append("i");
                    break;
                case Argon2.TypeIdentifiers.ARGON2ID:
                    decodableString.append("id");
                    break;
            }
            decodableString.append("$v=19$m=4096,t=3,p=1$AAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA");

            assertFalse(obj.argon2_verify(decodableString.toString(), common_key));
        }
    }

    @Test
    public void argon2_quick_verify_works() {
        assertTrue(Argon2.argon2_quick_verify("$argon2i$v=19$m=4096,t=3,p=1$gAABAgQIECE$dAcOK478Oesqg2adlw9OLg", common_key));
        assertFalse(Argon2.argon2_quick_verify("$argon2i$v=19$m=4096,t=3,p=1$AAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA", common_key));
    }
}
