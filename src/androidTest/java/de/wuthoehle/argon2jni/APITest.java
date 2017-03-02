package de.wuthoehle.argon2jni;

/*
 * Copyright (c) Marco Huenseler
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import android.support.test.runner.AndroidJUnit4;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertFalse;
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
                new byte[] {0},
                "ABCDEF"
        });
        // versionid: VERSION_13
        elements.add(new Object[] {
                Argon2.SecurityParameterTemplates.OFFICIAL_DEFAULT,
                Argon2.TypeIdentifiers.ARGON2D,
                Argon2.VersionIdentifiers.VERSION_13,
                new byte[] {0},
                "ABCDEF"
        });
        // ---------- typeid: ARGON2I
        // versionid: VERSION_10
        elements.add(new Object[] {
                Argon2.SecurityParameterTemplates.OFFICIAL_DEFAULT,
                Argon2.TypeIdentifiers.ARGON2I,
                Argon2.VersionIdentifiers.VERSION_10,
                new byte[] {0},
                "ABCDEF"
        });
        // versionid: VERSION_13
        elements.add(new Object[] {
                Argon2.SecurityParameterTemplates.OFFICIAL_DEFAULT,
                Argon2.TypeIdentifiers.ARGON2I,
                Argon2.VersionIdentifiers.VERSION_13,
                new byte[] {0},
                "ABCDEF"
        });
        // ---------- typeid: ARGON2ID
        // versionid: VERSION_10
        elements.add(new Object[] {
                Argon2.SecurityParameterTemplates.OFFICIAL_DEFAULT,
                Argon2.TypeIdentifiers.ARGON2ID,
                Argon2.VersionIdentifiers.VERSION_10,
                new byte[] {0},
                "ABCDEF"
        });
        // versionid: VERSION_13
        elements.add(new Object[] {
                Argon2.SecurityParameterTemplates.OFFICIAL_DEFAULT,
                Argon2.TypeIdentifiers.ARGON2ID,
                Argon2.VersionIdentifiers.VERSION_13,
                new byte[] {0},
                "ABCDEF"
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
            assertTrue(result.getResult().length == Argon2.DefaultHashlen);
            assertTrue(result.getEncoded().length() > 16);
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
            assertTrue(result.getResult().length == Argon2.DefaultHashlen);
        }
    }

    @Test
    public void argon2_quick_hash_works() {
        EncodedArgon2Result result = Argon2.argon2_quick_hash(common_key);
        assertTrue(Argon2.isRngInitialized());
        assertTrue(result.getResult().length == Argon2.DefaultHashlen);
        assertTrue(result.getEncoded().length() > 16);
    }

    @Test
    public void argon2_verify_works() {
        for(Object[] element : input_variations) {
            Argon2 obj = new Argon2((SecurityParameters) element[0],
                    Argon2.DefaultHashlen,
                    (Integer) element[1],
                    (Integer) element[2]);
            assertTrue(obj.argon2_verify((String) element[4], common_key));
            assertFalse(obj.argon2_verify("ABCDEFGHIJKLMNOPQRSTUVWXYZ", common_key));
        }
    }

    @Test
    public void argon2_quick_verify_works() {
        assertTrue(Argon2.argon2_quick_verify("ABCD", common_key));
        assertFalse(Argon2.argon2_quick_verify("ABCDEFGHIJKLMNOPQRSTUVWXYZ", common_key));
    }
}
