package de.wuthoehle.argon2jni;
/*
 * Copyright (c) Marco Huenseler
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import org.junit.Test;

import java.io.UnsupportedEncodingException;

import static junit.framework.Assert.fail;

public class ErrorStateTests {
    public ErrorStateTests() {}

    @Test
    public void invalidEncoding() throws UnsupportedEncodingException {
        // First
        try {
            Argon2.argon2_quick_verify(
                    "$argon2i$v=19$m=65536,t=2,p=1c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
                    "password".getBytes("US-ASCII")
            );
            fail("argon2_quick_verify should have thrown a decoding-related exception (#1)");
        } catch(Argon2Exception e) {
            if(! e.getMessage().contains("Decoding")) {
                fail("argon2_quick_verify should have thrown a decoding-related exception");
            }
        }

        // Second
        try {
            Argon2.argon2_quick_verify(
                    "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQwWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
                    "password".getBytes("US-ASCII")
            );
            fail("argon2_quick_verify should have thrown a decoding-related exception");
        } catch(Argon2Exception e) {
            if(! e.getMessage().contains("Decoding")) {
                fail("argon2_quick_verify should have thrown a decoding-related exception (#2)");
            }
        }
    }
}
