package de.wuthoehle.argon2jni;

/*
 * Copyright (c) Marco Huenseler
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

public class Argon2Exception extends RuntimeException {
    public Argon2Exception() {
    }

    public Argon2Exception(String s) {
        super(s);
    }

    public Argon2Exception(String message, Throwable cause) {
        super(message, cause);
    }

    public Argon2Exception(Throwable cause) {
        super(cause);
    }
}
