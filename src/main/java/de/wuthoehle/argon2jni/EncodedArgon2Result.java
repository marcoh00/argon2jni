package de.wuthoehle.argon2jni;
/*
 * Copyright (c) Marco Huenseler
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

public class EncodedArgon2Result extends Argon2Result {
    private String encoded;

    public EncodedArgon2Result(byte[] result, String encoded) {
        super(result);
        this.encoded = encoded;
    }

    public String getEncoded() {
        return encoded;
    }
}
