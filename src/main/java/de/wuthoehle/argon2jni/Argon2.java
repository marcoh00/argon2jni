package de.wuthoehle.argon2jni;

/*
 * Copyright (c) Marco Huenseler
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

public class Argon2 {
    static {
        System.loadLibrary("argon2jni");
    }

    public static final class TypeIdentifiers {
        public static final int ARGON2D = 0;
        public static final int ARGON2I = 1;
        public static final int ARGON2ID = 2;
    }

    public static final class VersionIdentifiers {
        public static final int VERSION_10 = 0x10;
        public static final int VERSION_13 = 0x13;
    }

    public static final class SecurityParameterTemplates {
        public static final SecurityParameters OFFICIAL_DEFAULT = new SecurityParameters(3, 1 << 12, 1);
    }

    public static final int DefaultTypeIdentifier = TypeIdentifiers.ARGON2I;
    public static final int DefaultVersionIdentifier = VersionIdentifiers.VERSION_13;
    public static final SecurityParameters DefaultSecurityParameterTemplate = SecurityParameterTemplates.OFFICIAL_DEFAULT;

    public static final int DefaultHashlen = 16;

    private int typeid;
    private int versionid;
    private SecurityParameters securityParameters;
    private int hashlen;

    public Argon2() {
        // Defaults:
        this.securityParameters = DefaultSecurityParameterTemplate;
        this.hashlen = DefaultHashlen;
        this.typeid = DefaultTypeIdentifier;
        this.versionid = DefaultVersionIdentifier;
    }

    public Argon2(int typeid, int versionid) {
        this.typeid = typeid;
        this.versionid = versionid;

        // Defaults:
        this.securityParameters = DefaultSecurityParameterTemplate;
        this.hashlen = DefaultHashlen;
    }

    public Argon2(SecurityParameters securityParameters, int hashlen) {
        this.securityParameters = securityParameters;
        this.hashlen = hashlen;

        // Defaults:
        this.typeid = TypeIdentifiers.ARGON2I;
        this.versionid = VersionIdentifiers.VERSION_13;
    }

    public Argon2(SecurityParameters securityParameters, int hashlen, int typeid, int versionid) {
        this.securityParameters = securityParameters;
        this.hashlen = hashlen;
        this.typeid = typeid;
        this.versionid = versionid;
    }

    public EncodedArgon2Result argon2_hash(byte[] pwd, byte[] salt) {
        return (EncodedArgon2Result) argon2jni_hash(
                this.securityParameters.t_cost, this.securityParameters.m_cost, this.securityParameters.parallelism,
                pwd, salt, this.hashlen,
                this.determineValidEncodedLen(salt),
                this.typeid, this.versionid
        );
    }

    public Argon2Result argon2_hash_raw(byte[] pwd, byte[] salt) {
        return argon2jni_hash(
                this.securityParameters.t_cost, this.securityParameters.m_cost, this.securityParameters.parallelism,
                pwd, salt, this.hashlen, 0, this.typeid, this.versionid
        );
    }

    public static native Argon2Result argon2jni_hash(int t_cost, int m_cost, int parallelism,
                                              byte[] pwd, byte[] salt,
                                              int hashlen, int encodedlen,
                                              int typeid, int versionid);

    public static native boolean argon2jni_verify(String encoded, byte[] pwd, int typeid);

    public int determineValidEncodedLen(byte[] salt) {
        // $argon2xx$v=[version]$m=[m_cost],t=[t_cost],p=[parallelism]$[b64:salt]$[b64:hash]
        // 12                   3          3          3               1          1
        // = 23
        // + 2 safety (possible closing '=' in base64 encoding etc.)
        int encodedlen = 25;

        encodedlen += Integer.toString(this.versionid, 10).length();
        encodedlen += Integer.toString(this.securityParameters.m_cost, 10).length();
        encodedlen += Integer.toString(this.securityParameters.t_cost, 10).length();
        encodedlen += Integer.toString(this.securityParameters.parallelism, 10).length();

        /* Salt and hash lengths
         * "Specifically, given an input of n bytes, the output will be {\displaystyle 4\lceil n/3\rceil } 4 \lceil n/3 \rceil bytes long, including padding characters."
         * https://en.wikipedia.org/wiki/Base64
         */

        encodedlen += 4 * Math.ceil(salt.length / 3.0f);
        encodedlen += 4 * Math.ceil(this.hashlen / 3.0f);
        return encodedlen;
    }

}
