package de.wuthoehle.argon2jni;

/*
 * Copyright (c) Marco Huenseler
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */


import java.security.SecureRandom;

/**
 * Java part of argon2jni. Define native methods and a Java API.
 * @author Marco Huenseler
 * @version 0.1
 */
public class Argon2 {
    static {
        System.loadLibrary("argon2jni");
    }

    /**
     * Possible algorithm IDs for "typeid" parameter.
     * @see #argon2jni_hash(int, int, int, byte[], byte[], int, int, int typeid, int)
     * @see #argon2jni_verify(String, byte[], int typeid)
     */
    public static final class TypeIdentifiers {
        public static final int ARGON2D = 0;
        public static final int ARGON2I = 1;
        public static final int ARGON2ID = 2;
    }

    /**
     * Possible algorithm version IDs for "versionid" parameter.
     * @see #argon2jni_hash(int, int, int, byte[], byte[], int, int, int, int versionid)
     */
    public static final class VersionIdentifiers {
        public static final int VERSION_10 = 0x10;
        public static final int VERSION_13 = 0x13;
    }

    /**
     * Useful security parameter combinations (t_cost, m_cost, parallelism)
     * @see #argon2jni_hash(int t_cost, int m_cost, int parallelism, byte[], byte[], int, int, int, int)
     */
    public static final class SecurityParameterTemplates {
        public static final SecurityParameters OFFICIAL_DEFAULT = new SecurityParameters(3, 1 << 12, 1);
    }

    public static final int DefaultTypeIdentifier = TypeIdentifiers.ARGON2I;
    public static final int DefaultVersionIdentifier = VersionIdentifiers.VERSION_13;
    public static final SecurityParameters DefaultSecurityParameterTemplate = SecurityParameterTemplates.OFFICIAL_DEFAULT;

    public static final int DefaultHashlen = 16;

    private static SecureRandom random;

    private int typeid;
    private int versionid;
    private SecurityParameters securityParameters;
    private int hashlen;

    /**
     * Construct a class using all default values
     */
    public Argon2() {
        // Defaults:
        this.securityParameters = DefaultSecurityParameterTemplate;
        this.hashlen = DefaultHashlen;
        this.typeid = DefaultTypeIdentifier;
        this.versionid = DefaultVersionIdentifier;
    }

    /**
     * Construct a class using all custom values
     * @param securityParameters SecurityParameters (t_cost, m_cost, parallelism) to use
     * @param hashlen Desired hash output length in bytes
     * @param typeid Argon2 algorithm type to use
     * @param versionid Argon2 version to use
     * @see SecurityParameters
     * @see TypeIdentifiers
     * @see VersionIdentifiers
     */
    public Argon2(SecurityParameters securityParameters, int hashlen, int typeid, int versionid) {
        this.securityParameters = securityParameters;
        this.hashlen = hashlen;
        this.typeid = typeid;
        this.versionid = versionid;
    }

    /**
     * Call Argon2 and get a result object containing the raw hash and an encoded version
     * @param pwd Password to hash
     * @param salt Salt to use
     * @return Object containing the raw hash and an encoded version
     */
    public EncodedArgon2Result argon2_hash(byte[] pwd, byte[] salt) {
        return (EncodedArgon2Result) argon2jni_hash(
                this.securityParameters.t_cost, this.securityParameters.m_cost, this.securityParameters.parallelism,
                pwd, salt, this.hashlen,
                this.determineValidEncodedLen(salt),
                this.typeid, this.versionid
        );
    }

    /**
     * Call Argon2 and get a result object containing the encoded version of the hash and the generated salt.
     * If you are unsure what to do and just want to hash a password, choose this method.
     * Do not forget to store the encoded version of the hash, as it contains the generated salt value,
     * which is needed to verify given passwords afterwards.
     * @param pwd Password to hash
     * @return Object containing the raw hash and an encoded version
     */
    public EncodedArgon2Result argon2_hash(byte[] pwd) {
        // Generate a random salt
        byte[] salt = new byte[16];

        Argon2.ensureRandom();
        Argon2.random.nextBytes(salt);

        return this.argon2_hash(pwd, salt);
    }

    /**
     * Call Argon2 and get a result object containing only the raw hash value
     * @param pwd Password to hash
     * @param salt Salt to use
     * @return Object containing the raw hash
     */
    public Argon2Result argon2_hash_raw(byte[] pwd, byte[] salt) {
        return argon2jni_hash(
                this.securityParameters.t_cost, this.securityParameters.m_cost, this.securityParameters.parallelism,
                pwd, salt, this.hashlen, 0, this.typeid, this.versionid
        );
    }

    public Argon2Result argon2_hash_raw(byte[] pwd) {
        // Generate a random salt
        byte[] salt = new byte[16];

        Argon2.ensureRandom();
        Argon2.random.nextBytes(salt);

        return this.argon2_hash_raw(pwd, salt);
    }

    /**
     * Call Argon2's verify function to check whether the password specified matches the encoded one
     * @param encoded Encoded Argon2 hash
     * @param pwd Password to check
     * @return true if password is valid, otherwise false
     */
    public boolean argon2_verify(String encoded, byte[] pwd) {
        return argon2jni_verify(encoded, pwd, this.typeid);
    }

    /**
     * Call Argon2's hash function using all default values
     * @param pwd Password to hash
     * @return Object containing the raw hash and an encoded version
     */
    public static EncodedArgon2Result argon2_quick_hash(byte[] pwd) {
        // Generate a random salt
        byte[] salt = new byte[16];

        Argon2.ensureRandom();
        Argon2.random.nextBytes(salt);

        return (EncodedArgon2Result) Argon2.argon2jni_hash(
                SecurityParameterTemplates.OFFICIAL_DEFAULT.t_cost,
                SecurityParameterTemplates.OFFICIAL_DEFAULT.m_cost,
                SecurityParameterTemplates.OFFICIAL_DEFAULT.parallelism,
                pwd,
                salt,
                Argon2.DefaultHashlen,
                Argon2.determineValidEncodedLen(Argon2.DefaultSecurityParameterTemplate,
                        Argon2.DefaultHashlen, Argon2.DefaultVersionIdentifier, salt),
                Argon2.DefaultTypeIdentifier, Argon2.DefaultVersionIdentifier);
    }


    /**
     * Call Argon2's verify function using all default values
     * @param encoded Encoded Argon2 hash
     * @param pwd Password to check
     * @return true if password is valid, otherwise false
     */
    public static boolean argon2_quick_verify(String encoded, byte[] pwd) {
        return argon2jni_verify(encoded, pwd, Argon2.DefaultTypeIdentifier);
    }

    /**
     * Used to make sure the RNG was initialized. Used for test cases.
     * @return Whether Argon2.random was initialized (not null)
     */
    public static boolean isRngInitialized() {
        return Argon2.random != null;
    }


    /**
     * This is a wrapper around Argon2's native argon2_hash function. Be sure to choose valid values.
     * Use argon2_hash for general usage.
     * @param t_cost Time cost
     * @param m_cost Memory cost
     * @param parallelism Threads to use
     * @param pwd Password to hash
     * @param salt Salt to use
     * @param hashlen Desired output hash length in bytes
     * @param encodedlen Internal size reserved for the encoded string. Try determineValidEncodedLen if in doubt or specify 0 if you do not need an encoded version.
     * @param typeid Argon2 algorithm type to use. See TypeIdentifiers if in doubt
     * @param versionid Argon2 algorithm version to use. See VersionIdentifiers if in doubt
     * @return Argon2Result or EncodedArgon2Result object, depending on the value specified for encodedlen.
     * @see #argon2_hash(byte[], byte[])
     * @see TypeIdentifiers
     * @see VersionIdentifiers
     * @see #determineValidEncodedLen(SecurityParameters, int, int, byte[])
     */
    private static native Argon2Result argon2jni_hash(int t_cost, int m_cost, int parallelism,
                                              byte[] pwd, byte[] salt,
                                              int hashlen, int encodedlen,
                                              int typeid, int versionid);



    /**
     * This is a wrapper around Argon2's native argon2_verify function. Be sure to choose valid values.
     * Use argon2_verify for general usage.
     * @param encoded Encoded Argon2 hash
     * @param pwd Password to check
     * @param typeid Argon2 algorithm to use. See VersionIdentifiers if in doubt
     * @return true if password is valid, otherwise false
     * @see #argon2_verify(String, byte[])
     * @see VersionIdentifiers
     */
    private static native boolean argon2jni_verify(String encoded, byte[] pwd, int typeid);

    /**
     * Helper function to determine a value for the encodedlen parameter, which is sufficient to hold the resulting encoded hash
     * @param salt Salt used to calculate the encoded hash
     * @return A size in bytes which is sufficient to hold an encoded hash string
     */
    private int determineValidEncodedLen(byte[] salt) {
        return determineValidEncodedLen(this.securityParameters, this.hashlen, this.versionid, salt);
    }

    /**
     * Helper function to determine a value for the encodedlen parameter, which is sufficient to hold the resulting encoded hash
     * @param securityParameters SecurityParameters (t_cost, m_cost, parallelism) used
     * @param hashlen Output hash size in bytes
     * @param versionid Argon2 version to use
     * @param salt Salt to use
     * @return A size in bytes which is sufficient to hold an encoded hash string
     */
    private static int determineValidEncodedLen(SecurityParameters securityParameters, int hashlen, int versionid, byte[] salt) {
        // $argon2xx$v=[version]$m=[m_cost],t=[t_cost],p=[parallelism]$[b64:salt]$[b64:hash]
        // 12                   3          3          3               1          1
        // = 23
        // + 2 safety (possible closing '=' in base64 encoding etc.)
        int encodedlen = 25;

        encodedlen += Integer.toString(versionid, 10).length();
        encodedlen += Integer.toString(securityParameters.m_cost, 10).length();
        encodedlen += Integer.toString(securityParameters.t_cost, 10).length();
        encodedlen += Integer.toString(securityParameters.parallelism, 10).length();

        /* Salt and hash lengths
         * "Specifically, given an input of n bytes, the output will be {\displaystyle 4\lceil n/3\rceil } 4 \lceil n/3 \rceil bytes long, including padding characters."
         * https://en.wikipedia.org/wiki/Base64
         */

        encodedlen += 4 * Math.ceil(salt.length / 3.0f);
        encodedlen += 4 * Math.ceil(hashlen / 3.0f);
        return encodedlen;
    }

    private static void ensureRandom() {
        if(Argon2.random == null) {
            Argon2.random = new SecureRandom();
        }
    }

}
