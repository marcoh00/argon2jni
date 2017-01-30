/*
 * Copyright (c) Marco Huenseler
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <inttypes.h>
#include <stdlib.h>

#include <jni.h>
#include <argon2.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ARGON2JNI_ARGON2D_ID 0
#define ARGON2JNI_ARGON2I_ID 1
#define ARGON2JNI_ARGON2ID_ID 2

#define ARGON2JNI_ARGON2_VERSION10_ID 0x10
#define ARGON2JNI_ARGON2_VERSION13_ID 0x13

/* All values needed to create a result object */
typedef struct result_ingredients {
    char* objname;
    char* constructorsig;
    jbyteArray result;
    jstring encoded;
} result_ingredients_t;

/* Throw Exception helper */
jint throw_exception(JNIEnv *, const char *, const char *);

/* Convert java integer to argon2_type helper */
int typeid_to_argon2_type(const jint, argon2_type*);

/* Convert java integer to argon2_version helper */
int versionid_to_argon2_version(const jint, argon2_version*);

/* Enrich ingredients with the encoded result if applicable */
int add_encoded_result(JNIEnv*, result_ingredients_t*, const char*);

/* Create a basic ingredient struct containing the raw return value */
int create_result_ingredients(JNIEnv*, const void*, const jsize, result_ingredients_t*);

/* Contruct result object [CAN THROW EXCEPTIONS]*/
jobject create_result(JNIEnv*, const void*, const jsize, const char*);

JNIEXPORT jobject JNICALL
Java_de_wuthoehle_argon2jni_Argon2_argon2jni_1hash(
        JNIEnv *env, jclass type,
        jint t_cost, jint m_cost, jint parallelism,
        jbyteArray pwd, jbyteArray salt,
        jint hashlen, jint encodedlen,
        jint typeid, jint versionid) {

    /* Entry guard, make sure Java's type sizes match with Argon2 input/output type sizes */
    if(sizeof(jint) != sizeof(uint32_t) || sizeof(jbyte) != sizeof(uint8_t)) {
        throw_exception(env, "java/lang/Exception", "Java and Argon2 type sizes do not match");
        return NULL;
    }

    jobject result = NULL;
    char* encoded = NULL;

    /* Determine Argon2 algorithm type */
    argon2_type target_type;
    if(! typeid_to_argon2_type(typeid, &target_type)) {
        throw_exception(env, "java/lang/IllegalArgumentException", "Argon2 target type must be a valid algorithm ID");
        goto cleanup_hash;
    }

    /* Determine Argon2 version */
    argon2_version target_version;
    if(! versionid_to_argon2_version(versionid, &target_version)) {
        throw_exception(env, "java/lang/IllegalArgumentException", "Argon2 target version must be a valid algorithm version ID");
        goto cleanup_hash;
    }

    /* Get Array lengths */
    jsize passwordlen = (*env)->GetArrayLength(env, pwd);
    jsize saltlen = (*env)->GetArrayLength(env, salt);

    /* Check for valid input sizes */
    if(t_cost <= 0 || m_cost <= 0 || parallelism <= 0 || hashlen <= 0 || passwordlen <= 0 || saltlen <= 0 || encodedlen < 0) {
        throw_exception(env,
                        "java/lang/IllegalArgumentException",
                        "Factors and values given to Argon2 must be positive and have a positive length (encodedlen may be 0)"
        );
        return NULL;
    }

    /* Get Salt and Password */
    jbyte *passwordval = (*env)->GetByteArrayElements(env, pwd, NULL);
    jbyte *saltval = (*env)->GetByteArrayElements(env, salt, NULL);

    /* Allocate space to store the to-be-generated hash */
    void *target = malloc(sizeof(jbyte) * hashlen);
    if(encodedlen > 0) {
        encoded = (char*) malloc((sizeof(char) * encodedlen) + 1);
    }

    if(passwordval == NULL || saltval == NULL || target == NULL || (encoded == NULL && encodedlen > 0)) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Could not allocate enough space to continue");
        goto cleanup_hash;
    }

    /* Call Argon2 */
    int argon2_result_code = argon2_hash((const uint32_t) t_cost, (const uint32_t) m_cost,
                                         (const uint32_t) parallelism,
                                         (const void*) passwordval, (const size_t) passwordlen,
                                         (const void*) saltval, (const size_t) saltlen,
                                         target, (const size_t) hashlen,
                                         encoded, (const size_t) encodedlen,
                                         target_type, target_version);

    /* Check result */
    if(argon2_result_code == ARGON2_OK) {
        result = create_result(env, target, hashlen, encoded);
        if(result == NULL) {
            /* create_result will already have thrown an exception with more information than we could wish for. Just tidy up this mess. */
            goto cleanup_hash;
        }
    } else {
        throw_exception(env, "de/wuthoehle/argon2jni/Argon2Exception",
                        argon2_error_message(argon2_result_code));
        goto cleanup_hash;
    }

    cleanup_hash:
    /* Free result target */
    if(target) {
        free(target);
    }
    if(encoded) {
        free(encoded);
    }

    /* Free JNI variables, never copy back changes */
    if(passwordval) {
        (*env)->ReleaseByteArrayElements(env, pwd, passwordval, JNI_ABORT);
    }
    if(saltval) {
        (*env)->ReleaseByteArrayElements(env, salt, saltval, JNI_ABORT);
    }

    return result;
}

JNIEXPORT jboolean JNICALL
Java_de_wuthoehle_argon2jni_Argon2_argon2jni_1verify(JNIEnv *env, jclass type, jstring encoded,
                                                     jbyteArray pwd, jint typeid) {
    jboolean result = 0;

    /* Get java parameter values */
    /* StringUTFChars should always be the same ones as given by argon2_hash, as the base64 encoding used is ASCII-only */
    const char *encodedval = (*env)->GetStringUTFChars(env, encoded, 0);
    jbyte *pwdval = (*env)->GetByteArrayElements(env, pwd, NULL);
    jsize pwdlen = (*env)->GetArrayLength(env, pwd);

    /* Check whether values got actually allocated */
    if(encodedval == NULL || pwdval == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Could not allocate enough space to continue");
        goto cleanup_verify;
    }

    /* Determine Argon2 type */
    argon2_type argon2_type;
    if(! typeid_to_argon2_type(typeid, &argon2_type)) {
        throw_exception(env, "java/lang/IllegalArgumentException", "Argon2 target type must be a valid algorithm ID");
        goto cleanup_verify;
    }

    /* Check for validity */
    if(pwdlen <= 0) {
        throw_exception(env, "java/lang/IllegalArgumentException", "Password length must be positive");
        goto cleanup_verify;
    }

    int argon2_result_code = argon2_verify(encodedval, (const void*) pwdval, (const size_t) pwdlen, argon2_type);
    if(argon2_result_code == ARGON2_OK) {
        result = 1;
        goto cleanup_verify;
    }
    else if(argon2_result_code == ARGON2_VERIFY_MISMATCH) {
        result = 0;
        goto cleanup_verify;
    }
    else {
        throw_exception(env, "de/wuthoehle/argon2jni/Argon2Exception",
                        argon2_error_message(argon2_result_code));
        goto cleanup_verify;
    }

    cleanup_verify:
    if(encodedval) {
        (*env)->ReleaseStringUTFChars(env, encoded, encodedval);
    }
    if(pwdval) {
        (*env)->ReleaseByteArrayElements(env, pwd, pwdval, JNI_ABORT);
    }

    return result;
}

jint throw_exception(JNIEnv *env, const char *exception, const char *message) {
    jclass exceptionClass = (*env)->FindClass(env, exception);
    if (exceptionClass == NULL) {
        return 0;
    }

    return (*env)->ThrowNew(env, exceptionClass, message);
}

int add_encoded_result(JNIEnv* env, result_ingredients_t* target_result, const char* encoded) {
    target_result->objname = "de/wuthoehle/argon2jni/EncodedArgon2Result";
    target_result->constructorsig = "([BLjava/lang/String;)V";

    /* Try to construct a Java String object from Argon's encoded result */
    jstring jencodedResult = (*env)->NewStringUTF(env, encoded);
    if(jencodedResult == NULL) {
        return 0;
    }

    target_result->encoded = jencodedResult;
    return 1;
}

int create_result_ingredients(JNIEnv* env, const void* result, const jsize result_len, result_ingredients_t* target_result) {
    target_result->objname = "de/wuthoehle/argon2jni/Argon2Result";
    target_result->constructorsig = "([B)V";

    /* Pack raw result into a Java Byte Array */
    jbyteArray jResult = (*env)->NewByteArray(env, result_len);
    if(jResult == NULL) {
        return 0;
    }
    (*env)->SetByteArrayRegion(env, jResult, 0, result_len, (jbyte*)result);

    target_result->result = jResult;
    target_result->encoded = NULL;

    return 1;
}

jobject create_result(JNIEnv* env, const void* result, const jsize result_len, const char* encoded) {
    jobject obj = NULL;

    result_ingredients_t result_ingredients;
    if(! create_result_ingredients(env, result, result_len, &result_ingredients)) {
        throw_exception(env, "java/lang/RuntimeException", "Could not compose return values (raw)");
        goto cleanup_result;
    }

    if(encoded != NULL) {
        if(! add_encoded_result(env, &result_ingredients, encoded)) {
            throw_exception(env, "java/lang/RuntimeException", "Could not compose return values (encoded)");
            goto cleanup_result;
        }
    }

    jobject cls = (*env)->FindClass(env, result_ingredients.objname);
    if(cls == NULL) {
        throw_exception(env, "java/lang/ClassNotFoundException", "Could not find Argon2Result class");
        goto cleanup_result;
    }

    jmethodID constructor = (*env)->GetMethodID(env, cls, "<init>", result_ingredients.constructorsig);
    if(constructor == NULL) {
        throw_exception(env, "java/lang/NoSuchMethodException", "Could not find Argon2Result constructor");
        goto cleanup_result;
    }

    if(encoded == NULL) {
        obj = (*env)->NewObject(env, cls, constructor, result_ingredients.result);
    }
    else {
        obj = (*env)->NewObject(env, cls, constructor, result_ingredients.result, result_ingredients.encoded);
    }
    if(obj == NULL) {
        throw_exception(env, "java/lang/InstantiationException", "There was an error while creating the Argon2Result object");
        goto cleanup_result;
    }

    cleanup_result:
    /* Not sure if the NewByteArray and NewStringUTF values need to be cleaned up somehow in case of an error */
    /* If yes, do it here */
    return obj;
}

int typeid_to_argon2_type(const jint typeid, argon2_type* target_type) {
    /* Determine Argon2 algorithm */
    switch(typeid) {
        case ARGON2JNI_ARGON2D_ID:
            *target_type = Argon2_d;
            return 1;
        case ARGON2JNI_ARGON2I_ID:
            *target_type = Argon2_i;
            return 1;
        case ARGON2JNI_ARGON2ID_ID:
            *target_type = Argon2_id;
            return 1;
        default:
            return 0;
    }
}

int versionid_to_argon2_version(const jint versionid, argon2_version* target_version) {
    /* Determine Argon2 version */
    switch(versionid) {
        case ARGON2JNI_ARGON2_VERSION10_ID:
            *target_version = ARGON2_VERSION_10;
            return 1;
        case ARGON2JNI_ARGON2_VERSION13_ID:
            *target_version = ARGON2_VERSION_13;
            return 1;
        default:
            return 0;
    }
}

#ifdef __cplusplus
}
#endif