#include "perf_util.h"
#include "util.h"
#include "object_util.h"

#include <time.h>

TPM2_RC sign(
        TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT keyHandle,
        const TPMT_SIG_SCHEME *inScheme,
        const TPM2B_DIGEST *digest,
        TPMT_SIGNATURE *signature,
        TPM2B_ECC_POINT *noncePoint,
        double *duration,
        double *duration_extra)
{
    /* Cmd parameters */
    TSS2L_SYS_AUTH_COMMAND cmdAuthsArray = prepare_session();
    TPMT_TK_HASHCHECK validation = {
        .tag = TPM2_ST_HASHCHECK,
        .hierarchy = TPM2_RH_NULL,
        .digest = { .size = 0 },
    };

    /* Rsp parameters */
    TSS2L_SYS_AUTH_RESPONSE rspAuthsArray = { .count = 1 };

    TPMT_SIG_SCHEME inSchemeCopy = *inScheme;
    struct timespec start, end;

    if(inSchemeCopy.scheme == TPM2_ALG_ECDAA) {
        TPM2B_ECC_POINT p1 = { .size = 4 };
        TPM2B_SENSITIVE_DATA s2 = { .size = 0 };
        TPM2B_ECC_PARAMETER y2 = { .size = 0 };
        TPM2B_ECC_POINT K = { .size = 0 };
        TPM2B_ECC_POINT L = { .size = 0 };
        TPM2B_ECC_POINT E = { .size = 0 };

        clock_gettime(CLOCK_MONOTONIC, &start);
        TPM2_RC rc = Tss2_Sys_Commit(
                sapi_context,
                keyHandle,
                &cmdAuthsArray,
                &p1,
                &s2,
                &y2,
                noncePoint ? noncePoint : &K, // BUG? The rG value seems to be stored here instead of E
                &L,
                &E,
                &inSchemeCopy.details.ecdaa.count,
                &rspAuthsArray);

        if(L.size > 4) {
            printf("Unexpected point output in TPM2_Commit: L 04");
            for(int i = 0; i < L.point.x.size; ++i) {
                printf("%02x", L.point.x.buffer[i]);
            }
            for(int i = 0; i < L.point.y.size; ++i) {
                printf("%02x", L.point.y.buffer[i]);
            }
            printf("\n");
        }

        if(E.size > 4) {
            printf("Unexpected point output in TPM2_Commit: E 04");
            for(int i = 0; i < E.point.x.size; ++i) {
                printf("%02x", E.point.x.buffer[i]);
            }
            for(int i = 0; i < E.point.y.size; ++i) {
                printf("%02x", E.point.y.buffer[i]);
            }
            printf("\n");
        }

        clock_gettime(CLOCK_MONOTONIC, &end);
        if (duration_extra != NULL) {
            *duration_extra = get_duration_s(&start, &end);
        }

        if(rc != 0) {
            return rc;
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &start);

    TPM2_RC rc = Tss2_Sys_Sign(sapi_context, keyHandle, &cmdAuthsArray,
            digest, &inSchemeCopy, &validation, signature,
            &rspAuthsArray);

    clock_gettime(CLOCK_MONOTONIC, &end);
    if (duration != NULL) {
        *duration = get_duration_s(&start, &end);
    }
    return rc;
}

TPM2_RC verifysignature(
        TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT keyHandle,
        const TPM2B_DIGEST *digest,
        const TPMT_SIGNATURE *signature,
        double *duration)
{
    /* Rsp parameters */
    TPMT_TK_VERIFIED validation;
    TSS2L_SYS_AUTH_RESPONSE rspAuthsArray;

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    TPM2_RC rc = Tss2_Sys_VerifySignature(sapi_context, keyHandle,
            NULL, digest, signature, &validation, &rspAuthsArray);

    clock_gettime(CLOCK_MONOTONIC, &end);
    if (duration != NULL) {
        *duration = get_duration_s(&start, &end);
    }
    return rc;
}

TPM2_RC rsa_encrypt(
        TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT keyHandle,
        const TPM2B_PUBLIC_KEY_RSA *message,
        const TPMT_RSA_DECRYPT *inScheme,
        TPM2B_PUBLIC_KEY_RSA *outData,
        double *duration)
{
    /* Cmd parameters */
    TPM2B_DATA label = { .size = 0 };

    /* Rsp parameters */
    TSS2L_SYS_AUTH_RESPONSE rspAuthsArray;

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    TPM2_RC rc = Tss2_Sys_RSA_Encrypt(sapi_context, keyHandle, NULL,
            message, inScheme, &label, outData, &rspAuthsArray);

    clock_gettime(CLOCK_MONOTONIC, &end);
    if (duration != NULL) {
        *duration = get_duration_s(&start, &end);
    }
    return rc;
}

TPM2_RC rsa_decrypt(
        TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT keyHandle,
        const TPM2B_PUBLIC_KEY_RSA *cipherText,
        const TPMT_RSA_DECRYPT *inScheme,
        TPM2B_PUBLIC_KEY_RSA *message,
        double *duration)
{
    /* Cmd parameters */
    TSS2L_SYS_AUTH_COMMAND cmdAuthsArray = prepare_session();
    TPM2B_DATA label = { .size = 0 };

    /* Rsp parameters */
    TSS2L_SYS_AUTH_RESPONSE rspAuthsArray;

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    TPM2_RC rc = Tss2_Sys_RSA_Decrypt(sapi_context, keyHandle, &cmdAuthsArray,
            cipherText, inScheme, &label, message, &rspAuthsArray);

    clock_gettime(CLOCK_MONOTONIC, &end);
    if (duration != NULL) {
        *duration = get_duration_s(&start, &end);
    }
    return rc;
}

TPM2_RC getrandom(
        TSS2_SYS_CONTEXT *sapi_context,
        double *duration)
{
    TPM2B_DIGEST randomBytes = { .size = 0 };
    TSS2L_SYS_AUTH_RESPONSE rspAuthsArray;

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    TPM2_RC rc = Tss2_Sys_GetRandom(sapi_context, NULL, 32, &randomBytes,
            &rspAuthsArray);

    clock_gettime(CLOCK_MONOTONIC, &end);
    if (duration != NULL) {
        *duration = get_duration_s(&start, &end);
    }
    return rc;
}

TPM2_RC encryptdecrypt(
        TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT keyHandle,
        TPMI_YES_NO decrypt,
        const TPM2B_IV *inIv,
        const TPM2B_MAX_BUFFER *inData,
        double *duration,
        bool deprecated)
{
    /* Cmd parameters */
    TSS2L_SYS_AUTH_COMMAND cmdAuthsArray = prepare_session();

    /* Rsp parameters */
    TPM2B_MAX_BUFFER outData;
    TPM2B_IV outIv;
    TSS2L_SYS_AUTH_RESPONSE rspAuthsArray;

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    TPM2_RC rc = deprecated ?
        Tss2_Sys_EncryptDecrypt(sapi_context, keyHandle, &cmdAuthsArray, decrypt, TPM2_ALG_NULL, inIv, inData, &outData, &outIv, &rspAuthsArray) :
        Tss2_Sys_EncryptDecrypt2(sapi_context, keyHandle, &cmdAuthsArray, inData, decrypt, TPM2_ALG_NULL, inIv, &outData, &outIv, &rspAuthsArray);

    clock_gettime(CLOCK_MONOTONIC, &end);
    if (duration != NULL) {
        *duration = get_duration_s(&start, &end);
    }
    return rc;
}

TPM2_RC hmac(
        TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT handle,
        const TPM2B_MAX_BUFFER *buffer,
        TPMI_ALG_HASH hashAlg,
        double *duration)
{
    /* Cmd parameters */
    TSS2L_SYS_AUTH_COMMAND cmdAuthsArray = prepare_session();

    /* Rsp parameters */
    TPM2B_DIGEST outHMAC = { .size = 0 };
    TSS2L_SYS_AUTH_RESPONSE rspAuthsArray;

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    TPM2_RC rc = Tss2_Sys_HMAC(sapi_context, handle, &cmdAuthsArray, buffer,
            hashAlg, &outHMAC, &rspAuthsArray);

    clock_gettime(CLOCK_MONOTONIC, &end);
    if (duration != NULL) {
        *duration = get_duration_s(&start, &end);
    }
    return rc;
}

TPM2_RC hash(
        TSS2_SYS_CONTEXT *sapi_context,
        const TPM2B_MAX_BUFFER *data,
        TPMI_ALG_HASH hashAlg,
        double *duration)
{
    TPM2B_DIGEST outHash = { .size = 0 };
    TPMT_TK_HASHCHECK validation;
    TSS2L_SYS_AUTH_RESPONSE rspAuthsArray;

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    TPM2_RC rc = Tss2_Sys_Hash(sapi_context, NULL, data, hashAlg,
            TPM2_RH_NULL, &outHash, &validation, &rspAuthsArray);

    clock_gettime(CLOCK_MONOTONIC, &end);
    if (duration != NULL) {
        *duration = get_duration_s(&start, &end);
    }
    return rc;
}

TPM2_RC ec_ephemeral(
        TSS2_SYS_CONTEXT *sapi_context,
        TPMI_ECC_CURVE curveID,
        TPM2B_ECC_POINT *outPoint,
        UINT16 *counter,
        double *duration)
{
    /* Rsp parameters */
    TSS2L_SYS_AUTH_RESPONSE rspAuthsArray;

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    TPM2_RC rc = Tss2_Sys_EC_Ephemeral(sapi_context, NULL,
                               curveID,
                               outPoint, counter,
                               &rspAuthsArray);

    clock_gettime(CLOCK_MONOTONIC, &end);
    if (duration != NULL) {
        *duration = get_duration_s(&start, &end);
    }
    return rc;
}

TPM2_RC zgen_2phase(
        TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT keyHandle,
        const TPM2B_ECC_POINT *inQsB,
        const TPM2B_ECC_POINT *inQeB,
        TPMI_ECC_KEY_EXCHANGE inScheme,
        UINT16 counter,
        TPM2B_ECC_POINT *outZ1,
        TPM2B_ECC_POINT *outZ2,
        double *duration)
{
    /* Cmd parameters */
    TSS2L_SYS_AUTH_COMMAND cmdAuthsArray = prepare_session();

    /* Rsp parameters */
    TSS2L_SYS_AUTH_RESPONSE rspAuthsArray;

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    TPM2_RC rc = Tss2_Sys_ZGen_2Phase(sapi_context, keyHandle, &cmdAuthsArray,
                                      inQsB, inQeB, inScheme, counter,
                                      outZ1, outZ2,
                                      &rspAuthsArray);

    clock_gettime(CLOCK_MONOTONIC, &end);
    if (duration != NULL) {
        *duration = get_duration_s(&start, &end);
    }
    return rc;
}
