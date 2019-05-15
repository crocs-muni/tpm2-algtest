#include "perf_util.h"
#include "util.h"
#include "object_util.h"
#include "logging.h"

#include <time.h>

TPM2_RC sign(
        TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT keyHandle,
        const TPMT_SIG_SCHEME *inScheme,
        const TPM2B_DIGEST *digest,
        TPMT_SIGNATURE *signature,
        double *duration)
{
    /* Cmd parameters */
    TSS2L_SYS_AUTH_COMMAND cmdAuthsArray = prepare_session();
    TPMT_TK_HASHCHECK validation = {
        .tag = TPM2_ST_HASHCHECK,
        .hierarchy = TPM2_RH_NULL,
        .digest = { .size = 0 },
    };

    /* Rsp parameters */
    TSS2L_SYS_AUTH_RESPONSE rspAuthsArray;

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    TPM2_RC rc = Tss2_Sys_Sign(sapi_context, keyHandle, &cmdAuthsArray,
            digest, inScheme, &validation, signature,
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
        const TPM2B_IV *inIv,
        const TPM2B_MAX_BUFFER *inData,
        double *duration)
{
    /* Cmd parameters */
    TSS2L_SYS_AUTH_COMMAND cmdAuthsArray = prepare_session();

    /* Rsp parameters */
    TPM2B_MAX_BUFFER outData;
    TPM2B_IV outIv;
    TSS2L_SYS_AUTH_RESPONSE rspAuthsArray;

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    TPM2_RC rc = Tss2_Sys_EncryptDecrypt(sapi_context, keyHandle, &cmdAuthsArray,
            TPM2_NO, TPM2_ALG_CBC, inIv, inData, &outData, &outIv, &rspAuthsArray);

    clock_gettime(CLOCK_MONOTONIC, &end);
    if (duration != NULL) {
        *duration = get_duration_s(&start, &end);
    }
    return rc;
}
