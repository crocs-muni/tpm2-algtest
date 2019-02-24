#include "object_util.h"
#include "logging.h"
#include "util.h"

#include <tss2/tss2_sys.h>
#include <tss2/tss2_mu.h>
#include <time.h>
#include <string.h>

TPM2_RC test_parms(
        TSS2_SYS_CONTEXT *sapi_context,
        const TPMT_PUBLIC *publicArea)
{
    TPMT_PUBLIC_PARMS parameters = {
        .type = publicArea->type,
        .parameters = publicArea->parameters
    };
    return Tss2_Sys_TestParms(sapi_context, NULL, &parameters, NULL);
}

TSS2L_SYS_AUTH_COMMAND prepare_session()
{
    /* Create password session with 0-length password */
    TPMS_AUTH_COMMAND sessionData = {
        .sessionHandle = TPM2_RS_PW,                // TPMI_SH_AUTH_SESSION
        .nonce = { .size = 0, /* .buffer */ },      // TPM2B_NONCE
        // TODO try removing this flag
        .sessionAttributes = TPMA_SESSION_CONTINUESESSION, // TPMA_SESSION
        .hmac = { .size = 0, /* .buffer */ }        // TPM2B_AUTH
    };

    TSS2L_SYS_AUTH_COMMAND cmdAuthsArray = {
        .count = 1,
        .auths = { sessionData }
    };
    return cmdAuthsArray;
}

TSS2L_SYS_AUTH_COMMAND prepare_dup_policy_session(TSS2_SYS_CONTEXT *sapi_context,
        TPMI_SH_AUTH_SESSION *sessionHandle)
{
    TPMI_DH_OBJECT tpmKey = TPM2_RH_NULL;
    TPMI_DH_ENTITY bind = TPM2_RH_NULL;
    TPM2B_NONCE nonceCaller = { .size = 16 };
    TPM2B_ENCRYPTED_SECRET encryptedSalt = { .size = 0 };
    TPM2_SE sessionType = TPM2_SE_POLICY;
    TPMT_SYM_DEF symmetric = { .algorithm = TPM2_ALG_NULL };
    TPMI_ALG_HASH authHash = TPM2_ALG_SHA256;
    TPM2B_NONCE nonceTPM = { .size = 0 };
    TSS2L_SYS_AUTH_RESPONSE rspAuthsArray;
    TPM2_RC rc = Tss2_Sys_StartAuthSession(sapi_context,
            tpmKey, bind, NULL, &nonceCaller, &encryptedSalt, sessionType,
            &symmetric, authHash, sessionHandle, &nonceTPM, &rspAuthsArray);
    if (rc != TPM2_RC_SUCCESS) {
        log_error("Cannot start DUP policy session! (%0x4)", rc);
    }
    TPM2B_DIGEST authPolicy;
    rc = Tss2_Sys_PolicyCommandCode(sapi_context, *sessionHandle, NULL,
            TPM2_CC_Duplicate, NULL);
    if (rc != TPM2_RC_SUCCESS) {
        log_error("Cannot policy command code %04x", rc);
    }
    rc = Tss2_Sys_PolicyGetDigest(sapi_context, *sessionHandle, NULL, &authPolicy, NULL);
    if (rc != TPM2_RC_SUCCESS) {
        log_error("Cannot get digest (%0x4)", rc);
    }

    TPMS_AUTH_COMMAND sessionData = {
        .sessionHandle = *sessionHandle,
        .nonce = { .size = 0 },
        .sessionAttributes = TPMA_SESSION_CONTINUESESSION,
        .hmac = { .size = 0 }
    };
    TSS2L_SYS_AUTH_COMMAND cmdAuthsArray = {
        .count = 1,
        .auths = { sessionData }
    };
    return cmdAuthsArray;
}

TPM2B_DIGEST create_dup_policy(TSS2_SYS_CONTEXT *sapi_context)
{
    TPMI_DH_OBJECT tpmKey = TPM2_RH_NULL;
    TPMI_DH_ENTITY bind = TPM2_RH_NULL;
    TPM2B_NONCE nonceCaller = { .size = 16 };
    TPM2B_ENCRYPTED_SECRET encryptedSalt = { .size = 0 };
    TPM2_SE sessionType = TPM2_SE_TRIAL;
    TPMT_SYM_DEF symmetric = { .algorithm = TPM2_ALG_NULL };
    TPMI_ALG_HASH authHash =  TPM2_ALG_SHA256;
    TPM2B_NONCE nonceTPM = { .size = 0 };
    TPMI_SH_AUTH_SESSION sessionHandle;
    TPM2_RC rc = Tss2_Sys_StartAuthSession(sapi_context, tpmKey, bind, NULL,
            &nonceCaller, &encryptedSalt, sessionType, &symmetric, authHash,
            &sessionHandle, &nonceTPM, NULL);
    if (rc != TPM2_RC_SUCCESS) {
        log_error("Cannot create trial session! (%04x)", rc);
    }
    TPM2B_DIGEST authPolicy;
    rc = Tss2_Sys_PolicyCommandCode(sapi_context, sessionHandle, NULL,
            TPM2_CC_Duplicate, NULL);
    if (rc != TPM2_RC_SUCCESS) {
        log_error("Cannot policy command code %04x", rc);
    }
    rc = Tss2_Sys_PolicyGetDigest(sapi_context, sessionHandle, NULL, &authPolicy, NULL);
    if (rc != TPM2_RC_SUCCESS) {
        log_error("Cannot get digest (%0x4)", rc);
    }
    Tss2_Sys_FlushContext(sapi_context, sessionHandle);
    return authPolicy;
}

TPM2B_SENSITIVE_CREATE prepare_null_authorization()
{
    return (TPM2B_SENSITIVE_CREATE) {
        .size = 0,
        .sensitive = {
            .userAuth = { .size = 0 },
            .data = { .size = 0 }
        }
    };
}

TPM2B_PUBLIC prepare_template_RSA(TPMI_RSA_KEY_BITS keyBits)
{
    return (TPM2B_PUBLIC) {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes =
                TPMA_OBJECT_SIGN_ENCRYPT
                | TPMA_OBJECT_DECRYPT
                | TPMA_OBJECT_SENSITIVEDATAORIGIN
                | TPMA_OBJECT_USERWITHAUTH,
            .authPolicy = { .size = 0 },
            .parameters = {
                .rsaDetail = {
                    .symmetric = TPM2_ALG_NULL,
                    .scheme = TPM2_ALG_NULL,
                    .keyBits = keyBits,
                    .exponent = 0
                }
            }
        }
    };
}

TPM2B_PUBLIC prepare_template_ECC(TPMI_ECC_CURVE curveID)
{
    return (TPM2B_PUBLIC) {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes =
                TPMA_OBJECT_SIGN_ENCRYPT
                | TPMA_OBJECT_DECRYPT
                | TPMA_OBJECT_SENSITIVEDATAORIGIN
                | TPMA_OBJECT_USERWITHAUTH,
            .authPolicy = { .size = 0 },
            .parameters = {
                .eccDetail = {
                    .symmetric = TPM2_ALG_NULL,
                    .scheme = TPM2_ALG_NULL,
                    .curveID = curveID,
                    .kdf = TPM2_ALG_NULL
                }
            }
        }
    };
}

TPM2B_PUBLIC prepare_template_RSA_primary(TPMI_RSA_KEY_BITS keyBits)
{
    TPM2B_PUBLIC public = prepare_template_RSA(keyBits);
    public.publicArea.objectAttributes |=
        TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT;
    public.publicArea.objectAttributes &= ~TPMA_OBJECT_SIGN_ENCRYPT;
    public.publicArea.parameters.rsaDetail.symmetric = (TPMT_SYM_DEF_OBJECT) {
        .algorithm = TPM2_ALG_AES,
        .keyBits = 128,
        .mode = TPM2_ALG_NULL,
    };
    return public;
}

TPM2B_PUBLIC prepare_template_ECC_primary(TPMI_ECC_CURVE curveID)
{
    TPM2B_PUBLIC public = prepare_template_ECC(curveID);
    public.publicArea.objectAttributes |=
        TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT;
    public.publicArea.objectAttributes &= ~TPMA_OBJECT_SIGN_ENCRYPT;
    public.publicArea.parameters.eccDetail.symmetric = (TPMT_SYM_DEF_OBJECT) {
        .algorithm = TPM2_ALG_AES,
        .keyBits = 128,
        .mode = TPM2_ALG_NULL,
    };
    return public;
}
#if 0
void prepare_create_params(struct create_params *params)
{
    params->cmdAuthsArray = prepare_session();
    params->inSensitive = prepare_null_authorization();
    params->outsideInfo.size = 0;
    params->creationPCR.count = 0;

    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {                         // TPMT_PUBLIC
            .nameAlg = TPM2_ALG_SHA256,             // TPMI_ALG_HASH
            .objectAttributes =                     // TPMA_OBJECT
                TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_DECRYPT
                | TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT
                | TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH,
            .authPolicy = { .size = 0, /* buffer */ }, // TPM2B_DIGEST
        }
    };
    params->inPublic = inPublic;
}
#endif
#if 0
void prepare_create_primary_params(struct create_params *params,
        TPMA_OBJECT objectAttributes)
{
    params->cmdAuthsArray = prepare_session();
    params->inSensitive = prepare_null_authorization();
    params->outsideInfo.size = 0;
    params->creationPCR.count = 0;

    TPM2B_PUBLIC inPublic = {
        .size = 0, // doesn't need to be set
        .publicArea = {                         // TPMT_PUBLIC
            .nameAlg = TPM2_ALG_SHA256,             // TPMI_ALG_HASH
            .objectAttributes = objectAttributes,
            .authPolicy = { .size = 0, /* buffer */ }, // TPM2B_DIGEST
        }
    };
    params->inPublic = inPublic;
}
#endif

TPM2_RC create_some_primary(TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT *primary_handle)
{
    TPM2B_PUBLIC inPublic;
    TPM2_RC rc;
    for (TPMI_ECC_CURVE curveID = 0x0000; curveID <= 0x0020; ++curveID) {
        inPublic = prepare_template_ECC_primary(curveID);
        rc = create_primary(sapi_context, &inPublic, primary_handle);
        if (rc == TPM2_RC_SUCCESS) {
            log_info("Created ECC 0x%04x primary key", curveID);
            return rc;
        }
    }
    inPublic = prepare_template_RSA_primary(1024);
    rc = create_primary(sapi_context, &inPublic, primary_handle);
    if (rc == TPM2_RC_SUCCESS) {
        log_info("Created RSA 1024 primary key");
        return rc;
    }
    inPublic = prepare_template_RSA_primary(2048);
    rc = create_primary(sapi_context, &inPublic, primary_handle);
    if (rc == TPM2_RC_SUCCESS) {
        log_info("Created RSA 2048 primary key");
        return rc;
    }
    log_error("Cannot create any primary key! (%04x)", rc);
    return rc;
}

TPM2_RC create_primary(
        TSS2_SYS_CONTEXT *sapi_context,
        const TPM2B_PUBLIC *inPublic,
        TPMI_DH_OBJECT *created_handle)
{
    /* Cmd parameters */
    TPMI_RH_HIERARCHY primaryHandle = TPM2_RH_NULL;
    TSS2L_SYS_AUTH_COMMAND cmdAuthsArray = prepare_session();
    TPM2B_SENSITIVE_CREATE inSensitive = prepare_null_authorization();
    TPM2B_DATA outsideInfo = { .size = 0 };
    TPML_PCR_SELECTION creationPCR = { .count = 0 };

    /* Rsp parameters */
    TPM2_HANDLE objectHandle;
    TPM2B_PUBLIC outPublic = { .size = 0 };
    TPM2B_CREATION_DATA creationData = { .size = 0 };
    TPM2B_DIGEST creationHash = { .size = 0 };
    TPMT_TK_CREATION creationTicket;
    TPM2B_NAME name = { .size = 0 };
    TSS2L_SYS_AUTH_RESPONSE rspAuthsArray; // sessionsDataOut

    TPM2_RC rc = Tss2_Sys_CreatePrimary(sapi_context,
            primaryHandle, &cmdAuthsArray,
            &inSensitive, inPublic, &outsideInfo, &creationPCR,
            &objectHandle, &outPublic, &creationData, &creationHash,
            &creationTicket, &name, &rspAuthsArray);

    *created_handle = objectHandle;
    return rc;
}

TPM2_RC create(
        TSS2_SYS_CONTEXT *sapi_context,
        const TPM2B_PUBLIC *inPublic,
        TPMI_DH_OBJECT primary_handle,
        TPM2B_PUBLIC *outPublic,
        TPM2B_PRIVATE *outPrivate,
        double *duration)
{
    /* Cmd parameters */
    TSS2L_SYS_AUTH_COMMAND cmdAuthsArray = prepare_session();
    TPM2B_SENSITIVE_CREATE inSensitive = prepare_null_authorization();
    TPM2B_DATA outsideInfo = { .size = 0 };
    TPML_PCR_SELECTION creationPCR = { .count = 0 };

    /* Rsp parameters */
    TPM2B_CREATION_DATA creationData = { .size = 0 };
    TPM2B_DIGEST creationHash = { .size = 0 };
    TPMT_TK_CREATION creationTicket;
    TSS2L_SYS_AUTH_RESPONSE rspAuthsArray;

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    TPM2_RC rc = Tss2_Sys_Create(sapi_context,
            primary_handle, &cmdAuthsArray,
            &inSensitive, inPublic, &outsideInfo, &creationPCR,
            outPrivate, outPublic, &creationData, &creationHash,
            &creationTicket, &rspAuthsArray);

    clock_gettime(CLOCK_MONOTONIC, &end);
    if (duration != NULL) {
        *duration = get_duration_s(&start, &end);
    }

    return rc;
}

TPM2_RC load(
        TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT parentHandle,
        TPM2B_PRIVATE *inPrivate,
        TPM2B_PUBLIC *inPublic,
        TPM2_HANDLE *objectHandle)
{
    TSS2L_SYS_AUTH_COMMAND cmdAuthsArray = prepare_session();
    TPM2B_NAME name = { .size = 0 };
    TSS2L_SYS_AUTH_RESPONSE rspAuthsArray;
    TPM2_RC rc = Tss2_Sys_Load(sapi_context, parentHandle, &cmdAuthsArray,
            inPrivate, inPublic, objectHandle, &name, &rspAuthsArray);
    return rc;
}

TPM2_RC extract_sensitive(
        TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT objectHandle,
        TPMU_SENSITIVE_COMPOSITE *sensitive)
{
    TPMI_SH_AUTH_SESSION sessionHandle;
    TSS2L_SYS_AUTH_COMMAND cmdAuthsArray = prepare_dup_policy_session(sapi_context, &sessionHandle);
    TPM2B_DATA encryptionKeyIn = { .size = 0 };
    TPMT_SYM_DEF_OBJECT symmetricAlg = { .algorithm = TPM2_ALG_NULL };
    TPM2B_DATA encryptionKeyOut;
    TPM2B_ENCRYPTED_SECRET outSymSeed;
    TSS2L_SYS_AUTH_RESPONSE rspAuthsArray;
    TPM2B_PRIVATE duplicate;
    TPM2_RC rc = Tss2_Sys_Duplicate(sapi_context, objectHandle, TPM2_RH_NULL,
            &cmdAuthsArray, &encryptionKeyIn, &symmetricAlg,
            &encryptionKeyOut, &duplicate, &outSymSeed, &rspAuthsArray);
    Tss2_Sys_FlushContext(sapi_context, sessionHandle);

    TPM2B_SENSITIVE s = { .size = 0 };
    Tss2_MU_TPM2B_SENSITIVE_Unmarshal(duplicate.buffer, duplicate.size, 0, &s);
    *sensitive = s.sensitiveArea.sensitive;
    return rc;
}
