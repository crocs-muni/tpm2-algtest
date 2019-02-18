#include "create_util.h"
#include "logging.h"
#include "util.h"

#include <tss2/tss2_sys.h>
#include <time.h>

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
        .sessionAttributes = TPMA_SESSION_CONTINUESESSION, // TPMA_SESSION
        .hmac = { .size = 0, /* .buffer */ }        // TPM2B_AUTH
    };

    TSS2L_SYS_AUTH_COMMAND cmdAuthsArray = {
        .count = 1,
        .auths = { sessionData }
    };
    return cmdAuthsArray;
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

TPM2B_PUBLIC prepare_template_RSA_primary(TPMI_RSA_KEY_BITS keyBits)
{
    return (TPM2B_PUBLIC) {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes =
                TPMA_OBJECT_RESTRICTED
                | TPMA_OBJECT_DECRYPT
                | TPMA_OBJECT_FIXEDTPM
                | TPMA_OBJECT_FIXEDPARENT
                | TPMA_OBJECT_SENSITIVEDATAORIGIN
                | TPMA_OBJECT_USERWITHAUTH,
            .authPolicy = { .size = 0 },
            .parameters = {
                .rsaDetail = {
            //        .symmetric = TPM2_ALG_NULL,

                    .symmetric = {
                        .algorithm = TPM2_ALG_AES,
                        .keyBits = 128,
                        .mode = TPM2_ALG_NULL,
                    },

                    .scheme = TPM2_ALG_NULL,
                    .keyBits = keyBits,
                    .exponent = 0
                }
            }
        }
    };
}

TPM2B_PUBLIC prepare_template_SYMCIPHER_primary()
{
    return (TPM2B_PUBLIC) {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_SYMCIPHER,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes =
                TPMA_OBJECT_RESTRICTED
                | TPMA_OBJECT_DECRYPT
                | TPMA_OBJECT_FIXEDTPM
                | TPMA_OBJECT_FIXEDPARENT
                | TPMA_OBJECT_SENSITIVEDATAORIGIN
                | TPMA_OBJECT_USERWITHAUTH,
            .authPolicy = { .size = 0 },
            .parameters = {
                .symDetail = {
                    .sym = {
                        .algorithm = TPM2_ALG_AES,
                        .keyBits = { .sym = 128 },
                        .mode = TPM2_ALG_CFB,
                    }
                }
            }
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
                | TPMA_OBJECT_FIXEDTPM
                | TPMA_OBJECT_FIXEDPARENT
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
                | TPMA_OBJECT_FIXEDTPM
                | TPMA_OBJECT_FIXEDPARENT
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
#if 1
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
        double *duration)
{
    /* Cmd parameters */
    TSS2L_SYS_AUTH_COMMAND cmdAuthsArray = prepare_session();
    TPM2B_SENSITIVE_CREATE inSensitive = prepare_null_authorization();
    TPM2B_DATA outsideInfo = { .size = 0 };
    TPML_PCR_SELECTION creationPCR = { .count = 0 };

    /* Rsp parameters */
    TPM2B_PRIVATE outPrivate = { .size = 0 };
    TPM2B_PUBLIC outPublic = { .size = 0 };
    TPM2B_CREATION_DATA creationData = { .size = 0 };
    TPM2B_DIGEST creationHash = { .size = 0 };
    TPMT_TK_CREATION creationTicket;
    TSS2L_SYS_AUTH_RESPONSE rspAuthsArray;

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    TPM2_RC rc = Tss2_Sys_Create(sapi_context,
            primary_handle, &cmdAuthsArray,
            &inSensitive, inPublic, &outsideInfo, &creationPCR,
            &outPrivate, &outPublic, &creationData, &creationHash,
            &creationTicket, &rspAuthsArray);

    clock_gettime(CLOCK_MONOTONIC, &end);
    if (duration != NULL) {
        *duration = get_duration_s(&start, &end);
    }
    return rc;
}
#if 0
TPM2_RC create_SYMCIPHER_primary(
        TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT *created_handle)
{
    struct create_params params;
    TPMA_OBJECT objectAttributes =
        TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT
        | TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT
        | TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH;
    prepare_create_primary_params(&params, objectAttributes);

    /* Create RSA template */
    params.inPublic.publicArea.type = TPM2_ALG_RSA;
    TPMU_PUBLIC_PARMS parameters = {
        .rsaDetail = {          // TPMS_RSA_PARMS
            .symmetric = {              // TPMT_SYM_DEF_OBJECT
                .algorithm = TPM2_ALG_AES,  // TPMI_ALG_SYM_OBJECT
                .keyBits = 128,             // TPMU_SYM_KEY_BITS
                .mode = TPM2_ALG_NULL,        // TPMU_SYM_MODE
            },
            .scheme = TPM2_ALG_NULL,        // TPMT_RSA_SCHEME+
            .keyBits = 1024,
            .exponent = 0
        }
    };
    params.inPublic.publicArea.parameters = parameters;

    TPM2_RC rc = test_parms(sapi_context, &params);
    if (rc != TPM2_RC_SUCCESS) {
        fprintf(stderr, "TPM2_Create: cannot create parent object! (%04x)\n", rc);
    }

    TPM2_HANDLE objectHandle;
    TPM2B_PUBLIC outPublic = { .size = 0 };
    TPM2B_CREATION_DATA creationData = { .size = 0 };
    TPM2B_DIGEST creationHash = { .size = 0 };
    TPMT_TK_CREATION creationTicket;
    TPM2B_NAME name = { .size = 0 };
    TSS2L_SYS_AUTH_RESPONSE rspAuthsArray; // sessionsDataOut

    TPMI_RH_HIERARCHY primaryHandle = TPM2_RH_NULL;

    rc = Tss2_Sys_CreatePrimary(sapi_context,
            primaryHandle, &params.cmdAuthsArray,
            &params.inSensitive, &params.inPublic, &params.outsideInfo,
            &params.creationPCR, &objectHandle, &outPublic,
            &creationData, &creationHash,
            &creationTicket, &name, &rspAuthsArray);

    *created_handle = objectHandle;
    return rc;
}
#endif
