#include "sign.h"
#include "create.h"
#include "createprimary.h"
#include "util.h"
#include "context.h"

#include <string.h>
#include <stdio.h>

extern struct tpm_algtest_ctx ctx;

static
TPM2_RC create_RSA_signing_parent(TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT *parentHandle, TPMI_RSA_KEY_BITS keyBits)
{
    struct create_params params;
    TPMA_OBJECT objectAttributes =
        TPMA_OBJECT_SIGN_ENCRYPT
        | TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT
        | TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH;
    prepare_create_primary_params(&params, objectAttributes);

    /* Create RSA template */
    params.inPublic.publicArea.type = TPM2_ALG_RSA;
    TPMU_PUBLIC_PARMS parameters = {
        .rsaDetail = {          // TPMS_RSA_PARMS
            .symmetric = TPM2_ALG_NULL,
            .scheme = {
                .scheme = TPM2_ALG_RSASSA,
                .details = {
                    .rsassa = { .hashAlg = TPM2_ALG_SHA256 }
                }
            },
            .keyBits = keyBits,
            .exponent = 0
        }
    };
    params.inPublic.publicArea.parameters = parameters;

    TPM2_RC rc = test_parms(sapi_context, &params);
    if (rc != TPM2_RC_SUCCESS) {
        return rc;
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

    *parentHandle = objectHandle;
    return rc;
}

static
void test_and_measure(TSS2_SYS_CONTEXT *sapi_context, char *param_fields,
        TPMI_DH_OBJECT parentHandle, TPM2B_DIGEST *digest,
        FILE *out, FILE *out_all)
{
    TPMT_SIG_SCHEME inScheme = { .scheme = TPM2_ALG_NULL };
    TPMT_TK_HASHCHECK validation = {
        .tag = TPM2_ST_HASHCHECK,
        .hierarchy = TPM2_RH_NULL,
        .digest = { .size = 0 }
    };

    /* Create password session, w/ 0-length password */
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

    struct summary summary;
    init_summary(&summary);

    unsigned repetitions = ctx.repetitions ? ctx.repetitions : 100;
    for (unsigned i = 0; i < repetitions; ++i) {
        TPMT_SIGNATURE signature;
        TSS2L_SYS_AUTH_RESPONSE rspAuthsArray; // sessionsDataOut

        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        TPM2_RC rc = Tss2_Sys_Sign(sapi_context,
                parentHandle, &cmdAuthsArray,
                digest, &inScheme, &validation,
                &signature, &rspAuthsArray);
        clock_gettime(CLOCK_MONOTONIC, &end);
        double duration = get_duration_sec(&start, &end);
        printf("param: %s | %fs | rc: %04x\n", param_fields, duration, rc);
        if (rc != TPM2_RC_SUCCESS) {
            update_error_codes(rc, &summary.seen_error_codes);
            continue;
        }
        add_measurement(duration, &summary.measurements);

        fprintf(out_all, "%s;%f;%04x\n", param_fields, duration, rc);
    }
    print_summary_to_file(out, param_fields, &summary);
}


void test_Sign(TSS2_SYS_CONTEXT *sapi_context)
{
    printf("TPM2_Sign:\n");

    FILE* out_all = open_csv("TPM2_Sign_all.csv",
            "keyBits;digest;duration_mean;error_codes", "w");
    FILE* out = open_csv("TPM2_Sign.csv",
            "keyBits;digest;duration;return_code", "w");

    for (TPMI_RSA_KEY_BITS keyBits = 0; keyBits <= 2048; keyBits += 32) {
        TPMI_DH_OBJECT parentHandle;
        TPM2_RC rc = create_RSA_signing_parent(
                sapi_context, &parentHandle, keyBits);
        if (rc != TPM2_RC_SUCCESS) {
            continue;
        }
        printf("TPM2_Sign: created RSA %db signing key with handle %08x\n",
                keyBits, parentHandle);
        char param_fields[16];
        TPM2B_DIGEST digest = { .size = 32 };

        snprintf(param_fields, 16, "%d;0xFF", keyBits);
        memset(&digest.buffer, 0xFF, 32);
        test_and_measure(sapi_context, param_fields, parentHandle, &digest,
                out, out_all);

        snprintf(param_fields, 16, "%d;0x00", keyBits);
        memset(&digest.buffer, 0x00, 32);
        test_and_measure(sapi_context, param_fields, parentHandle, &digest,
                out, out_all);

        Tss2_Sys_FlushContext(sapi_context, parentHandle);
    }

    fclose(out_all);
    fclose(out);
}
