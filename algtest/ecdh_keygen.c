#include "ecdh_keygen.h"
#include "createprimary.h"
#include "context.h"
#include "util.h"

#include <stdio.h>

extern struct tpm_algtest_ctx ctx;

static
void test_and_measure(TSS2_SYS_CONTEXT *sapi_context, TPM2_ECC_CURVE curve,
        TPMI_DH_OBJECT parentHandle, FILE *out, FILE *out_all)
{
    struct summary summary;
    init_summary(&summary);

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

    unsigned repetitions = ctx.repetitions ? ctx.repetitions : 100;
    for (unsigned i = 0; i < repetitions; ++i) {
        /* Response paramters have to be cleared before each run. */
        TPM2B_ECC_POINT zPoint = { .size = 0 };
        TPM2B_ECC_POINT pubPoint = { .size = 0 };
        TSS2L_SYS_AUTH_RESPONSE rspAuthsArray; // sessionsDataOut

        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        TPM2_RC rc = Tss2_Sys_ECDH_KeyGen(sapi_context,
                parentHandle, NULL,
                &zPoint, &pubPoint, &rspAuthsArray);
        clock_gettime(CLOCK_MONOTONIC, &end);

        // TODO: cleanup this
        if (rc == 0x02c4) {
            fprintf(stderr, "0x02c4");
            return;
        }
        double duration = get_duration_sec(&start, &end);

        // TODO: add return parameters to see if there is something interesting
        printf("curve: %04x | %fs | rc: %04x\n", curve, duration, rc);

        if (rc != TPM2_RC_SUCCESS) {
            update_error_codes(rc, &summary.seen_error_codes);
            continue;
        }
        add_measurement(duration, &summary.measurements);
        fprintf(out_all, "%04x;%f;%04x\n", curve, duration, rc);
    }
    char curve_string[8];
    sprintf(curve_string, "%04x", curve);
    print_summary_to_file(out, curve_string, &summary);
}

static
FILE *open_csv_summary()
{
    return open_csv("TPM2_ECDH_KeyGen.csv", "curve;duration_mean;error_codes", "w");
}

static
FILE *open_csv_all()
{
    return open_csv("TPM2_ECDH_KeyGen_all.csv", "curve;duration;return_code", "w");
}

TPM2_RC create_ECC(TSS2_SYS_CONTEXT *sapi_context, struct create_params *params,
        TPMI_DH_OBJECT parentHandle, TPM2_HANDLE *objectHandle)
{
    TPM2_RC rc = test_parms(sapi_context, params);
    if (rc != TPM2_RC_SUCCESS) {
        return rc;
    }
    TPM2B_PRIVATE outPrivate = { .size = 0 };
    TPM2B_PUBLIC outPublic = { .size = 0 };
    TPM2B_CREATION_DATA creationData = { .size = 0 };
    TPM2B_DIGEST creationHash = { .size = 0 };
    TPMT_TK_CREATION creationTicket;
    TSS2L_SYS_AUTH_RESPONSE rspAuthsArray; // sessionsDataOut

    // TODO: Sometimes the key is not created on first try - investigate
    for (int tries = 4; tries >= 0; --tries) {
        rc = Tss2_Sys_Create(sapi_context,
                parentHandle, &params->cmdAuthsArray,
                &params->inSensitive, &params->inPublic, &params->outsideInfo,
                &params->creationPCR, &outPrivate, &outPublic,
                &creationData, &creationHash,
                &creationTicket, &rspAuthsArray);

        if (rc == TPM2_RC_SUCCESS)
            break;
    }
    if (rc != TPM2_RC_SUCCESS)
        return rc;

    //TPM2B_SENSITIVE inPrivate = { .size = 0 };
    TPM2B_NAME name = { .size = 0 };
    rc = Tss2_Sys_Load(sapi_context, parentHandle, &params->cmdAuthsArray,
            &outPrivate, &outPublic, objectHandle, &name, &rspAuthsArray);
    return rc;
}

void test_ECDH_KeyGen_detail(TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT parentHandle)
{
    FILE *out = open_csv_summary();
    FILE *out_all = open_csv_all();

    struct create_params params;
    prepare_create_params(&params);
    params.inPublic.publicArea.type = TPM2_ALG_ECC;
    params.inPublic.publicArea.parameters.eccDetail = (TPMS_ECC_PARMS) {
        .symmetric = TPM2_ALG_NULL,
        .scheme = TPM2_ALG_NULL,
        .kdf = TPM2_ALG_NULL
    };

    for (int curve = 0x00; curve <= 0x20; ++curve) {
        params.inPublic.publicArea.parameters.eccDetail.curveID = curve;
        params.inPublic.publicArea.objectAttributes &= ~TPMA_OBJECT_DECRYPT;
        TPM2_HANDLE objectHandle;
        TPM2_RC ecc_key_created = create_ECC(sapi_context, &params, parentHandle,
                &objectHandle);
        // RC 0x02e6 - curve not supported
        if (ecc_key_created == 0x01e6) {
            continue;
        }
        if (ecc_key_created != TPM2_RC_SUCCESS) {
            fprintf(stderr, "TPM2_ECDH_KeyGen: Cannot create ECC key! (%04x)\n",
                    ecc_key_created);
        } else {
            printf("Created ECC key with handle: %08x\n", objectHandle);
        }

        test_and_measure(sapi_context, curve, objectHandle, out, out_all);

        Tss2_Sys_FlushContext(sapi_context, objectHandle);
    }

    fclose(out);
    fclose(out_all);
}

void test_ECDH_KeyGen(TSS2_SYS_CONTEXT *sapi_context)
{
    printf("TPM2_ECDH_KeyGen:\n");
    TPMI_DH_OBJECT parentHandle;
    TPM2_RC rc = create_RSA_parent(sapi_context, &parentHandle);
    if (rc != TPM2_RC_SUCCESS) {
        fprintf(stderr, "TPM2_ECDH_KeyGen: Cannot create RSA parent! (%04x)\n", rc);
        return;
    }
    printf("Created RSA parent with handle %08x\n", parentHandle);

    test_ECDH_KeyGen_detail(sapi_context, parentHandle);

    Tss2_Sys_FlushContext(sapi_context, parentHandle);
}
