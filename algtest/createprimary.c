#include "createprimary.h"
#include "utils.h"
#include "tpm2_util.h"

#include <tss2/tss2_sys.h>

#include <stdio.h>
#include <time.h>
#include <string.h>

const int numMeasurements = 10;

bool testParms(TSS2_SYS_CONTEXT *sapi_context,
        struct createPrimaryParams *params)
{
    TPMT_PUBLIC_PARMS parameters = {
        .type = params->inPublic.publicArea.type,
        .parameters = params->inPublic.publicArea.parameters
    };
    TPM2_RC rc = Tss2_Sys_TestParms(sapi_context, NULL, &parameters, NULL);
    //printf("test keybits: %d -> %04x\n", params->inPublic.publicArea.parameters.rsaDetail.keyBits, rc);
    return rc == TPM2_RC_SUCCESS;
}

void testAndMeasure(TSS2_SYS_CONTEXT *sapi_context,
        struct createPrimaryParams *params, FILE *out, FILE *outAll)
{
    if (!testParms(sapi_context, params))
        return;

    double durations[numMeasurements];

    TPM2_HANDLE handles[maxNumHandles];
    int numHandles = 0;

    TPM2_RC errorCodes[maxNumErrorCodes];
    int numErrorCodes = 0;

    for (int i = 0; i < numMeasurements; ++i) {
        /* Response paramters have to be cleared before each run. */
        TPM2_HANDLE objectHandle;
        TPM2B_PUBLIC outPublic = { .size = 0 };
        TPM2B_CREATION_DATA creationData = { .size = 0 };
        TPM2B_DIGEST creationHash = { .size = 0 };
        TPMT_TK_CREATION creationTicket;
        TPM2B_NAME name = { .size = 0 };
        TSS2L_SYS_AUTH_RESPONSE rspAuthsArray; // sessionsDataOut

        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        TPM2_RC rc = Tss2_Sys_CreatePrimary(sapi_context,
                params->primaryHandle, &params->cmdAuthsArray,
                &params->inSensitive, &params->inPublic, &params->outsideInfo,
                &params->creationPCR, &objectHandle, &outPublic,
                &creationData, &creationHash,
                &creationTicket, &name, &rspAuthsArray);
        clock_gettime(CLOCK_MONOTONIC, &end);

        /* Flush context to avoid running out of memory */
        Tss2_Sys_FlushContext(sapi_context, objectHandle);

        // TODO: cleanup this
        if (rc == 0x02c4) {
            return;
        }

        durations[i] = get_duration_sec(&start, &end);
        char toWrite[48];
        snprintf(toWrite, 47, "%d,%f,%04x,%08x\n",
                params->inPublic.publicArea.parameters.rsaDetail.keyBits,
                durations[i], rc, objectHandle);
        toWrite[47] = '\0';
        fwrite(toWrite, 1, strlen(toWrite), outAll);
        fflush(outAll);

        updateErrorCodes(rc, errorCodes, &numErrorCodes);
        updateHandles(objectHandle, handles, &numHandles);


        printf("keyBits %d | %fs | handle: %08x | rc: %04x\n",
                params->inPublic.publicArea.parameters.rsaDetail.keyBits,
                durations[i], objectHandle, rc);
    }

    char toWrite[256];
    char handlesString[handlesStringSize];
    fillHandlesString(handlesString, handles, numHandles);
    char errorCodesString[errorCodesStringSize];
    fillErrorCodesString(errorCodesString, errorCodes, numErrorCodes);

    snprintf(toWrite, 255, "%d; %f; %s; %s\n",
            params->inPublic.publicArea.parameters.rsaDetail.keyBits,
            mean(durations, numMeasurements),
            errorCodesString, handlesString);
    toWrite[255] = '\0';
    fwrite(toWrite, 1, strlen(toWrite), out);
}

void measure_CreatePrimary_RSA(TSS2_SYS_CONTEXT *sapi_context,
        struct createPrimaryParams *params)
{
    /* Create RSA template */
    TPM2B_PUBLIC inPublic = {
        .size = 0, // doesn't need to be set
        .publicArea = {             // TPMT_PUBLIC
            .type = TPM2_ALG_RSA,                   // TPMI_ALG_PUBLIC
            .nameAlg = TPM2_ALG_SHA256,             // TPMI_ALG_HASH
            .objectAttributes =                     // TPMA_OBJECT
                TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT
                | TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT
                | TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH,
            .authPolicy = { .size = 0, /* buffer */ }, // TPM2B_DIGEST
            .parameters = {                 // TPMU_PUBLIC_PARMS
                .rsaDetail = {                  // TPMS_RSA_PARMS
                    .symmetric = {              // TPMT_SYM_DEF_OBJECT
                        .algorithm = TPM2_ALG_AES,  // TPMI_ALG_SYM_OBJECT
                        .keyBits = 128,             // TPMU_SYM_KEY_BITS
                        .mode = TPM2_ALG_NULL,        // TPMU_SYM_MODE
                    },
                    .scheme = TPM2_ALG_NULL,        // TPMT_RSA_SCHEME+
                    .keyBits = 0,
                    .exponent = 0
                }
            },
            .unique = {                     // TPMU_PUBLIC_ID
                .rsa = {                        // TPM2B_PUBLIC_KEY_RSA
                    .size = 0,
                    /* buffer */
                }
            }
        }
    };

    params->inPublic = inPublic;

    FILE *out = openCSV("TPM2_CreatePrimary_RSA.csv",
            "keyBits;duration_mean;error_codes;handles\n", "w");
    FILE *outAll = openCSV("TPM2_CreatePrimary_RSA_all.csv",
            "keyBits;duration;return_code;handle\n", "w");

    for (int keyBits = 0; keyBits < 4096; keyBits += 32) {
        params->inPublic.publicArea.parameters.rsaDetail.keyBits = keyBits;
        testAndMeasure(sapi_context, params, out, outAll);
    }

    fclose(out);
    fclose(outAll);
}

void measure_CreatePrimary(TSS2_SYS_CONTEXT *sapi_context)
{
    printf("TPM2_CreatePrimary:\n");
    struct createPrimaryParams params;

    /* Use NULL hierarchy for testing */
    params.primaryHandle = TPM2_RH_NULL;        // TPMI_RH_HIERARCHY

    /* Create password session, w/ 0-length password */
    TPMS_AUTH_COMMAND sessionData = {
        .sessionHandle = TPM2_RS_PW,                // TPMI_SH_AUTH_SESSION
        .nonce = { .size = 0, /* .buffer */ },      // TPM2B_NONCE
        .sessionAttributes = TPMA_SESSION_CONTINUESESSION, // TPMA_SESSION
        .hmac = { .size = 0, /* .buffer */ }        // TPM2B_AUTH
    };
    params.sessionData = sessionData;

    TSS2L_SYS_AUTH_COMMAND cmdAuthsArray = {
        .count = 1,
        .auths = { sessionData }
    };
    params.cmdAuthsArray = cmdAuthsArray;

    /* No key authorization */
    TPM2B_SENSITIVE_CREATE inSensitive = {
        .size = 0,
        .sensitive = {                              // TPMS_SENSITIVE_CREATE
            .userAuth = { .size = 0, /* buffer */ },    // TPM2B_AUTH
            .data = { .size = 0, /* buffer */ },        // TPM2B_SENSITIVE_DATA
        }
    };
    params.inSensitive = inSensitive;
    params.outsideInfo.size = 0;
    params.creationPCR.count = 0;

    measure_CreatePrimary_RSA(sapi_context, &params);
    //measure_CreatePrimary_ECC(sapi_context, &params);
}

