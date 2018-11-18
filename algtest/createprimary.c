#include "createprimary.h"
#include "utils.h"
#include "tpm2_util.h"

#include <tss2/tss2_sys.h>

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

void measure_CreatePrimary_RSA(TSS2_SYS_CONTEXT *sapi_context,
        struct createPrimaryParams params)
{
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
                    .keyBits = 1024,
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

    params.inPublic = inPublic;

    // TODO: find out which are available first and then pass them to function
    int availableKeyBits[] = { 1024, 2048 };
    int numAvailableKeyBits = 2;
    int numMeasurements = 100;

    char filename[40];
    snprintf(filename, 40, "TPM2_CreatePrimary_RSA.csv");
    FILE *out = fopen(filename, "w");
    if (!out) {
        perror(strerror(errno));
        exit(1);
    }
    char header[] = "keyBits,retval,duration,handle\n";
    fwrite(header, 1, strlen(header), out);

    for (int i = 0; i < 2; ++i) {
        int keyBits = availableKeyBits[i];
        inPublic.publicArea.parameters.rsaDetail.keyBits = keyBits;


        for (int j = 0; j < numMeasurements; ++j) {
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
            TPM2_RC retval = Tss2_Sys_CreatePrimary(sapi_context,
                    params.primaryHandle, &params.cmdAuthsArray,
                    &params.inSensitive, &params.inPublic, &params.outsideInfo,
                    &params.creationPCR, &objectHandle, &outPublic,
                    &creationData, &creationHash,
                    &creationTicket, &name, &rspAuthsArray);
            clock_gettime(CLOCK_MONOTONIC, &end);

            /* Flush context to avoid running out of memory */
            Tss2_Sys_FlushContext(sapi_context, objectHandle);

            double duration = get_duration_sec(&start, &end);
            char toWrite[256];
            snprintf(toWrite, 255, "%d,%04x,%f,%08x\n", keyBits, retval,
                    duration, objectHandle);
            fwrite(toWrite, 1, strlen(toWrite), out);
            fflush(out);

            printf("keyBits %d | %04x | %fs | handle: %08x\n", keyBits, retval,
                    duration, objectHandle);
        }
    }
    fclose(out);
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

    measure_CreatePrimary_RSA(sapi_context, params);
}

