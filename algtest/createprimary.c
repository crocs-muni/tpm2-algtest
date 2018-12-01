#include "createprimary.h"
#include "util.h"
#include "tpm2_util.h"

#include <tss2/tss2_sys.h>

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <assert.h>

const int num_measurements = 100;

bool test_parms(TSS2_SYS_CONTEXT *sapi_context,
        struct create_primary_params *params)
{
    TPMT_PUBLIC_PARMS parameters = {
        .type = params->inPublic.publicArea.type,
        .parameters = params->inPublic.publicArea.parameters
    };
    TPM2_RC rc = Tss2_Sys_TestParms(sapi_context, NULL, &parameters, NULL);
    return rc == TPM2_RC_SUCCESS;
}

void test_and_measure(TSS2_SYS_CONTEXT *sapi_context, char *param_fields,
        struct create_primary_params *params, FILE *out, FILE *out_all)
{
    if (!test_parms(sapi_context, params))
        return;

    double durations[num_measurements];

    TPM2_HANDLE handles[max_num_handles];
    int num_handles = 0;

    TPM2_RC error_codes[max_num_error_codes];
    int num_error_codes = 0;

    for (int i = 0; i < num_measurements; ++i) {
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
        fprintf(out_all, "%s;%f;%04x;%08x\n", param_fields, durations[i], rc,
                objectHandle);

        update_error_codes(rc, error_codes, &num_error_codes);
        update_handles(objectHandle, handles, &num_handles);

        printf("param: %s | %fs | handle: %08x | rc: %04x\n", param_fields,
                durations[i], objectHandle, rc);
    }

    char handles_string[handles_string_size];
    fill_handles_string(handles_string, handles, num_handles);
    char error_codes_string[error_codes_string_size];
    fill_error_codes_string(error_codes_string, error_codes, num_error_codes);

    fprintf(out, "%s; %f; %s; %s\n", param_fields,
            mean(durations, num_measurements), error_codes_string, handles_string);
}

void measure_CreatePrimary_RSA(TSS2_SYS_CONTEXT *sapi_context,
        struct create_primary_params *params)
{
    puts("Measuring CreatePrimary (RSA)...");

    /* Create RSA template */
    params->inPublic.publicArea.type = TPM2_ALG_RSA;
    TPMU_PUBLIC_PARMS parameters = {
        .rsaDetail = {          // TPMS_RSA_PARMS
            .symmetric = {              // TPMT_SYM_DEF_OBJECT
                .algorithm = TPM2_ALG_AES,  // TPMI_ALG_SYM_OBJECT
                .keyBits = 128,             // TPMU_SYM_KEY_BITS
                .mode = TPM2_ALG_NULL,        // TPMU_SYM_MODE
            },
            .scheme = TPM2_ALG_NULL,        // TPMT_RSA_SCHEME+
            .keyBits = 0,
            .exponent = 0
        }
    };
    params->inPublic.publicArea.parameters = parameters;

    FILE *out = open_csv("TPM2_CreatePrimary_RSA.csv",
            "keyBits;duration_mean;error_codes;handles", "w");
    FILE *out_all = open_csv("TPM2_CreatePrimary_RSA_all.csv",
            "keyBits;duration;return_code;handle", "w");

    for (int keyBits = 0; keyBits < 4096; keyBits += 32) {
        params->inPublic.publicArea.parameters.rsaDetail.keyBits = keyBits;
        char param_fields[6];
        snprintf(param_fields, 6, "%d", keyBits);
        test_and_measure(sapi_context, param_fields, params, out, out_all);
    }

    fclose(out);
    fclose(out_all);
}

void measure_CreatePrimary_KEYEDHASH(TSS2_SYS_CONTEXT *sapi_context,
    struct create_primary_params *params)
{
    puts("Measuring CreatePrimary (KEYEDHASH)...");

    TPMI_ALG_KEYEDHASH_SCHEME schemes[] = {
        TPM2_ALG_HMAC,
        TPM2_ALG_XOR,
        TPM2_ALG_NULL
    };

    /* Create KEYEDHASH template */
    params->inPublic.publicArea.type = TPM2_ALG_KEYEDHASH;

    FILE *out = open_csv("TPM2_CreatePrimary_KEYEDHASH.csv",
            "scheme;details;duration_mean;error_codes;handles", "w");
    FILE *out_all = open_csv("TPM2_CreatePrimary_KEYEDHASH_all.csv",
            "scheme;details;duration;return_code;handle", "w");

    for (int i = 0; i < sizeof(schemes) / sizeof(TPMI_ALG_KEYEDHASH_SCHEME); ++i) {
        TPMI_ALG_KEYEDHASH_SCHEME scheme = schemes[i];
        TPMU_PUBLIC_PARMS parameters;
        parameters.keyedHashDetail.scheme.scheme = scheme;

        switch (scheme) {
        case TPM2_ALG_HMAC:
            for (int hashAlg = TPM2_ALG_FIRST; hashAlg <= TPM2_ALG_LAST; ++hashAlg) {
                parameters.keyedHashDetail.scheme.details.hmac.hashAlg = hashAlg;
                params->inPublic.publicArea.parameters = parameters;
                char param_fields[16];
                snprintf(param_fields, 16, "%04x;%04x", scheme, hashAlg);
                test_and_measure(sapi_context, param_fields, params, out, out_all);
            }
            break;
        case TPM2_ALG_XOR:
            for (int hashAlg = TPM2_ALG_FIRST; hashAlg <= TPM2_ALG_LAST; ++hashAlg) {
                for (int kdf = TPM2_ALG_FIRST; kdf <= TPM2_ALG_LAST; ++kdf) {
                    TPMS_SCHEME_XOR details = {
                        .hashAlg = hashAlg,
                        .kdf = kdf
                    };
                    parameters.keyedHashDetail.scheme.details.exclusiveOr = details;
                    params->inPublic.publicArea.parameters = parameters;
                    char param_fields[16];
                    snprintf(param_fields, 16, "%04x;%04x,%04x", scheme, hashAlg, kdf);
                    test_and_measure(sapi_context, param_fields, params, out, out_all);
                }
            }
            break;
        case TPM2_ALG_NULL:
            {
                char param_fields[16];
                snprintf(param_fields, 16, "%04x;", scheme);
                test_and_measure(sapi_context, param_fields, params, out, out_all);
            }
            break;
        default:
            fprintf(stderr, "CreatePrimary: unknown keyedhash scheme");
        }
    }

    fclose(out);
    fclose(out_all);
}

void measure_CreatePrimary_SYMCIPHER(TSS2_SYS_CONTEXT *sapi_context,
        struct create_primary_params *params)
{
    puts("Measuring CreatePrimary (SYMCIPHER)...");

    /* Create SYMCIPHER template */
    params->inPublic.publicArea.type = TPM2_ALG_SYMCIPHER;
    TPMU_PUBLIC_PARMS parameters = {
        .symDetail = {          // TPMS_SYMCIPHER_PARMS
            .sym = {              // TPMT_SYM_DEF_OBJECT
                .mode = TPM2_ALG_CFB,        // TPMU_SYM_MODE
            },
        }
    };
    params->inPublic.publicArea.parameters = parameters;

    FILE *out = open_csv("TPM2_CreatePrimary_SYMCIPHER.csv",
            "algorithm;keyBits;duration_mean;error_codes;handles", "w");
    FILE *out_all = open_csv("TPM2_CreatePrimary_SYMCIPHER_all.csv",
            "algorithm;keyBits;duration;return_code;handle", "w");

    for (TPMI_ALG_SYM_OBJECT algorithm = TPM2_ALG_FIRST;
            algorithm < TPM2_ALG_LAST; ++algorithm) {
        params->inPublic.publicArea.parameters.symDetail.sym.algorithm
            = algorithm;
        for (int keyBits = 0; keyBits < 512; keyBits += 32) {
            params->inPublic.publicArea.parameters.symDetail.sym.keyBits.sym
                = keyBits;
            char param_fields[12];
            snprintf(param_fields, 12, "%04x;%d", algorithm, keyBits);
            test_and_measure(sapi_context, param_fields, params, out, out_all);
        }
    }

    fclose(out);
    fclose(out_all);
}

void measure_CreatePrimary_ECC(TSS2_SYS_CONTEXT *sapi_context,
        struct create_primary_params *params)
{
    puts("Measuring CreatePrimary (ECC)...");

    /* Create ECC template */
    params->inPublic.publicArea.type = TPM2_ALG_ECC;
    TPMU_PUBLIC_PARMS parameters = {
        .eccDetail = {
            .symmetric = {              // TPMT_SYM_DEF_OBJECT
                .algorithm = TPM2_ALG_AES,  // TPMI_ALG_SYM_OBJECT
                .keyBits = 128,             // TPMU_SYM_KEY_BITS
                .mode = TPM2_ALG_NULL,        // TPMU_SYM_MODE
            },
            .scheme = TPM2_ALG_NULL,        // TPMT_RSA_SCHEME+
            .kdf = TPM2_ALG_NULL
        }
    };
    params->inPublic.publicArea.parameters = parameters;

    FILE *out = open_csv("TPM2_CreatePrimary_ECC.csv",
            "curveID;duration_mean;error_codes;handles", "w");
    FILE *out_all = open_csv("TPM2_CreatePrimary_ECC_all.csv",
            "curveID;duration;return_code;handle", "w");

    for (TPM2_ECC_CURVE curve = 0x00; curve <= 0x0020; ++curve) {
        params->inPublic.publicArea.parameters.eccDetail.curveID = curve;
        char param_fields[7];
        snprintf(param_fields, 7, "%04x", curve);
        test_and_measure(sapi_context, param_fields, params, out, out_all);
    }

    fclose(out);
    fclose(out_all);
}

void measure_CreatePrimary(TSS2_SYS_CONTEXT *sapi_context)
{
    printf("TPM2_CreatePrimary:\n");
    struct create_primary_params params;

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

    TPM2B_PUBLIC inPublic = {
        .size = 0, // doesn't need to be set
        .publicArea = {                         // TPMT_PUBLIC
            .nameAlg = TPM2_ALG_SHA256,             // TPMI_ALG_HASH
            .objectAttributes =                     // TPMA_OBJECT
                TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT
                | TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT
                | TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH,
            .authPolicy = { .size = 0, /* buffer */ }, // TPM2B_DIGEST
        }
    };
    params.inPublic = inPublic;

//    measure_CreatePrimary_RSA(sapi_context, &params);
    //measure_CreatePrimary_ECC(sapi_context, &params);
//    measure_CreatePrimary_SYMCIPHER(sapi_context, &params);
    measure_CreatePrimary_KEYEDHASH(sapi_context, &params);
}

