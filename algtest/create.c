#include "util.h"

static const int NUM_MEASUREMENTS = 10;

TPMI_DH_OBJECT create_parent(TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT *parentHandle)
{
    struct create_params params;
    prepare_create_primary_params(&params);

#if 0
    params.inPublic.publicArea.type = TPM2_ALG_SYMCIPHER;
    TPMU_PUBLIC_PARMS parameters = {
        .symDetail = {          // TPMS_SYMCIPHER_PARMS
            .sym = {              // TPMT_SYM_DEF_OBJECT
                .algorithm = TPM2_ALG_AES,
                .mode = TPM2_ALG_CFB,        // TPMU_SYM_MODE
                .keyBits = { .sym = 128 } // should be always available
            },
        }
    };
    params.inPublic.publicArea.parameters = parameters;
#endif

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

    if (!test_parms(sapi_context, &params)) {
        fprintf(stderr, "Error: AES128 not available, cannot create parent object! (TPM2_Create)\n");
    }

    TPM2_HANDLE objectHandle;
    TPM2B_PUBLIC outPublic = { .size = 0 };
    TPM2B_CREATION_DATA creationData = { .size = 0 };
    TPM2B_DIGEST creationHash = { .size = 0 };
    TPMT_TK_CREATION creationTicket;
    TPM2B_NAME name = { .size = 0 };
    TSS2L_SYS_AUTH_RESPONSE rspAuthsArray; // sessionsDataOut

    TPMI_RH_HIERARCHY primaryHandle = TPM2_RH_NULL;

    TPM2_RC rc = Tss2_Sys_CreatePrimary(sapi_context,
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
        struct create_params *params, TPMI_DH_OBJECT parentHandle,
        FILE *out, FILE *out_all)
{
    if (!test_parms(sapi_context, params))
        return;

    struct summary summary;
    init_summary(&summary);

    for (int i = 0; i < NUM_MEASUREMENTS; ++i) {
        /* Response paramters have to be cleared before each run. */
        TPM2B_PRIVATE outPrivate = { .size = 0 };
        TPM2B_PUBLIC outPublic = { .size = 0 };
        TPM2B_CREATION_DATA creationData = { .size = 0 };
        TPM2B_DIGEST creationHash = { .size = 0 };
        TPMT_TK_CREATION creationTicket;
        TPM2B_NAME name = { .size = 0 };
        TSS2L_SYS_AUTH_RESPONSE rspAuthsArray; // sessionsDataOut

        TPMI_RH_HIERARCHY primaryHandle = TPM2_RH_NULL; // use NULL hierarchy for testing

        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        TPM2_RC rc = Tss2_Sys_Create(sapi_context,
                parentHandle, &params->cmdAuthsArray,
                &params->inSensitive, &params->inPublic, &params->outsideInfo,
                &params->creationPCR, &outPrivate, &outPublic,
                &creationData, &creationHash,
                &creationTicket, &rspAuthsArray);
        clock_gettime(CLOCK_MONOTONIC, &end);

        // TODO: cleanup this
        if (rc == 0x02c4) {
            return;
        }
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

void measure_Create_RSA(TSS2_SYS_CONTEXT *sapi_context,
        struct create_params *params, TPMI_DH_OBJECT parentHandle)
{
    puts("Measuring Create (RSA)...");

    /* Create RSA template */
    params->inPublic.publicArea.type = TPM2_ALG_RSA;
    TPMU_PUBLIC_PARMS parameters = {
        .rsaDetail = {          // TPMS_RSA_PARMS
            .symmetric = TPM2_ALG_NULL,
            .scheme = TPM2_ALG_NULL,        // TPMT_RSA_SCHEME+
            .keyBits = 0,
            .exponent = 0
        }
    };
    params->inPublic.publicArea.parameters = parameters;

    FILE *out = open_csv("TPM2_Create_RSA.csv",
            "keyBits;duration_mean;error_codes", "w");
    FILE *out_all = open_csv("TPM2_Create_RSA_all.csv",
            "keyBits;duration;return_code", "w");

    for (int keyBits = 0; keyBits <= TPM2_MAX_RSA_KEY_BYTES * 8; keyBits += 32) {
        params->inPublic.publicArea.parameters.rsaDetail.keyBits = keyBits;
        char param_fields[6];
        snprintf(param_fields, 6, "%d", keyBits);
        test_and_measure(sapi_context, param_fields, params, parentHandle, out, out_all);
    }

    fclose(out);
    fclose(out_all);
}

void measure_Create_ECC(TSS2_SYS_CONTEXT *sapi_context,
        struct create_params *params, TPMI_DH_OBJECT parentHandle)
{
    puts("Measuring Create (ECC)...");

    /* Create ECC template */
    params->inPublic.publicArea.type = TPM2_ALG_ECC;
    TPMU_PUBLIC_PARMS parameters = {
        .eccDetail = {          // TPMS_ECC_PARMS
            .symmetric = TPM2_ALG_NULL,
            .scheme = TPM2_ALG_NULL,        // TPMT_ECC_SCHEME+
            .kdf = TPM2_ALG_NULL
        }
    };
    params->inPublic.publicArea.parameters = parameters;

    FILE *out = open_csv("TPM2_Create_ECC.csv",
            "curveID;duration_mean;error_codes", "w");
    FILE *out_all = open_csv("TPM2_Create_ECC_all.csv",
            "curveID;duration;return_code", "w");

    for (TPM2_ECC_CURVE curve = 0x00; curve <= 0x0020; ++curve) {
        params->inPublic.publicArea.parameters.eccDetail.curveID = curve;
        char param_fields[7];
        snprintf(param_fields, 7, "%04x", curve);
        test_and_measure(sapi_context, param_fields, params, parentHandle,
                out, out_all);
    }

    fclose(out);
    fclose(out_all);
}

void measure_Create_SYMCIPHER(TSS2_SYS_CONTEXT *sapi_context,
        struct create_params *params, TPMI_DH_OBJECT parentHandle)
{
    puts("Measuring Create (SYMCIPHER)...");

    /* Create ECC template */
    params->inPublic.publicArea.type = TPM2_ALG_SYMCIPHER;
    TPMU_PUBLIC_PARMS parameters = {
        .symDetail = {          // TPMS_SYMCIPHER_PARMS
            .sym = {
                .mode = TPM2_ALG_CFB,        // TPMU_SYM_MODE
            }
        }
    };
    params->inPublic.publicArea.parameters = parameters;

    FILE *out = open_csv("TPM2_Create_SYMCIPHER.csv",
            "algorithm;keyBits;duration_mean;error_codes", "w");
    FILE *out_all = open_csv("TPM2_Create_SYMCIPHER_all.csv",
            "algorithm;keyBits;duration;return_code", "w");

    for (TPMI_ALG_SYM_OBJECT algorithm = TPM2_ALG_FIRST;
            algorithm < TPM2_ALG_LAST; ++algorithm) {
        params->inPublic.publicArea.parameters.symDetail.sym.algorithm
            = algorithm;
        for (int keyBits = 0; keyBits <= TPM2_MAX_SYM_KEY_BYTES * 8; keyBits += 32) {
            params->inPublic.publicArea.parameters.symDetail.sym.keyBits.sym
                = keyBits;
            char param_fields[12];
            snprintf(param_fields, 12, "%04x;%d", algorithm, keyBits);
            test_and_measure(sapi_context, param_fields, params, parentHandle,
                    out, out_all);
        }
    }
    fclose(out);
    fclose(out_all);
}

void measure_Create_KEYEDHASH(TSS2_SYS_CONTEXT *sapi_context,
        struct create_params *params, TPMI_DH_OBJECT parentHandle)
{
    puts("Measuring CreatePrimary (KEYEDHASH)...");

    /* KEYEDHASH cannot decrypt */
    params->inPublic.publicArea.objectAttributes &= ~TPMA_OBJECT_DECRYPT;

    TPMI_ALG_KEYEDHASH_SCHEME schemes[] = {
        TPM2_ALG_HMAC,
        TPM2_ALG_XOR,
        TPM2_ALG_NULL
    };

    /* Create KEYEDHASH template */
    params->inPublic.publicArea.type = TPM2_ALG_KEYEDHASH;

    FILE *out = open_csv("TPM2_Create_KEYEDHASH.csv",
            "scheme;details;duration_mean;error_codes", "w");
    FILE *out_all = open_csv("TPM2_Create_KEYEDHASH_all.csv",
            "scheme;details;duration;return_code", "w");

    for (int i = 0; i < sizeof(schemes) / sizeof(TPMI_ALG_KEYEDHASH_SCHEME); ++i) {
        TPMI_ALG_KEYEDHASH_SCHEME scheme = schemes[i];
        TPMU_PUBLIC_PARMS parameters;
        parameters.keyedHashDetail.scheme.scheme = scheme;

        switch (scheme) {
        case TPM2_ALG_HMAC:
            /* HMAC only signs, doesn't decrypt */
            params->inPublic.publicArea.objectAttributes &= ~TPMA_OBJECT_DECRYPT;
            params->inPublic.publicArea.objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
            for (int hashAlg = TPM2_ALG_FIRST; hashAlg <= TPM2_ALG_LAST; ++hashAlg) {
                parameters.keyedHashDetail.scheme.details.hmac.hashAlg = hashAlg;
                params->inPublic.publicArea.parameters = parameters;
                char param_fields[16];
                snprintf(param_fields, 16, "%04x;%04x", scheme, hashAlg);
                test_and_measure(sapi_context, param_fields, params,
                        parentHandle, out, out_all);
            }
            params->inPublic.publicArea.objectAttributes |= TPMA_OBJECT_DECRYPT;
            params->inPublic.publicArea.objectAttributes &= ~TPMA_OBJECT_SIGN_ENCRYPT;
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
                    test_and_measure(sapi_context, param_fields, params,
                            parentHandle, out, out_all);
                }
            }
            break;
        case TPM2_ALG_NULL:
            {
                char param_fields[16];
                snprintf(param_fields, 16, "%04x;", scheme);
                test_and_measure(sapi_context, param_fields, params,
                        parentHandle, out, out_all);
            }
            break;
        default:
            fprintf(stderr, "CreatePrimary: unknown keyedhash scheme");
        }
    }

    fclose(out);
    fclose(out_all);
}

void measure_Create(TSS2_SYS_CONTEXT *sapi_context)
{
    printf("TPM2_Create:\n");
    TPMI_DH_OBJECT parentHandle;
    TPM2_RC rc = create_parent(sapi_context, &parentHandle);
    if (rc != TPM2_RC_SUCCESS) {
        fprintf(stderr, "Error: Couldn't create parent object! (TPM2_Create): %04x\n", rc);
        return;
    }
    printf("Created parent with handle %08x\n", parentHandle);

    struct create_params params;
    prepare_create_params(&params);

    measure_Create_RSA(sapi_context, &params, parentHandle);
    measure_Create_ECC(sapi_context, &params, parentHandle);
    measure_Create_SYMCIPHER(sapi_context, &params, parentHandle);
    measure_Create_KEYEDHASH(sapi_context, &params, parentHandle);

    Tss2_Sys_FlushContext(sapi_context, parentHandle);
}
