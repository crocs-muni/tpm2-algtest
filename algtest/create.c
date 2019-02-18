#include "options.h"
#include "createprimary.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>

extern struct tpm_algtest_options options;

static
void test_and_measure(TSS2_SYS_CONTEXT *sapi_context, char *param_fields,
        struct create_params *params, TPMI_DH_OBJECT parentHandle,
        FILE *out, FILE *out_all)
{
    if (test_parms(sapi_context, params) != TPM2_RC_SUCCESS)
        return;

    struct summary summary;
    init_summary(&summary);

    unsigned repetitions = options.repetitions ? options.repetitions : 100;
    for (unsigned i = 0; i < repetitions; ++i) {
        /* Response paramters have to be cleared before each run. */
        TPM2B_PRIVATE outPrivate = { .size = 0 };
        TPM2B_PUBLIC outPublic = { .size = 0 };
        TPM2B_CREATION_DATA creationData = { .size = 0 };
        TPM2B_DIGEST creationHash = { .size = 0 };
        TPMT_TK_CREATION creationTicket;
        TSS2L_SYS_AUTH_RESPONSE rspAuthsArray; // sessionsDataOut

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
            fprintf(stderr, "%s: value out of range\n", param_fields);
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

static
void log_testing(TPM2_ALG_ID type)
{
    printf("Testing Create ");
    switch (type) {
    case TPM2_ALG_RSA:
        printf("(RSA)...\n");
        break;
    case TPM2_ALG_ECC:
        printf("(ECC)...\n");
        break;
    case TPM2_ALG_SYMCIPHER:
        printf("(SYMCIPHER)...\n");
        break;
    case TPM2_ALG_KEYEDHASH:
        printf("(KEYEDHASH)...\n");
        break;
    }
}

static
void create_template_for_type(struct create_params *params, TPM2_ALG_ID type)
{
    params->inPublic.publicArea.type = type;
    TPMU_PUBLIC_PARMS parameters;
    switch (type) {
    case TPM2_ALG_RSA:
        parameters.rsaDetail = (TPMS_RSA_PARMS) {
            .symmetric = TPM2_ALG_NULL,
            .scheme = TPM2_ALG_NULL,
            .keyBits = 0,
            .exponent = 0
        };
        break;
    case TPM2_ALG_ECC:
        parameters.eccDetail = (TPMS_ECC_PARMS) {
            .symmetric = TPM2_ALG_NULL,
            .scheme = TPM2_ALG_NULL,
            .kdf = TPM2_ALG_NULL
        };
        break;
    case TPM2_ALG_KEYEDHASH:
        // Depends on scheme
        break;
    case TPM2_ALG_SYMCIPHER:
        parameters.symDetail = (TPMS_SYMCIPHER_PARMS) {
            .sym = { .mode = TPM2_ALG_CFB }
        };
        break;
    }
    params->inPublic.publicArea.parameters = parameters;
}

static
FILE *open_csv_summary(TPM2_ALG_ID type)
{
    const char *filename;
    const char *header;
    switch (type) {
    case TPM2_ALG_RSA:
        filename = "TPM2_Create_RSA.csv";
        header = "keyBits;duration_mean;error_codes";
        break;
    case TPM2_ALG_ECC:
        filename = "TPM2_Create_ECC.csv";
        header = "curveId;duration_mean;error_codes";
        break;
    case TPM2_ALG_KEYEDHASH:
        filename = "TPM2_Create_KEYEDHASH.csv";
        header = "scheme;details;duration_mean;error_codes";
        break;
    case TPM2_ALG_SYMCIPHER:
        filename = "TPM2_Create_SYMCIPHER.csv";
        header = "algorithm;keyBits;duration_mean;error_codes";
        break;
    }
    return open_csv(filename, header, "w");
}

static
FILE *open_csv_all(TPM2_ALG_ID type)
{
    const char *filename;
    const char *header;
    switch (type) {
    case TPM2_ALG_RSA:
        filename = "TPM2_Create_RSA_all.csv";
        header = "keyBits;duration;return_code";
        break;
    case TPM2_ALG_ECC:
        filename = "TPM2_Create_ECC_all.csv";
        header = "curveId;duration;return_code";
        break;
    case TPM2_ALG_KEYEDHASH:
        filename = "TPM2_Create_KEYEDHASH_all.csv";
        header = "scheme;details;duration;return_code";
        break;
    case TPM2_ALG_SYMCIPHER:
        filename = "TPM2_Create_SYMCIPHER_all.csv";
        header = "algorithm;keyBits;duration;return_code";
        break;
    }
    return open_csv(filename, header, "w");
}

static
void test_RSA(TSS2_SYS_CONTEXT *sapi_context, struct create_params *params,
        TPMI_DH_OBJECT parentHandle, FILE* out, FILE* out_all)
{
    const int minKeyBits = options.keylen ? options.keylen : 0;
    const int maxKeyBits = options.keylen ? options.keylen : TPM2_MAX_RSA_KEY_BYTES * 8;
    for (int keyBits = minKeyBits; keyBits <= maxKeyBits; keyBits += 32) {
        params->inPublic.publicArea.parameters.rsaDetail.keyBits = keyBits;
        char param_fields[6];
        snprintf(param_fields, 6, "%d", keyBits);
        test_and_measure(sapi_context, param_fields, params, parentHandle,
                out, out_all);
    }
}

static
void test_ECC(TSS2_SYS_CONTEXT *sapi_context, struct create_params *params,
        TPMI_DH_OBJECT parentHandle, FILE* out, FILE* out_all)
{
    for (TPM2_ECC_CURVE curve = 0x00; curve <= 0x0020; ++curve) {
        params->inPublic.publicArea.parameters.eccDetail.curveID = curve;
        char param_fields[7];
        snprintf(param_fields, 7, "%04x", curve);
        test_and_measure(sapi_context, param_fields, params, parentHandle,
                out, out_all);
    }
}

static
void test_SYMCIPHER(TSS2_SYS_CONTEXT *sapi_context, struct create_params *params,
        TPMI_DH_OBJECT parentHandle, FILE* out, FILE* out_all)
{
    const int minKeyBits = options.keylen ? options.keylen : 0;
    const int maxKeyBits = options.keylen ? options.keylen : TPM2_MAX_SYM_KEY_BYTES * 8;
    for (TPMI_ALG_SYM_OBJECT algorithm = TPM2_ALG_FIRST;
            algorithm < TPM2_ALG_LAST; ++algorithm) {
        params->inPublic.publicArea.parameters.symDetail.sym.algorithm
            = algorithm;
        for (int keyBits = minKeyBits; keyBits <= maxKeyBits; keyBits += 32) {
            params->inPublic.publicArea.parameters.symDetail.sym.keyBits.sym
                = keyBits;
            char param_fields[12];
            snprintf(param_fields, 12, "%04x;%d", algorithm, keyBits);
            test_and_measure(sapi_context, param_fields, params, parentHandle,
                    out, out_all);
        }
    }
}

static
void test_KEYEDHASH(TSS2_SYS_CONTEXT *sapi_context, struct create_params *params,
        TPMI_DH_OBJECT parentHandle, FILE* out, FILE* out_all)
{
    TPMI_ALG_KEYEDHASH_SCHEME schemes[] = {
        TPM2_ALG_HMAC,
        TPM2_ALG_XOR,
        TPM2_ALG_NULL
    };

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
                test_and_measure(sapi_context, param_fields, params, parentHandle,
                        out, out_all);
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
                    test_and_measure(sapi_context, param_fields, params, parentHandle,
                            out, out_all);
                }
            }
            break;
        case TPM2_ALG_NULL:
            {
                char param_fields[16];
                snprintf(param_fields, 16, "%04x;", scheme);
                test_and_measure(sapi_context, param_fields, params, parentHandle,
                        out, out_all);
            }
            break;
        default:
            fprintf(stderr, "Create: unknown keyedhash scheme");
        }
    }
}

void test_Create_detail(TSS2_SYS_CONTEXT *sapi_context,
        struct create_params *params, TPMI_DH_OBJECT parentHandle,
        TPM2_ALG_ID type)
{
    log_testing(type);
    create_template_for_type(params, type);
    FILE *out = open_csv_summary(type);
    FILE *out_all = open_csv_all(type);
    switch (type) {
    case TPM2_ALG_RSA:
        test_RSA(sapi_context, params, parentHandle, out, out_all);
        break;
    case TPM2_ALG_ECC:
        test_ECC(sapi_context, params, parentHandle, out, out_all);
        break;
    case TPM2_ALG_SYMCIPHER:
        test_SYMCIPHER(sapi_context, params, parentHandle, out, out_all);
        break;
    case TPM2_ALG_KEYEDHASH:
        test_KEYEDHASH(sapi_context, params, parentHandle, out, out_all);
        break;
    }

    fclose(out);
    fclose(out_all);
}

void test_Create(TSS2_SYS_CONTEXT *sapi_context)
{
    printf("TPM2_Create:\n");
    TPMI_DH_OBJECT parentHandle;
    TPM2_RC rc = create_RSA_parent(sapi_context, &parentHandle);
    if (rc != TPM2_RC_SUCCESS) {
        fprintf(stderr, "TPM2_Create: Cannot create RSA parent! (%04x)\n", rc);
        return;
    }
    printf("Created RSA parent with handle %08x\n", parentHandle);

    struct create_params params;
    prepare_create_params(&params);

    if (!strcmp(options.type, "all")) {
        test_Create_detail(sapi_context, &params, parentHandle, TPM2_ALG_RSA);
        test_Create_detail(sapi_context, &params, parentHandle, TPM2_ALG_ECC);
        test_Create_detail(sapi_context, &params, parentHandle, TPM2_ALG_SYMCIPHER);
        test_Create_detail(sapi_context, &params, parentHandle, TPM2_ALG_KEYEDHASH);
    } else if (!strcmp(options.type, "rsa")) {
        test_Create_detail(sapi_context, &params, parentHandle, TPM2_ALG_RSA);
    } else if (!strcmp(options.type, "ecc")) {
        test_Create_detail(sapi_context, &params, parentHandle, TPM2_ALG_ECC);
    } else if (!strcmp(options.type, "symcipher")) {
        test_Create_detail(sapi_context, &params, parentHandle, TPM2_ALG_SYMCIPHER);
    } else if (!strcmp(options.type, "keyedhash")) {
        test_Create_detail(sapi_context, &params, parentHandle, TPM2_ALG_KEYEDHASH);
    } else {
        fprintf(stderr, "Unknown algorithm!\n");
    }

    Tss2_Sys_FlushContext(sapi_context, parentHandle);
}
