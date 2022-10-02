#include "keygen.h"
#include "options.h"
#include "logging.h"
#include "object_util.h"
#include "key_params_generator.h"
#include "util.h"
#include "status.h"

#include <tss2/tss2_sys.h>
#include <stdlib.h>
#include <stdio.h>

extern struct tpm_algtest_options options;

void extract_keys(
        TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT primary_handle,
        const TPM2B_PUBLIC *outPublic,
        const TPM2B_PRIVATE *outPrivate,
        struct keygen_keypair *keypair)
{
    keypair->public_key = outPublic->publicArea.unique;
    TPM2_HANDLE object_handle;
    TPM2_RC rc = load(sapi_context, primary_handle, outPrivate, outPublic,
            &object_handle);
    if (rc != TPM2_RC_SUCCESS) {
        log_warning("Keygen: Cannot load object into TPM! (%04x)", rc);
        return;
    }

    TPMU_SENSITIVE_COMPOSITE sensitive;
    rc = extract_sensitive(sapi_context, object_handle, &sensitive);
    Tss2_Sys_FlushContext(sapi_context, object_handle);
    if (rc != TPM2_RC_SUCCESS) {
        log_warning("Keygen: Cannot extract private key! (%04x)", rc);
        return;
    } else {
        keypair->private_key = sensitive;
    }
}

/*
 * Result needs to be allocated at this point
 */
bool test_detail(
        TSS2_SYS_CONTEXT *sapi_context,
        const struct keygen_scenario *scenario,
        TPMI_DH_OBJECT primary_handle,
        struct keygen_result *result,
	struct progress *prog)
{

    TPM2B_PUBLIC inPublic = prepare_template(&scenario->key_params);
    // Workaround for instances where BN_P256 can be used only for ECDAA.
    if (scenario->key_params.type == TPM2_ALG_ECC && scenario->key_params.parameters.eccDetail.curveID == TPM2_ECC_BN_P256) {
        inPublic.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_ECDAA;
        inPublic.publicArea.parameters.eccDetail.scheme.details.ecdaa.hashAlg = TPM2_ALG_SHA256;
    }

    if (!scenario->no_export) {
        inPublic.publicArea.authPolicy = get_dup_policy(sapi_context);
    }

    TPM2_RC rc = test_parms(sapi_context, &inPublic.publicArea);
    if (rc != TPM2_RC_SUCCESS) {
        return false;
    }

    result->size = 0;
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (unsigned i = 0; i < scenario->parameters.repetitions; ++i) {
        clock_gettime(CLOCK_MONOTONIC, &end);
        if (get_duration_s(&start, &end) > scenario->parameters.max_duration_s) {
            break;
        }

        TPM2B_PUBLIC outPublic = { .size = 0 };
        TPM2B_PRIVATE outPrivate = { .size = 0 };

        result->data_points[i].rc = create(sapi_context, &inPublic,
                primary_handle, &outPublic, &outPrivate,
                &result->data_points[i].duration_s);

        ++result->size;
        switch (scenario->key_params.type) {
        case TPM2_ALG_RSA:
            log_info("Keygen %d: RSA | keybits %d | duration %f | rc %04x",
                    i, scenario->key_params.parameters.rsaDetail.keyBits,
                    result->data_points[i].duration_s, result->data_points[i].rc);
            break;
        case TPM2_ALG_ECC:
            log_info("Keygen %d: ECC | curve %04x | duration %f | rc %04x",
                    i, scenario->key_params.parameters.eccDetail.curveID,
                    result->data_points[i].duration_s, result->data_points[i].rc);
            break;
        case TPM2_ALG_KEYEDHASH:
            log_info("Keygen %d: KEYEDHASH | duration %f | rc %04x",
                    i, result->data_points[i].duration_s, result->data_points[i].rc);
            break;
        case TPM2_ALG_SYMCIPHER:
            log_info("Keygen %d: SYMCIPHER | algorithm %04x | keylen %d | duration %f | rc %04x",
                    i, scenario->key_params.parameters.symDetail.sym.algorithm,
                    scenario->key_params.parameters.symDetail.sym.keyBits.sym,
                    result->data_points[i].duration_s, result->data_points[i].rc);
            break;
        }

        if (result->data_points[i].rc != TPM2_RC_SUCCESS) {
            continue;
        }

        if (!scenario->no_export) {
            extract_keys(sapi_context, primary_handle, &outPublic, &outPrivate,
                    &result->keypairs[i]);
        }

	prog->current++;
	printf("%lu%%\n", get_progress_percentage(prog));
    }
    return true;
}

static
void output_results(
        const struct keygen_scenario *scenario,
        const struct keygen_result *result)
{
    char filename[256];
    char filename_keys[256];
    switch (scenario->key_params.type) {
    case TPM2_ALG_RSA:
        snprintf(filename, 256, "Perf_Create:RSA_%d.csv",
                scenario->key_params.parameters.rsaDetail.keyBits);
        snprintf(filename_keys, 256, "Keygen:RSA_%d.csv",
                scenario->key_params.parameters.rsaDetail.keyBits);
        break;
    case TPM2_ALG_ECC:
        snprintf(filename, 256, "Perf_Create:ECC_0x%04x.csv",
                scenario->key_params.parameters.eccDetail.curveID);
        snprintf(filename_keys, 256, "Keygen:ECC_0x%04x.csv",
                scenario->key_params.parameters.eccDetail.curveID);
        break;
    case TPM2_ALG_KEYEDHASH:
        snprintf(filename, 256, "Perf_Create:HMAC.csv");
        break;
    case TPM2_ALG_SYMCIPHER:
        snprintf(filename, 256, "Perf_Create:SYMCIPHER_0x%04x_%d.csv",
                scenario->key_params.parameters.symDetail.sym.algorithm,
                scenario->key_params.parameters.symDetail.sym.keyBits.sym);
        break;
    default:
        log_error("Keygen: (output_results) Key type not supported.");
        return;
    }

    FILE* out = open_csv(filename, "duration,return_code");
    for (int i = 0; i < result->size; ++i) {
        struct keygen_data_point *dp = &result->data_points[i];
        fprintf(out, "%f, %04x\n", dp->duration_s, dp->rc);
    }
    fclose(out);

    if (scenario->no_export) {
        return;
    }

    switch (scenario->key_params.type) {
    case TPM2_ALG_RSA:
        out = open_csv(filename_keys, "id;n;e;p;q;d;t");
        for (int i = 0; i < result->size; ++i) {
            if (result->data_points[i].rc != TPM2_RC_SUCCESS) {
                fprintf(out, "null;null;null;null;null;null;null\n");
                continue;
            }
            fprintf(out, "%d;", i);
            for (int j = 0; j < result->keypairs[i].public_key.rsa.size; ++j) {
                fprintf(out, "%02X", result->keypairs[i].public_key.rsa.buffer[j]);
            }
            fprintf(out, ";010001;");
            for (int j = 0; j < result->keypairs[i].private_key.rsa.size; ++j) {
                fprintf(out, "%02X", result->keypairs[i].private_key.rsa.buffer[j]);
            }
            fprintf(out, "; ; ;%d\n", (int) (result->data_points[i].duration_s * 1000));
        }
        break;
    case TPM2_ALG_ECC:
        out = open_csv(filename_keys, "id;x;y;private;t");
        for (int i = 0; i < result->size; ++i) {
            if (result->data_points[i].rc != TPM2_RC_SUCCESS) {
                fprintf(out, "null;null;null;null;null;null;null\n");
                continue;
            }
            fprintf(out, "%d;", i);
            for (int j = 0; j < result->keypairs[i].public_key.ecc.x.size; ++j) {
                fprintf(out, "%02X", result->keypairs[i].public_key.ecc.x.buffer[j]);
            }
            fprintf(out, ";");
            for (int j = 0; j < result->keypairs[i].public_key.ecc.y.size; ++j) {
                fprintf(out, "%02X", result->keypairs[i].public_key.ecc.y.buffer[j]);
            }
            fprintf(out, ";");
            for (int j = 0; j < result->keypairs[i].private_key.ecc.size; ++j) {
                fprintf(out, "%02X", result->keypairs[i].private_key.ecc.buffer[j]);
            }
            fprintf(out, ";%d\n", (int) (result->data_points[i].duration_s * 1000));
        }
        break;
    case TPM2_ALG_KEYEDHASH:
    case TPM2_ALG_SYMCIPHER:
        break;
    default:
        log_error("Keygen (output_results) Key type not supported.");
    }
}

static
bool alloc_result(
        const struct keygen_scenario *scenario,
        struct keygen_result *result)
{
    result->data_points = calloc(scenario->parameters.repetitions,
            sizeof(struct keygen_data_point));
    if (result->data_points == NULL) {
        log_error("Keygen: (calloc) Cannot allocate memory for result.");
        return false;
    }

    if (!scenario->no_export) {
        result->keypairs = calloc(scenario->parameters.repetitions,
                sizeof(struct keygen_keypair));
        if (result->keypairs == NULL) {
            log_error("Keygen: (calloc) Cannot allocate memory for keypairs.");
            free(result->data_points);
            return false;
        }
    }
    return true;
}

static
void free_result(
        const struct keygen_scenario *scenario,
        struct keygen_result *result)
{
    free(result->data_points);
    if (!scenario->no_export) {
        free(result->keypairs);
    }
}

void run_keygen_on_primary(
        TSS2_SYS_CONTEXT *sapi_context,
        const struct keygen_scenario *scenario,
        TPMI_DH_OBJECT primary_handle,
	struct progress *prog)
{
    struct keygen_result result;

    if (!alloc_result(scenario, &result)) {
        return;
    }

    bool ok = test_detail(sapi_context, scenario, primary_handle, &result, prog);
    if (ok) {
        output_results(scenario, &result);
    }

    free_result(scenario, &result);
}

long unsigned count_supported_keygen_scenarios(
        TSS2_SYS_CONTEXT *sapi_context,
        const struct scenario_parameters *parameters)
{
    struct keygen_scenario scenario = {
        .parameters = *parameters,
        .key_params = { .type = TPM2_ALG_NULL },
        .no_export = options.no_export,
    };

    long unsigned total = 0;

    while (get_next_key_params(&scenario.key_params)) {
	    TPM2B_PUBLIC inPublic = prepare_template(&scenario.key_params);

	    if (!scenario.no_export) {
		    inPublic.publicArea.authPolicy = get_dup_policy(sapi_context);
	    }

	    TPM2_RC rc = test_parms(sapi_context, &inPublic.publicArea);
	    if (rc != TPM2_RC_SUCCESS) {
		    continue;
	    }

	    total += scenario.parameters.repetitions;
    }

    return total;
}

void run_keygen_scenarios(
        TSS2_SYS_CONTEXT *sapi_context,
        const struct scenario_parameters *parameters)
{
    struct keygen_scenario scenario = {
        .parameters = *parameters,
        .key_params = { .type = TPM2_ALG_NULL },
        .no_export = options.no_export,
    };

    struct progress prog;

    prog.total = count_supported_keygen_scenarios(sapi_context, parameters);
    prog.current = 0;

    TPMI_DH_OBJECT primary_handle;
    log_info("Keygen: Creating primary key...");
    TPM2_RC rc = create_primary_ECC_NIST_P256(sapi_context, &primary_handle);
    if (rc != TPM2_RC_SUCCESS) {
        log_error("Keygen: Failed to create primary key!");
        return;
    } else {
        log_info("Keygen: Created primary key with handle %08x", primary_handle);
    }

    while (get_next_key_params(&scenario.key_params)) {
        run_keygen_on_primary(sapi_context, &scenario, primary_handle, &prog);
    }

    Tss2_Sys_FlushContext(sapi_context, primary_handle);
}
