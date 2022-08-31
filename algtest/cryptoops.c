#include "cryptoops.h"
#include "object_util.h"
#include "logging.h"
#include "util.h"
#include "perf_util.h"
#include "key_params_generator.h"
#include "status.h"

#include <string.h>
#include <stdlib.h>
#include <time.h>

static
void nonce_extract_keys(
        TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT primary_handle,
        const TPM2B_PUBLIC *outPublic,
        const TPM2B_PRIVATE *outPrivate,
        struct nonce_keypair *keypair)
{
    keypair->public_key = outPublic->publicArea.unique;
    TPM2_HANDLE object_handle;
    TPM2_RC rc = load(sapi_context, primary_handle, outPrivate, outPublic,
                      &object_handle);
    if (rc != TPM2_RC_SUCCESS) {
        log_warning("Cryptoops nonce: Cannot load object into TPM! (%04x)", rc);
        return;
    }

    TPMU_SENSITIVE_COMPOSITE sensitive;
    rc = extract_sensitive(sapi_context, object_handle, &sensitive);
    Tss2_Sys_FlushContext(sapi_context, object_handle);
    if (rc != TPM2_RC_SUCCESS) {
        log_warning("Cryptoops nonce: Cannot extract private key! (%04x)", rc);
        return;
    } else {
        keypair->private_key = sensitive;
    }
}

static
bool alloc_result(
        const struct cryptoops_scenario *scenario,
        struct cryptoops_result *result)
{
    result->data_points = calloc(scenario->parameters.repetitions,
            sizeof(struct cryptoops_data_point));
    return result->data_points != NULL;
}

static
void free_result(struct cryptoops_result *result)
{
    free(result->data_points);
}

bool get_csv_filename_nonce(
        const struct cryptoops_scenario *scenario,
        char filename[256])
{
    switch (scenario->nonce.key_params.type) {
    case TPM2_ALG_ECC:
        snprintf(filename, 256, "Nonce:ECC_0x%04x_0x%04x.csv",
                scenario->nonce.key_params.parameters.eccDetail.curveID, scenario->nonce.scheme.scheme);
        break;
    default:
        log_error("Cryptoops nonce: (output_results) Algorithm type not supported.");
        return false;
    }
    return true;
}

static
void output_nonce_results(
        const struct cryptoops_scenario *scenario,
        const struct cryptoops_result *result)
{
    char filename[256];
    bool fn_valid = true;
    switch (scenario->command_code) {
    case TPM2_CC_Sign:
        fn_valid = get_csv_filename_nonce(scenario, filename); break;
    default:
        log_error("Cryptoops nonce: (output_results) Command not supported.");
        return;
    }
    if (!fn_valid) { return; }

    FILE *out = open_csv(filename, "id,algorithm,curve,digest,signature_r,signature_s,private_key,public_key_x,public_key_y,duration,return_code");
    for (int i = 0; i < result->size; ++i) {
        struct cryptoops_data_point *dp = &result->data_points[i];
        fprintf(out, "%d,%04x,%04x,", i, dp->nonce.algorithm_id, dp->nonce.curve_id);
        for(uint16_t j = 0; j < dp->nonce.digest_size; ++j) {
            fprintf(out, "%02x", dp->nonce.digest[j]);
        }
        fprintf(out, ",");
        for(uint16_t j = 0; j < dp->nonce.signature_r_size; ++j) {
            fprintf(out, "%02x", dp->nonce.signature_r[j]);
        }
        fprintf(out, ",");
        for(uint16_t j = 0; j < dp->nonce.signature_s_size; ++j) {
            fprintf(out, "%02x", dp->nonce.signature_s[j]);
        }
        fprintf(out, ",");
        for(uint16_t j = 0; j < dp->nonce.private_key_size; ++j) {
            fprintf(out, "%02x", dp->nonce.private_key[j]);
        }
        fprintf(out, ",");
        for(uint16_t j = 0; j < dp->nonce.public_key_x_size; ++j) {
            fprintf(out, "%02x", dp->nonce.public_key_x[j]);
        }
        fprintf(out, ",");
        for(uint16_t j = 0; j < dp->nonce.public_key_y_size; ++j) {
            fprintf(out, "%02x", dp->nonce.public_key_y[j]);
        }
        fprintf(out, ",%f,%04x\n", dp->duration_s, dp->rc);
    }
    fclose(out);
}

bool run_nonce_sign(
        TSS2_SYS_CONTEXT *sapi_context,
        const struct cryptoops_scenario *scenario,
        TPMI_DH_OBJECT primary_handle,
        struct cryptoops_result *result,
        struct progress *prog)
{
    TPM2B_PUBLIC inPublic = prepare_template(&scenario->nonce.key_params);
    if(!scenario->nonce.no_export) {
        inPublic.publicArea.authPolicy = get_dup_policy(sapi_context);
    }

    TPM2_RC rc = test_parms(sapi_context, &inPublic.publicArea);
    if (rc != TPM2_RC_SUCCESS) {
        return false;
    }

    TPM2B_PUBLIC outPublic = { .size = 0 };
    TPM2B_PRIVATE outPrivate = { .size = 0 };

    TPM2_HANDLE object_handle;
    log_info("Cryptoops nonce: Generating signing key...");
    rc = create(sapi_context, &inPublic, primary_handle, &outPublic, &outPrivate, NULL);
    if (rc != TPM2_RC_SUCCESS) {
        log_error("Cryptoops nonce: Error when creating signing key %04x", rc);
        return false;
    }

    rc = load(sapi_context, primary_handle, &outPrivate, &outPublic, &object_handle);
    if (rc != TPM2_RC_SUCCESS) {
        log_error("Cryptoops nonce: Error when loading signing key %04x", rc);
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

        TPMT_SIGNATURE signature;
        result->data_points[i].rc = sign(sapi_context, object_handle,
                &scenario->nonce.scheme, &scenario->nonce.digest, &signature,
                &result->data_points[i].duration_s);

        if(result->data_points[i].rc == TPM2_RC_SUCCESS) {
            TPM2B_ECC_PARAMETER *r = NULL, *s = NULL;
            switch (signature.sigAlg) {
                case TPM2_ALG_ECDSA:
                    r = &signature.signature.ecdsa.signatureR;
                    s = &signature.signature.ecdsa.signatureS;
                    break;
                case TPM2_ALG_SM2:
                    r = &signature.signature.sm2.signatureR;
                    s = &signature.signature.sm2.signatureS;
                    break;
                case TPM2_ALG_ECSCHNORR:
                    r = &signature.signature.ecschnorr.signatureR;
                    s = &signature.signature.ecschnorr.signatureS;
                    break;
                default:
                    log_warning("Cryptoops nonce: Unknown signature algorithm %04x", signature.sigAlg);
            }
            result->data_points[i].nonce.algorithm_id = signature.sigAlg;
            result->data_points[i].nonce.curve_id = scenario->nonce.key_params.parameters.eccDetail.curveID;
            result->data_points[i].nonce.digest_size = scenario->nonce.digest.size;
            memcpy(&result->data_points[i].nonce.digest, scenario->nonce.digest.buffer, scenario->nonce.digest.size);

            if(r) {
                result->data_points[i].nonce.signature_r_size = r->size;
                memcpy(&result->data_points[i].nonce.signature_r, r->buffer, r->size);
            }
            if(s) {
                result->data_points[i].nonce.signature_s_size = s->size;
                memcpy(&result->data_points[i].nonce.signature_s, s->buffer, s->size);
            }

            if (!scenario->nonce.no_export) {
                struct nonce_keypair keypair;
                nonce_extract_keys(sapi_context, primary_handle, &outPublic, &outPrivate,
                                   &keypair);

                result->data_points[i].nonce.private_key_size = keypair.private_key.ecc.size;
                memcpy(&result->data_points[i].nonce.private_key, keypair.private_key.ecc.buffer, keypair.private_key.ecc.size);

                result->data_points[i].nonce.public_key_x_size = keypair.public_key.ecc.x.size;
                memcpy(&result->data_points[i].nonce.public_key_x, keypair.public_key.ecc.x.buffer, keypair.public_key.ecc.x.size);

                result->data_points[i].nonce.public_key_y_size = keypair.public_key.ecc.y.size;
                memcpy(&result->data_points[i].nonce.public_key_y, keypair.public_key.ecc.y.buffer, keypair.public_key.ecc.y.size);
            }
        }
        ++result->size;
        log_info("Cryptoops nonce %d: ECC | scheme %04x | curve %04x | duration %f | rc %04x",
                i, scenario->nonce.scheme.scheme,
                scenario->nonce.key_params.parameters.eccDetail.curveID,
                result->data_points[i].duration_s, result->data_points[i].rc);

	    printf("%lu%%\n", inc_and_get_progress_percentage(prog));
    }

    Tss2_Sys_FlushContext(sapi_context, object_handle);
    return true;
}

void run_nonce_on_primary(
        TSS2_SYS_CONTEXT *sapi_context,
        const struct cryptoops_scenario *scenario,
        TPMI_DH_OBJECT primary_handle,
        struct progress *prog)
{
    struct cryptoops_result result;
    if (!alloc_result(scenario, &result)) {
        log_error("Cryptoops nonce: cannot allocate memory for result.");
        return;
    }

    if(run_nonce_sign(sapi_context, scenario, primary_handle, &result, prog)) {
        output_nonce_results(scenario, &result);
    }
    free_result(&result);
}

unsigned long count_supported_nonce_scenarios(
        TSS2_SYS_CONTEXT *sapi_context,
        const struct scenario_parameters *parameters)
{
    struct cryptoops_scenario scenario = {
        .parameters = *parameters,
    };
    unsigned long total = 0;

    if (command_in_options("sign")) {
        scenario.command_code = TPM2_CC_Sign;
        scenario.nonce.key_params = (TPMT_PUBLIC_PARMS) { .type = TPM2_ALG_NULL };
        scenario.nonce.scheme = (TPMT_SIG_SCHEME) { .scheme = TPM2_ALG_NULL };
        scenario.nonce.digest = (struct TPM2B_DIGEST) { .size = 32 }; // Using SHA256
        memset(&scenario.nonce.digest.buffer, 0x00, scenario.nonce.digest.size);
        while (get_next_asym_key_params(&scenario.nonce.key_params)) {
            while (get_next_sign_scheme(&scenario.nonce.scheme, scenario.nonce.key_params.type)) {
                TPM2B_PUBLIC inPublic = prepare_template(&scenario.nonce.key_params);

                TPM2_RC rc = test_parms(sapi_context, &inPublic.publicArea);
                if (rc == TPM2_RC_SUCCESS) {
                    total += scenario.parameters.repetitions;
                }
            }
            scenario.nonce.scheme.scheme = TPM2_ALG_NULL;
        }
    }

    return total;
}

void run_cryptoops_scenarios(
        TSS2_SYS_CONTEXT *sapi_context,
        const struct scenario_parameters *parameters)
{
    struct cryptoops_scenario scenario = {
        .parameters = *parameters,
    };
    struct progress prog;

    prog.total = count_supported_nonce_scenarios(sapi_context, parameters);
    prog.current = 0;

    TPMI_DH_OBJECT primary_handle;
    log_info("Cryptoops nonce: Creating primary key...");
    TPM2_RC rc = create_primary_ECC_NIST_P256(sapi_context, &primary_handle);
    if (rc != TPM2_RC_SUCCESS) {
        log_error("Cryptoops nonce: Failed to create primary key!");
        return;
    } else {
        log_info("Cryptoops nonce: Created primary key with handle %08x", primary_handle);
    }

    if (command_in_options("sign")) {
        scenario.command_code = TPM2_CC_Sign;
        scenario.nonce.key_params = (TPMT_PUBLIC_PARMS) { .type = TPM2_ALG_NULL };
        scenario.nonce.scheme = (TPMT_SIG_SCHEME) { .scheme = TPM2_ALG_NULL };
        scenario.nonce.digest = (struct TPM2B_DIGEST) { .size = 32 }; // Using SHA256
        memset(&scenario.nonce.digest.buffer, 0x00, scenario.nonce.digest.size);

        scenario.nonce.key_params.type = TPM2_ALG_ECC;
        if (type_in_options("ecc")) {
            scenario.nonce.key_params.parameters.eccDetail = (TPMS_ECC_PARMS) {
                    .symmetric = TPM2_ALG_NULL,
                    .scheme = TPM2_ALG_NULL,
                    .curveID = 0x0000,
                    .kdf = TPM2_ALG_NULL
            };
        }

        while (get_next_ecc_curve(&scenario.nonce.key_params.parameters.eccDetail.curveID)) {
            while (get_next_sign_scheme(&scenario.nonce.scheme, scenario.nonce.key_params.type)) {
                run_nonce_on_primary(sapi_context, &scenario, primary_handle, &prog);
            }
            scenario.nonce.scheme.scheme = TPM2_ALG_NULL;
        }
    }

    Tss2_Sys_FlushContext(sapi_context, primary_handle);
}
