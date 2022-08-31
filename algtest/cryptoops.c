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
void export_keypair(
        TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT primary_handle,
        const TPM2B_PUBLIC *outPublic,
        const TPM2B_PRIVATE *outPrivate,
        struct exported_keypair *keypair)
{
    keypair->public_key = outPublic->publicArea.unique;
    TPM2_HANDLE object_handle;
    TPM2_RC rc = load(sapi_context, primary_handle, outPrivate, outPublic,
                      &object_handle);
    if (rc != TPM2_RC_SUCCESS) {
        log_warning("Cryptoops ecc: Cannot load object into TPM! (%04x)", rc);
        return;
    }

    TPMU_SENSITIVE_COMPOSITE sensitive;
    rc = extract_sensitive(sapi_context, object_handle, &sensitive);
    Tss2_Sys_FlushContext(sapi_context, object_handle);
    if (rc != TPM2_RC_SUCCESS) {
        log_warning("Cryptoops ecc: Cannot extract private key! (%04x)", rc);
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

static
void output_ecc_results(
        const struct cryptoops_scenario *scenario,
        const struct cryptoops_result *result)
{
    char filename[256];
    snprintf(filename, 256, "Cryptoops_Sign:ECC_0x%04x_0x%04x.csv",
             scenario->sign.key_params.parameters.eccDetail.curveID, scenario->sign.scheme.scheme);

    FILE *out = open_csv(filename, "id,algorithm,curve,digest,signature_r,signature_s,private_key,public_key_x,public_key_y,duration,return_code");
    for (int i = 0; i < result->size; ++i) {
        struct cryptoops_data_point *dp = &result->data_points[i];
        fprintf(out, "%d,%04x,%04x,", i, dp->ecc.algorithm_id, dp->ecc.curve_id);
        for(uint16_t j = 0; j < dp->ecc.digest_size; ++j) {
            fprintf(out, "%02x", dp->ecc.digest[j]);
        }
        fprintf(out, ",");
        for(uint16_t j = 0; j < dp->ecc.signature_r_size; ++j) {
            fprintf(out, "%02x", dp->ecc.signature_r[j]);
        }
        fprintf(out, ",");
        for(uint16_t j = 0; j < dp->ecc.signature_s_size; ++j) {
            fprintf(out, "%02x", dp->ecc.signature_s[j]);
        }
        fprintf(out, ",");
        for(uint16_t j = 0; j < dp->ecc.private_key_size; ++j) {
            fprintf(out, "%02x", dp->ecc.private_key[j]);
        }
        fprintf(out, ",");
        for(uint16_t j = 0; j < dp->ecc.public_key_x_size; ++j) {
            fprintf(out, "%02x", dp->ecc.public_key_x[j]);
        }
        fprintf(out, ",");
        for(uint16_t j = 0; j < dp->ecc.public_key_y_size; ++j) {
            fprintf(out, "%02x", dp->ecc.public_key_y[j]);
        }
        fprintf(out, ",%f,%04x\n", dp->duration_s, dp->rc);
    }
    fclose(out);
}

static
void output_rsa_results(
        const struct cryptoops_scenario *scenario,
        const struct cryptoops_result *result)
{
    char filename[256];
    snprintf(filename, 256, "Cryptoops_Sign:RSA_%d_0x%04x.csv",
             scenario->sign.key_params.parameters.rsaDetail.keyBits, scenario->sign.scheme.scheme);

    FILE *out = open_csv(filename, "id,algorithm,hash,digest,signature,e,p,n,duration,return_code");
    for (int i = 0; i < result->size; ++i) {
        struct cryptoops_data_point *dp = &result->data_points[i];
        fprintf(out, "%d,%04x,%04x,", i, dp->rsa.algorithm_id, dp->rsa.hash_id);
        for(uint16_t j = 0; j < dp->rsa.digest_size; ++j) {
            fprintf(out, "%02x", dp->rsa.digest[j]);
        }
        fprintf(out, ",");
        for(uint16_t j = 0; j < dp->rsa.signature_size; ++j) {
            fprintf(out, "%02x", dp->rsa.signature[j]);
        }
        fprintf(out, ",010001,");
        for(uint16_t j = 0; j < dp->rsa.private_key_size; ++j) {
            fprintf(out, "%02x", dp->rsa.private_key[j]);
        }
        fprintf(out, ",");
        for(uint16_t j = 0; j < dp->rsa.public_key_size; ++j) {
            fprintf(out, "%02x", dp->rsa.public_key[j]);
        }
        fprintf(out, ",%f,%04x\n", dp->duration_s, dp->rc);
    }
    fclose(out);
}

bool run_ecc_sign(
        TSS2_SYS_CONTEXT *sapi_context,
        const struct cryptoops_scenario *scenario,
        TPMI_DH_OBJECT primary_handle,
        struct cryptoops_result *result,
        struct progress *prog)
{
    TPM2B_PUBLIC inPublic = prepare_template(&scenario->sign.key_params);
    if(!scenario->sign.no_export) {
        inPublic.publicArea.authPolicy = get_dup_policy(sapi_context);
    }

    TPM2_RC rc = test_parms(sapi_context, &inPublic.publicArea);
    if (rc != TPM2_RC_SUCCESS) {
        return false;
    }

    TPM2B_PUBLIC outPublic = { .size = 0 };
    TPM2B_PRIVATE outPrivate = { .size = 0 };

    TPM2_HANDLE object_handle;
    log_info("Cryptoops ecc: Generating signing key...");
    rc = create(sapi_context, &inPublic, primary_handle, &outPublic, &outPrivate, NULL);
    if (rc != TPM2_RC_SUCCESS) {
        log_error("Cryptoops ecc: Error when creating signing key %04x", rc);
        return false;
    }

    rc = load(sapi_context, primary_handle, &outPrivate, &outPublic, &object_handle);
    if (rc != TPM2_RC_SUCCESS) {
        log_error("Cryptoops ecc: Error when loading signing key %04x", rc);
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
                &scenario->sign.scheme, &scenario->sign.digest, &signature,
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
                    log_warning("Cryptoops ecc: Unknown signature algorithm %04x", signature.sigAlg);
            }
            result->data_points[i].ecc.algorithm_id = signature.sigAlg;
            result->data_points[i].ecc.curve_id = scenario->sign.key_params.parameters.eccDetail.curveID;
            result->data_points[i].ecc.digest_size = scenario->sign.digest.size;
            memcpy(&result->data_points[i].ecc.digest, scenario->sign.digest.buffer, scenario->sign.digest.size);

            if(r) {
                result->data_points[i].ecc.signature_r_size = r->size;
                memcpy(&result->data_points[i].ecc.signature_r, r->buffer, r->size);
            }
            if(s) {
                result->data_points[i].ecc.signature_s_size = s->size;
                memcpy(&result->data_points[i].ecc.signature_s, s->buffer, s->size);
            }

            if (!scenario->sign.no_export) {
                struct exported_keypair keypair;
                export_keypair(sapi_context, primary_handle, &outPublic, &outPrivate, &keypair);

                result->data_points[i].ecc.private_key_size = keypair.private_key.ecc.size;
                memcpy(&result->data_points[i].ecc.private_key, keypair.private_key.ecc.buffer, keypair.private_key.ecc.size);

                result->data_points[i].ecc.public_key_x_size = keypair.public_key.ecc.x.size;
                memcpy(&result->data_points[i].ecc.public_key_x, keypair.public_key.ecc.x.buffer, keypair.public_key.ecc.x.size);

                result->data_points[i].ecc.public_key_y_size = keypair.public_key.ecc.y.size;
                memcpy(&result->data_points[i].ecc.public_key_y, keypair.public_key.ecc.y.buffer, keypair.public_key.ecc.y.size);
            }
        }
        ++result->size;
        log_info("Cryptoops ecc %d: | scheme %04x | curve %04x | duration %f | rc %04x",
                i, scenario->sign.scheme.scheme,
                scenario->sign.key_params.parameters.eccDetail.curveID,
                result->data_points[i].duration_s, result->data_points[i].rc);

	    printf("%lu%%\n", inc_and_get_progress_percentage(prog));
    }

    Tss2_Sys_FlushContext(sapi_context, object_handle);
    return true;
}

void run_ecc_sign_on_primary(
        TSS2_SYS_CONTEXT *sapi_context,
        const struct cryptoops_scenario *scenario,
        TPMI_DH_OBJECT primary_handle,
        struct progress *prog)
{
    struct cryptoops_result result;
    if (!alloc_result(scenario, &result)) {
        log_error("Cryptoops ecc: cannot allocate memory for result.");
        return;
    }

    if(run_ecc_sign(sapi_context, scenario, primary_handle, &result, prog)) {
        output_ecc_results(scenario, &result);
    }
    free_result(&result);
}

bool run_rsa_sign(
        TSS2_SYS_CONTEXT *sapi_context,
        const struct cryptoops_scenario *scenario,
        TPMI_DH_OBJECT primary_handle,
        struct cryptoops_result *result,
        struct progress *prog)
{
    TPM2B_PUBLIC inPublic = prepare_template(&scenario->sign.key_params);
    if(!scenario->sign.no_export) {
        inPublic.publicArea.authPolicy = get_dup_policy(sapi_context);
    }

    TPM2_RC rc = test_parms(sapi_context, &inPublic.publicArea);
    if (rc != TPM2_RC_SUCCESS) {
        return false;
    }

    TPM2B_PUBLIC outPublic = { .size = 0 };
    TPM2B_PRIVATE outPrivate = { .size = 0 };

    TPM2_HANDLE object_handle;
    log_info("Cryptoops rsa: Generating signing key...");
    rc = create(sapi_context, &inPublic, primary_handle, &outPublic, &outPrivate, NULL);
    if (rc != TPM2_RC_SUCCESS) {
        log_error("Cryptoops rsa: Error when creating signing key %04x", rc);
        return false;
    }

    rc = load(sapi_context, primary_handle, &outPrivate, &outPublic, &object_handle);
    if (rc != TPM2_RC_SUCCESS) {
        log_error("Cryptoops rsa: Error when loading signing key %04x", rc);
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
                                         &scenario->sign.scheme, &scenario->sign.digest, &signature,
                                         &result->data_points[i].duration_s);

        if(result->data_points[i].rc == TPM2_RC_SUCCESS) {
            TPMI_ALG_HASH *hash = NULL;
            TPM2B_PUBLIC_KEY_RSA *sig = NULL;
            switch (signature.sigAlg) {
                case TPM2_ALG_RSAPSS:
                    hash = &signature.signature.rsapss.hash;
                    sig = &signature.signature.rsapss.sig;
                    break;
                case TPM2_ALG_RSASSA:
                    hash = &signature.signature.rsassa.hash;
                    sig = &signature.signature.rsassa.sig;
                    break;
                default:
                    log_warning("Cryptoops rsa: Unknown signature algorithm %04x", signature.sigAlg);
            }
            result->data_points[i].rsa.algorithm_id = signature.sigAlg;
            result->data_points[i].rsa.digest_size = scenario->sign.digest.size;
            memcpy(&result->data_points[i].rsa.digest, scenario->sign.digest.buffer, scenario->sign.digest.size);

            if(hash) {
                result->data_points[i].rsa.hash_id = *hash;
            }
            if(sig) {
                result->data_points[i].rsa.signature_size = sig->size;
                memcpy(&result->data_points[i].rsa.signature, sig->buffer, sig->size);
            }

            if (!scenario->sign.no_export) {
                struct exported_keypair keypair;
                export_keypair(sapi_context, primary_handle, &outPublic, &outPrivate, &keypair);

                result->data_points[i].rsa.private_key_size = keypair.private_key.rsa.size;
                memcpy(&result->data_points[i].rsa.private_key, keypair.private_key.rsa.buffer, keypair.private_key.rsa.size);

                result->data_points[i].rsa.public_key_size = keypair.public_key.rsa.size;
                memcpy(&result->data_points[i].rsa.public_key, keypair.public_key.rsa.buffer, keypair.public_key.rsa.size);
            }
        }
        ++result->size;
        log_info("Cryptoops rsa %d: scheme %04x | duration %f | rc %04x",
                 i, scenario->sign.scheme.scheme,
                 result->data_points[i].duration_s, result->data_points[i].rc);

        printf("%lu%%\n", inc_and_get_progress_percentage(prog));
    }

    Tss2_Sys_FlushContext(sapi_context, object_handle);
    return true;
}

void run_rsa_on_primary(
        TSS2_SYS_CONTEXT *sapi_context,
        const struct cryptoops_scenario *scenario,
        TPMI_DH_OBJECT primary_handle,
        struct progress *prog)
{
    struct cryptoops_result result;
    if (!alloc_result(scenario, &result)) {
        log_error("Cryptoops rsa: cannot allocate memory for result.");
        return;
    }

    if(run_rsa_sign(sapi_context, scenario, primary_handle, &result, prog)) {
        output_rsa_results(scenario, &result);
    }
    free_result(&result);
}

unsigned long count_supported_cryptoops_scenarios(
        TSS2_SYS_CONTEXT *sapi_context,
        const struct scenario_parameters *parameters)
{
    struct cryptoops_scenario scenario = {
        .parameters = *parameters,
    };
    unsigned long total = 0;

    if (command_in_options("sign")) {
        scenario.command_code = TPM2_CC_Sign;
        scenario.sign = (struct cryptoops_sign_scenario) {
                .key_params = { .type = TPM2_ALG_NULL },
                .scheme = { .scheme = TPM2_ALG_NULL },
                .digest = { .size = 32 },
        };
        while (get_next_asym_key_params(&scenario.sign.key_params)) {
            while (get_next_sign_scheme(&scenario.sign.scheme, scenario.sign.key_params.type)) {
                TPM2B_PUBLIC inPublic = prepare_template(&scenario.sign.key_params);

                TPM2_RC rc = test_parms(sapi_context, &inPublic.publicArea);
                if (rc == TPM2_RC_SUCCESS) {
                    total += scenario.parameters.repetitions;
                }
            }
            scenario.sign.scheme.scheme = TPM2_ALG_NULL;
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

    prog.total = count_supported_cryptoops_scenarios(sapi_context, parameters);
    prog.current = 0;

    TPMI_DH_OBJECT primary_handle;
    log_info("Cryptoops ecc: Creating primary key...");
    TPM2_RC rc = create_primary_ECC_NIST_P256(sapi_context, &primary_handle);
    if (rc != TPM2_RC_SUCCESS) {
        log_error("Cryptoops ecc: Failed to create primary key!");
        return;
    } else {
        log_info("Cryptoops ecc: Created primary key with handle %08x", primary_handle);
    }

    if (command_in_options("sign")) {
        scenario.command_code = TPM2_CC_Sign;
        scenario.sign = (struct cryptoops_sign_scenario) {
                .key_params = { .type = TPM2_ALG_NULL },
                .scheme = { .scheme = TPM2_ALG_NULL },
                .digest = {
                        .size = 32,
                        .buffer = { 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
                                    0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
                                    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
                                    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
                        } // SHA256("")
                },
        };

        while (get_next_asym_key_params(&scenario.sign.key_params)) {
            while (get_next_sign_scheme(&scenario.sign.scheme, scenario.sign.key_params.type)) {
                if(scenario.sign.key_params.type == TPM2_ALG_ECC) {
                    run_ecc_sign_on_primary(sapi_context, &scenario, primary_handle, &prog);
                } else if(scenario.sign.key_params.type == TPM2_ALG_RSA) {
                    run_rsa_on_primary(sapi_context, &scenario, primary_handle, &prog);
                } else {
                    log_error("Cryptoops: Unknown signing algorithm %04x", scenario.sign.key_params.type);
                }
            }
            scenario.sign.scheme.scheme = TPM2_ALG_NULL;
        }
    }

    Tss2_Sys_FlushContext(sapi_context, primary_handle);
}
