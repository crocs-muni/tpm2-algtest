#include "perf.h"
#include "object_util.h"
#include "logging.h"
#include "util.h"
#include "perf_util.h"
#include "key_params_generator.h"

#include <string.h>
#include <stdlib.h>
#include <time.h>

bool create_primary_for_perf(
        TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT *primary_handle)
{
    log_info("Perf: creating primary...");
    TPM2_RC rc = create_some_primary(sapi_context, primary_handle);
    if (rc == TPM2_RC_SUCCESS) {
        log_info("Created primary object with handle %08x", *primary_handle);
    }
    return rc == TPM2_RC_SUCCESS;
}

static
bool alloc_result(
        const struct perf_scenario *scenario,
        struct perf_result *result)
{
    result->data_points = calloc(scenario->parameters.repetitions,
            sizeof(struct perf_data_point));
    if (result->data_points == NULL) {
        return false;
    }
    return true;
}

static
void free_result(struct perf_result *result)
{
    free(result->data_points);
}

bool get_csv_filename_sign(
        const struct perf_sign_scenario *scenario,
        char filename[256])
{
    switch (scenario->key_params.type) {
    case TPM2_ALG_RSA:
        snprintf(filename, 256, "Perf_Sign_RSA_%d.csv",
                scenario->key_params.parameters.rsaDetail.keyBits);
        break;
    case TPM2_ALG_ECC:
        snprintf(filename, 256, "Perf_Sign_ECC_0x%04x.csv",
                scenario->key_params.parameters.eccDetail.curveID);
        break;
    default:
        log_error("Perf sign: (output_results) Algorithm type not supported.");
        return false;
    }
    return true;
}

bool get_csv_filename_verifysignature(
        const struct perf_verifysignature_scenario *scenario,
        char filename[256])
{
    switch (scenario->key_params.type) {
    case TPM2_ALG_RSA:
        snprintf(filename, 256, "Perf_VerifySignature_RSA_%d.csv",
                scenario->key_params.parameters.rsaDetail.keyBits);
        break;
    case TPM2_ALG_ECC:
        snprintf(filename, 256, "Perf_VerifySignature_ECC_0x%04x.csv",
                scenario->key_params.parameters.eccDetail.curveID);
        break;
    default:
        log_error("Perf verifysignature: (output_results) Algorithm type not supported.");
        return false;
    }
    return true;
}

static
void output_results(
        const struct perf_scenario *scenario,
        const struct perf_result *result)
{
    char filename[256];
    bool fn_valid = true;
    switch (scenario->command_code) {
    case TPM2_CC_Sign:
        fn_valid = get_csv_filename_sign(&scenario->sign, filename); break;
    case TPM2_CC_VerifySignature:
        fn_valid = get_csv_filename_verifysignature(&scenario->verifysignature, filename); break;
    case TPM2_CC_RSA_Encrypt:
        snprintf(filename, 256, "Perf_RSA_Encrypt_%d.csv", scenario->rsa_encrypt.keylen); break;
    case TPM2_CC_RSA_Decrypt:
        snprintf(filename, 256, "Perf_RSA_Decrypt_%d.csv", scenario->rsa_decrypt.keylen); break;
    default:
        log_error("Perf: (output_results) Command not supported.");
        return;
    }
    if (!fn_valid) { return; }

    FILE *out = open_csv(filename, "duration,return_code");
    for (int i = 0; i < result->size; ++i) {
        struct perf_data_point *dp = &result->data_points[i];
        fprintf(out, "%f, %04x\n", dp->duration_s, dp->rc);
    }
    fclose(out);
}

bool run_perf_sign(
        TSS2_SYS_CONTEXT *sapi_context,
        const struct perf_scenario *scenario,
        TPMI_DH_OBJECT primary_handle,
        struct perf_result *result)
{
    TPM2B_PUBLIC inPublic = prepare_template(&scenario->sign.key_params);

    TPM2_RC rc = test_parms(sapi_context, &inPublic.publicArea);
    if (rc != TPM2_RC_SUCCESS) {
        return false;
    }

    TPM2_HANDLE object_handle;
    log_info("Perf sign: Generating signing key...");
    rc = create_loaded(sapi_context, &inPublic, primary_handle, &object_handle);
    if (rc != TPM2_RC_SUCCESS) {
        log_error("Perf sign: Error when creating signing key %04x", rc);
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
                &scenario->sign.digest, &signature,
                &result->data_points[i].duration_s);

        ++result->size;
        switch (scenario->sign.key_params.type) {
        case TPM2_ALG_RSA:
            log_info("Perf sign %d: RSA | keybits %d | duration %f | rc %04x",
                    i, scenario->sign.key_params.parameters.rsaDetail.keyBits,
                    result->data_points[i].duration_s, result->data_points[i].rc);
                    break;
        case TPM2_ALG_ECC:
            log_info("Perf sign %d: ECC | curve %04x | duration %f | rc %04x",
                    i, scenario->sign.key_params.parameters.eccDetail.curveID,
                    result->data_points[i].duration_s, result->data_points[i].rc);
        }
    }

    Tss2_Sys_FlushContext(sapi_context, object_handle);
    return true;
}

bool run_perf_verifysignature(
        TSS2_SYS_CONTEXT *sapi_context,
        const struct perf_scenario *scenario,
        TPMI_DH_OBJECT primary_handle,
        struct perf_result *result)
{
    TPM2B_PUBLIC inPublic = prepare_template(&scenario->verifysignature.key_params);

    TPM2_RC rc = test_parms(sapi_context, &inPublic.publicArea);
    if (rc != TPM2_RC_SUCCESS) {
        return false;
    }

    TPM2_HANDLE object_handle;
    log_info("Perf verifysignature: Generating signing key...");
    rc = create_loaded(sapi_context, &inPublic, primary_handle, &object_handle);
    if (rc != TPM2_RC_SUCCESS) {
        log_error("Perf verifysignature: Error when creating signing key %04x", rc);
        return false;
    }

    TPMT_SIGNATURE signature;
    rc = sign(sapi_context, object_handle, &scenario->verifysignature.digest,
            &signature, NULL);

    if (rc != TPM2_RC_SUCCESS) {
        log_error("Perf verifysignature: Could not create signature %04x", rc);
        Tss2_Sys_FlushContext(sapi_context, object_handle);
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

        result->data_points[i].rc = verifysignature(sapi_context, object_handle,
                &scenario->verifysignature.digest, &signature,
                &result->data_points[i].duration_s);

        ++result->size;
        switch (scenario->verifysignature.key_params.type) {
        case TPM2_ALG_RSA:
            log_info("Perf verifysignature %d: RSA | keybits %d | duration %f | rc %04x",
                    i, scenario->verifysignature.key_params.parameters.rsaDetail.keyBits,
                    result->data_points[i].duration_s, result->data_points[i].rc);
                    break;
        case TPM2_ALG_ECC:
            log_info("Perf verifysignature %d: ECC | curve %04x | duration %f | rc %04x",
                    i, scenario->verifysignature.key_params.parameters.eccDetail.curveID,
                    result->data_points[i].duration_s, result->data_points[i].rc);
        }
    }
    Tss2_Sys_FlushContext(sapi_context, object_handle);
    return true;
}

bool run_perf_rsa_encrypt(
        TSS2_SYS_CONTEXT* sapi_context,
        const struct perf_scenario *scenario,
        TPMI_DH_OBJECT primary_handle,
        struct perf_result *result)
{
    TPM2B_PUBLIC inPublic = prepare_template_RSA(scenario->rsa_encrypt.keylen);
    TPM2_RC rc = test_parms(sapi_context, &inPublic.publicArea);
    if (rc != TPM2_RC_SUCCESS) {
        return false;
    }

    TPM2_HANDLE object_handle;
    log_info("Perf rsa_encrypt: Generating encryption key...");
    rc = create_loaded(sapi_context, &inPublic, primary_handle, &object_handle);
    if (rc != TPM2_RC_SUCCESS) {
        log_error("Perf rsa_encrypt: Error when creating encryption key %04x", rc);
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

        TPM2B_PUBLIC_KEY_RSA outData;
        result->data_points[i].rc = rsa_encrypt(sapi_context, object_handle,
                &scenario->rsa_encrypt.message, &outData,
                &result->data_points[i].duration_s);
        ++result->size;
        log_info("Perf rsa_encrypt: %d: keybits %d | duration %f | rc %04x",
                i, scenario->rsa_encrypt.keylen, result->data_points[i].duration_s,
                result->data_points[i].rc);
    }
    Tss2_Sys_FlushContext(sapi_context, object_handle);
    return true;
}

bool run_perf_rsa_decrypt(
        TSS2_SYS_CONTEXT* sapi_context,
        const struct perf_scenario *scenario,
        TPMI_DH_OBJECT primary_handle,
        struct perf_result *result)
{
    TPM2B_PUBLIC inPublic = prepare_template_RSA(scenario->rsa_decrypt.keylen);
    TPM2_RC rc = test_parms(sapi_context, &inPublic.publicArea);
    if (rc != TPM2_RC_SUCCESS) {
        return false;
    }

    TPM2_HANDLE object_handle;
    log_info("Perf rsa_decrypt: Generating encryption key...");
    rc = create_loaded(sapi_context, &inPublic, primary_handle, &object_handle);
    if (rc != TPM2_RC_SUCCESS) {
        log_error("Perf rsa_decrypt: Error when creating encryption key %04x", rc);
        return false;
    }

    TPM2B_PUBLIC_KEY_RSA ciphertext = { .size = scenario->rsa_decrypt.keylen / 8 };
    memset(&ciphertext.buffer, 0x00, ciphertext.size);

    result->size = 0;
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (unsigned i = 0; i < scenario->parameters.repetitions; ++i) {
        clock_gettime(CLOCK_MONOTONIC, &end);
        if (get_duration_s(&start, &end) > scenario->parameters.max_duration_s) {
            break;
        }

        TPM2B_PUBLIC_KEY_RSA decrypted_message;
        result->data_points[i].rc = rsa_decrypt(sapi_context, object_handle,
                &ciphertext, &decrypted_message,
                &result->data_points[i].duration_s);
        ++result->size;
        log_info("Perf rsa_decrypt: %d: keybits %d | duration %f | rc %04x",
                i, scenario->rsa_decrypt.keylen, result->data_points[i].duration_s,
                result->data_points[i].rc);
    }
    Tss2_Sys_FlushContext(sapi_context, object_handle);
    return true;
}

void run_perf_on_primary(
        TSS2_SYS_CONTEXT *sapi_context,
        const struct perf_scenario *scenario,
        TPMI_DH_OBJECT primary_handle)
{
    struct perf_result result;
    if (!alloc_result(scenario, &result)) {
        log_error("Perf: cannot allocate memory for result.");
        return;
    }

    bool ok;
    switch (scenario->command_code) {
    case TPM2_CC_Sign:
        ok = run_perf_sign(sapi_context, scenario, primary_handle, &result);
        break;
    case TPM2_CC_VerifySignature:
        ok = run_perf_verifysignature(sapi_context, scenario, primary_handle, &result);
        break;
    case TPM2_CC_RSA_Encrypt:
        ok = run_perf_rsa_encrypt(sapi_context, scenario, primary_handle, &result);
        break;
    case TPM2_CC_RSA_Decrypt:
        ok = run_perf_rsa_decrypt(sapi_context, scenario, primary_handle, &result);
        break;
    default:
        log_warning("Perf: unsupported command code %04x", scenario->command_code);
    }

    if (ok) {
        output_results(scenario, &result);
    }
    free_result(&result);
}

#if 0
void run_perf(
        TSS2_SYS_CONTEXT *sapi_context,
        const struct perf_scenario *scenario)
{
    TPMI_DH_OBJECT primary_handle;
    bool ok = create_primary_for_perf(sapi_context, &primary_handle);
    if (!ok) {
        log_error("Failed to create primary object for perf testing.");
    }

    run_perf_on_primary(sapi_context, scenario, primary_handle);

    Tss2_Sys_FlushContext(sapi_context, primary_handle);
}
#endif

void run_perf_scenarios(
        TSS2_SYS_CONTEXT *sapi_context,
        const struct scenario_parameters *parameters)
{
    struct perf_scenario scenario = {
        .parameters = *parameters,
    };

    TPMI_DH_OBJECT primary_handle;
    bool ok = create_primary_for_perf(sapi_context, &primary_handle);
    if (!ok) {
        log_error("Failed to create primary object for perf testing.");
    }

    if (command_in_options("sign")) {
        scenario.command_code = TPM2_CC_Sign;
        scenario.sign = (struct perf_sign_scenario) {
            .key_params = { .type = TPM2_ALG_NULL },
            .digest = { .size = 32 }, // Using SHA256
        };
        memset(&scenario.sign.digest.buffer, 0x00, scenario.sign.digest.size);
        while (get_next_key_params(&scenario.sign.key_params)) {
            run_perf_on_primary(sapi_context, &scenario, primary_handle);
        }
    }

    if (command_in_options("verifysignature")) {
        scenario.command_code = TPM2_CC_VerifySignature;
        scenario.verifysignature = (struct perf_verifysignature_scenario) {
            .key_params = { .type = TPM2_ALG_NULL },
            .digest = { .size = 32 }, // Using SHA256
        };
        memset(&scenario.verifysignature.digest.buffer, 0x00, scenario.verifysignature.digest.size);
        while (get_next_key_params(&scenario.verifysignature.key_params)) {
            run_perf_on_primary(sapi_context, &scenario, primary_handle);
        }
    }

    if (command_in_options("rsa_encrypt")) {
        scenario.command_code = TPM2_CC_RSA_Encrypt;
        scenario.rsa_encrypt = (struct perf_rsa_encrypt_scenario) {
            .keylen = 0,
            .message = { .size = 64 },
        };
        memset(&scenario.rsa_encrypt.message.buffer, 0x00, scenario.rsa_encrypt.message.size);
        while (get_next_rsa_keylen(&scenario.rsa_encrypt.keylen)) {
            run_perf_on_primary(sapi_context, &scenario, primary_handle);
        }
    }

    if (command_in_options("rsa_decrypt")) {
        scenario.command_code = TPM2_CC_RSA_Decrypt;
        scenario.rsa_decrypt = (struct perf_rsa_decrypt_scenario) {
            .keylen = 0,
            .ciphertext = { .size = 64 },
        };
        memset(&scenario.rsa_decrypt.ciphertext.buffer, 0x00, scenario.rsa_decrypt.ciphertext.size);
        while (get_next_rsa_keylen(&scenario.rsa_decrypt.keylen)) {
            run_perf_on_primary(sapi_context, &scenario, primary_handle);
        }
    }

    Tss2_Sys_FlushContext(sapi_context, primary_handle);
}
