#include "perf.h"
#include "object_util.h"
#include "logging.h"
#include "util.h"
#include "perf_util.h"
#include "key_params_generator.h"

#include <string.h>
#include <stdlib.h>
#include <time.h>

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
        snprintf(filename, 256, "Perf_Sign:RSA_%d_0x%04x.csv",
                scenario->key_params.parameters.rsaDetail.keyBits, scenario->scheme.scheme);
        break;
    case TPM2_ALG_ECC:
        snprintf(filename, 256, "Perf_Sign:ECC_0x%04x_0x%04x.csv",
                scenario->key_params.parameters.eccDetail.curveID, scenario->scheme.scheme);
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
        snprintf(filename, 256, "Perf_VerifySignature:RSA_%d_0x%04x.csv",
                scenario->key_params.parameters.rsaDetail.keyBits, scenario->scheme.scheme);
        break;
    case TPM2_ALG_ECC:
        snprintf(filename, 256, "Perf_VerifySignature:ECC_0x%04x_0x%04x.csv",
                scenario->key_params.parameters.eccDetail.curveID, scenario->scheme.scheme);
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
        snprintf(filename, 256, "Perf_RSA_Encrypt:RSA_%d_0x%04x.csv",
                scenario->rsa_encrypt.keylen, scenario->rsa_encrypt.scheme.scheme); break;
    case TPM2_CC_RSA_Decrypt:
        snprintf(filename, 256, "Perf_RSA_Decrypt:RSA_%d_0x%04x.csv",
                scenario->rsa_decrypt.keylen, scenario->rsa_decrypt.scheme.scheme); break;
    case TPM2_CC_GetRandom:
        snprintf(filename, 256, "Perf_GetRandom.csv"); break;
    case TPM2_CC_EncryptDecrypt:
        snprintf(filename, 256, "Perf_EncryptDecrypt:0x%04x_%d_0x%04x_%s.csv",
                scenario->encryptdecrypt.sym.algorithm,
                scenario->encryptdecrypt.sym.keyBits.sym,
                scenario->encryptdecrypt.sym.mode.sym,
                scenario->encryptdecrypt.decrypt ? "decrypt" : "encrypt");
        break;
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
                &scenario->sign.scheme, &scenario->sign.digest, &signature,
                &result->data_points[i].duration_s);

        ++result->size;
        switch (scenario->sign.key_params.type) {
        case TPM2_ALG_RSA:
            log_info("Perf sign %d: RSA | scheme %04x | keybits %d | duration %f | rc %04x",
                    i, scenario->sign.scheme.scheme,
                    scenario->sign.key_params.parameters.rsaDetail.keyBits,
                    result->data_points[i].duration_s, result->data_points[i].rc);
            break;
        case TPM2_ALG_ECC:
            log_info("Perf sign %d: ECC | scheme %04x | curve %04x | duration %f | rc %04x",
                    i, scenario->sign.scheme.scheme,
                    scenario->sign.key_params.parameters.eccDetail.curveID,
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
    rc = sign(sapi_context, object_handle, &scenario->verifysignature.scheme,
            &scenario->verifysignature.digest, &signature, NULL);

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
            log_info("Perf verifysignature %d: RSA | scheme %04x | keybits %d | duration %f | rc %04x",
                    i, scenario->verifysignature.scheme.scheme,
                    scenario->verifysignature.key_params.parameters.rsaDetail.keyBits,
                    result->data_points[i].duration_s, result->data_points[i].rc);
                    break;
        case TPM2_ALG_ECC:
            log_info("Perf verifysignature %d: ECC | scheme %04x | curve %04x | duration %f | rc %04x",
                    i, scenario->verifysignature.scheme.scheme,
                    scenario->verifysignature.key_params.parameters.eccDetail.curveID,
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
                &scenario->rsa_encrypt.message, &scenario->rsa_encrypt.scheme,
                &outData, &result->data_points[i].duration_s);
        ++result->size;
        log_info("Perf rsa_encrypt: %d: scheme: %04x | keybits %d | duration %f | rc %04x",
                i, scenario->rsa_encrypt.scheme.scheme,
                scenario->rsa_encrypt.keylen, result->data_points[i].duration_s,
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

    TPM2B_PUBLIC_KEY_RSA ciphertext = { .size = 0 };
    rsa_encrypt(sapi_context, object_handle, &scenario->rsa_decrypt.message,
            &scenario->rsa_decrypt.scheme, &ciphertext, NULL);

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
                &ciphertext, &scenario->rsa_decrypt.scheme, &decrypted_message,
                &result->data_points[i].duration_s);
        ++result->size;
        log_info("Perf rsa_decrypt: %d: scheme %04x | keybits %d | duration %f | rc %04x",
                i, scenario->rsa_decrypt.scheme.scheme,
                scenario->rsa_decrypt.keylen, result->data_points[i].duration_s,
                result->data_points[i].rc);
    }
    Tss2_Sys_FlushContext(sapi_context, object_handle);
    return true;
}

bool run_perf_encryptdecrypt(
        TSS2_SYS_CONTEXT *sapi_context,
        const struct perf_scenario *scenario,
        TPMI_DH_OBJECT primary_handle,
        struct perf_result *result)
{
    TPMT_PUBLIC_PARMS key_params = {
        .type = TPM2_ALG_SYMCIPHER,
        .parameters = {
            .symDetail = {
                .sym = scenario->encryptdecrypt.sym,
            }
        }
    };

    TPM2B_PUBLIC inPublic = prepare_template(&key_params);
    inPublic.publicArea.objectAttributes |= TPMA_OBJECT_DECRYPT;

    TPM2_RC rc = test_parms(sapi_context, &inPublic.publicArea);
    if (rc != TPM2_RC_SUCCESS) {
        return false;
    }

    TPM2_HANDLE object_handle;
    log_info("Perf encryptdecrypt: Generating key...");
    rc = create_loaded(sapi_context, &inPublic, primary_handle, &object_handle);
    if (rc != TPM2_RC_SUCCESS) {
        log_error("Perf encryptdecrypt: Error when creating key %04x", rc);
        return false;
    }

    TPM2B_IV inIv = {
        .size = scenario->encryptdecrypt.sym.mode.sym == TPM2_ALG_ECB
            ? 0 : scenario->encryptdecrypt.sym.keyBits.sym / 8
    };
    memset(&inIv.buffer, 0x00, inIv.size);
    TPM2B_MAX_BUFFER inData = { .size = 256 };
    memset(&inData.buffer, 0x00, inData.size);

    result->size = 0;
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (unsigned i = 0; i < scenario->parameters.repetitions; ++i) {
        clock_gettime(CLOCK_MONOTONIC, &end);
        if (get_duration_s(&start, &end) > scenario->parameters.max_duration_s) {
            break;
        }

        result->data_points[i].rc = encryptdecrypt(sapi_context, object_handle,
                scenario->encryptdecrypt.decrypt, &inIv, &inData,
                &result->data_points[i].duration_s);
        ++result->size;

        log_info("Perf encryptdecrypt %d: algorithm %04x | keybits %d | mode %04x | %s | duration %f | rc %04x",
            i, scenario->encryptdecrypt.sym.algorithm,
            scenario->encryptdecrypt.sym.keyBits,
            scenario->encryptdecrypt.sym.mode,
            scenario->encryptdecrypt.decrypt ? "decrypt" : "encrypt",
            result->data_points[i].duration_s, result->data_points[i].rc);
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
    case TPM2_CC_EncryptDecrypt:
        ok = run_perf_encryptdecrypt(sapi_context, scenario, primary_handle, &result);
        break;
    default:
        log_warning("Perf: unsupported command code %04x", scenario->command_code);
    }

    if (ok) {
        output_results(scenario, &result);
    }
    free_result(&result);
}

void run_perf_getrandom(
        TSS2_SYS_CONTEXT *sapi_context,
        const struct perf_scenario *scenario)
{
    struct perf_result result;
    if (!alloc_result(scenario, &result)) {
        log_error("Perf: cannot allocate memory for result.");
        return;
    }
    result.size = 0;
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (unsigned i = 0; i < scenario->parameters.repetitions; ++i) {
        clock_gettime(CLOCK_MONOTONIC, &end);
        if (get_duration_s(&start, &end) > scenario->parameters.max_duration_s) {
            break;
        }

        result.data_points[i].rc = getrandom(sapi_context, &result.data_points[i].duration_s);
        ++result.size;
        log_info("Perf getrandom: %d: duration %f | rc %04x",
                i, result.data_points[i].duration_s, result.data_points[i].rc);
    }

    output_results(scenario, &result);
    free_result(&result);
}

void run_perf_scenarios(
        TSS2_SYS_CONTEXT *sapi_context,
        const struct scenario_parameters *parameters)
{
    struct perf_scenario scenario = {
        .parameters = *parameters,
    };

    TPMI_DH_OBJECT primary_handle;
    log_info("Perf: Creating primary key...");
    TPM2_RC rc = create_primary_ECC_NIST_P256(sapi_context, &primary_handle);
    if (rc != TPM2_RC_SUCCESS) {
        log_error("Perf: Failed to create primary key!");
        return;
    } else {
        log_info("Perf: Created primary key with handle %08x", primary_handle);
    }

    if (command_in_options("sign")) {
        scenario.command_code = TPM2_CC_Sign;
        scenario.sign = (struct perf_sign_scenario) {
            .key_params = { .type = TPM2_ALG_NULL },
            .scheme = { .scheme = TPM2_ALG_NULL },
            .digest = { .size = 32 }, // Using SHA256
        };
        memset(&scenario.sign.digest.buffer, 0x00, scenario.sign.digest.size);
        while (get_next_asym_key_params(&scenario.sign.key_params)) {
            while (get_next_sign_scheme(&scenario.sign.scheme, scenario.sign.key_params.type)) {
                run_perf_on_primary(sapi_context, &scenario, primary_handle);
            }
            scenario.sign.scheme.scheme = TPM2_ALG_NULL;
        }
    }

    if (command_in_options("verifysignature")) {
        scenario.command_code = TPM2_CC_VerifySignature;
        scenario.verifysignature = (struct perf_verifysignature_scenario) {
            .key_params = { .type = TPM2_ALG_NULL },
            .scheme = { .scheme = TPM2_ALG_NULL },
            .digest = { .size = 32 }, // Using SHA256
        };
        memset(&scenario.verifysignature.digest.buffer, 0x00, scenario.verifysignature.digest.size);
        while (get_next_asym_key_params(&scenario.verifysignature.key_params)) {
            do {
                run_perf_on_primary(sapi_context, &scenario, primary_handle);
            } while (get_next_sign_scheme(&scenario.verifysignature.scheme, scenario.verifysignature.key_params.type));
            scenario.verifysignature.scheme.scheme = TPM2_ALG_NULL;
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
            do {
                run_perf_on_primary(sapi_context, &scenario, primary_handle);
            } while (get_next_rsa_enc_scheme(&scenario.rsa_encrypt.scheme));
            scenario.rsa_encrypt.scheme.scheme = TPM2_ALG_NULL;
        }
    }

    if (command_in_options("rsa_decrypt")) {
        scenario.command_code = TPM2_CC_RSA_Decrypt;
        scenario.rsa_decrypt = (struct perf_rsa_decrypt_scenario) {
            .keylen = 0,
            .message = { .size = 64 },
        };
        memset(&scenario.rsa_decrypt.message.buffer, 0x00, scenario.rsa_decrypt.message.size);
        while (get_next_rsa_keylen(&scenario.rsa_decrypt.keylen)) {
            do {
                run_perf_on_primary(sapi_context, &scenario, primary_handle);
            } while (get_next_rsa_enc_scheme(&scenario.rsa_decrypt.scheme));
            scenario.rsa_decrypt.scheme.scheme = TPM2_ALG_NULL;
        }
    }

    if (command_in_options("getrandom")) {
        scenario.command_code = TPM2_CC_GetRandom;
        run_perf_getrandom(sapi_context, &scenario);
    }

    if (command_in_options("encryptdecrypt")) {
        scenario.command_code = TPM2_CC_EncryptDecrypt;
        scenario.encryptdecrypt = (struct perf_encryptdecrypt_scenario) {
            .sym = {
                .algorithm = TPM2_ALG_NULL,
                .keyBits = 0,
                .mode = TPM2_ALG_NULL,
            },
        };
        while (get_next_symcipher(&scenario.encryptdecrypt.sym)) {
            while (get_next_sym_mode(&scenario.encryptdecrypt.sym.mode.sym)) {
                scenario.encryptdecrypt.decrypt = TPM2_NO;
                run_perf_on_primary(sapi_context, &scenario, primary_handle);
                scenario.encryptdecrypt.decrypt = TPM2_YES;
                run_perf_on_primary(sapi_context, &scenario, primary_handle);
            }
            scenario.encryptdecrypt.sym.mode.sym = TPM2_ALG_NULL;
        }
    }

    Tss2_Sys_FlushContext(sapi_context, primary_handle);
}
