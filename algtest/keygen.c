#include "keygen.h"
#include "logging.h"
#include "create_util.h"
#include "util.h"

#include <tss2/tss2_sys.h>
#include <stdlib.h>
#include <stdio.h>

bool test_detail(
        TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT primary_handle,
        const struct keygen_scenario *scenario,
        struct keygen_result *result)
{
    TPM2B_PUBLIC inPublic;
    switch (scenario->type) {
    case TPM2_ALG_RSA:
        inPublic = prepare_template_RSA(scenario->keyBits);
        break;
    case TPM2_ALG_ECC:
        inPublic = prepare_template_ECC(scenario->curveID);
        break;
    default:
        log_error("Keygen: algorithm type not supported!");
        return false;
    }

    TPM2_RC rc = test_parms(sapi_context, &inPublic.publicArea);
    if (rc != TPM2_RC_SUCCESS) {
        return false;
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (unsigned i = 0; i < scenario->parameters.repetitions; ++i) {
        result->data_points[i].rc = create(sapi_context, &inPublic,
                primary_handle, &result->data_points[i].duration_s);
        ++result->size;
        log_info("Keygen: type %04x | keybits %d | curve %04x | duration %f | rc %04x",
                scenario->type, scenario->keyBits, scenario->curveID,
                result->data_points[i].duration_s, result->data_points[i].rc);
        if (scenario->output_keys) {

        }

        clock_gettime(CLOCK_MONOTONIC, &end);
        if (get_duration_s(&start, &end) > scenario->parameters.max_duration_s) {
            break;
        }
    }
    return true;
}

void output_results(const struct keygen_scenario *scenario,
        const struct keygen_result *result)
{
    char filename[256];
    switch (scenario->type) {
    case TPM2_ALG_RSA:
        snprintf(filename, 256, "Keygen_RSA_%d.csv", scenario->keyBits);
        break;
    case TPM2_ALG_ECC:
        snprintf(filename, 256, "Keygen_ECC_0x%04x.csv", scenario->curveID);
        break;
    default:
        log_error("Keygen: (output_results) Algorithm type not supported.");
        return;
    }

    FILE* out = open_csv(filename, "duration,return_code");
    for (unsigned i = 0; i < result->size; ++i) {
        struct keygen_data_point *dp = &result->data_points[i];
        fprintf(out, "%f, %04x\n", dp->duration_s, dp->rc);
    }
    fclose(out);
}

bool alloc_result(const struct keygen_scenario *scenario,
        struct keygen_result *result)
{
    result->data_points = calloc(scenario->parameters.repetitions,
            sizeof(struct keygen_data_point));
    if (result->data_points == NULL) {
        log_error("Keygen: (calloc) Cannot allocate memory for result.");
        return false;
    }

    if (scenario->output_keys) {
        result->public_keys = calloc(scenario->parameters.repetitions,
                sizeof(TPMU_PUBLIC_ID));
        if (result->public_keys == NULL) {
            log_error("Keygen: (calloc) Cannot allocate memory for public keys.");
            free(result->data_points);
            return false;
        }
    }
    return true;
}

void free_result(const struct keygen_scenario *scenario,
        struct keygen_result *result)
{
    free(result->data_points);
    free(result->public_keys);
}

bool test_keygen_on_primary(TSS2_SYS_CONTEXT *sapi_context,
        const struct keygen_scenario *scenario,
        TPMI_DH_OBJECT primary_handle)
{
    struct keygen_result result;

    if (!alloc_result(scenario, &result)) {
        return false;
    }

    bool ok = test_detail(sapi_context, primary_handle, scenario, &result);
    if (ok) {
        output_results(scenario, &result);
    }

    free_result(scenario, &result);
    return ok;
}

bool create_primary_for_keygen(TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT *primary_handle)
{
    log_info("Keygen: creating primary...");
    TPM2B_PUBLIC inPublic = prepare_template_RSA_primary(1024); // TODO: if fail, try different
    TPM2_RC rc = test_parms(sapi_context, &inPublic.publicArea);
    if (rc != TPM2_RC_SUCCESS) {
        log_warning("Keygen: (create_primary_for_keygen) "
                "Invalid parms for primary object! (%04x)", rc);
        return false;
    }

    rc = create_primary(sapi_context, &inPublic, primary_handle);
    if (rc != TPM2_RC_SUCCESS) {
        log_error("Keygen: (create_primary_for_keygen) "
                "Cannot create primary object! (%04x)", rc);
        return false;
    }
    log_info("Created primary object with handle %08x", *primary_handle);
    return true;
}

bool test_keygen(TSS2_SYS_CONTEXT *sapi_context,
        const struct keygen_scenario *scenario)
{
    TPMI_DH_OBJECT primary_handle;
    bool ok = create_primary_for_keygen(sapi_context, &primary_handle);
    if (!ok) {
        return false;
    }
    ok = test_keygen_on_primary(sapi_context, scenario, primary_handle);

    Tss2_Sys_FlushContext(sapi_context, primary_handle);
    return ok;
}

void test_keygen_all(TSS2_SYS_CONTEXT *sapi_context,
        const struct scenario_parameters *parameters)
{
    struct keygen_scenario scenario = {
        .parameters = *parameters,
        .keyBits = 0,
        .curveID = 0x0000,
        .output_keys = false
    };

    TPMI_DH_OBJECT primary_handle;
    bool ok = create_primary_for_keygen(sapi_context, &primary_handle);
    if (!ok) {
        return;
    }

    scenario.type = TPM2_ALG_RSA;
    for (TPMI_RSA_KEY_BITS keyBits = 0; keyBits <= 2048; keyBits += 32) {
        scenario.keyBits = keyBits;
        test_keygen_on_primary(sapi_context, &scenario, primary_handle);
    }
    scenario.keyBits = 0;

    scenario.type = TPM2_ALG_ECC;
    for (TPMI_ECC_CURVE curveID = 0x0000; curveID <= 0x0020; ++curveID) {
        scenario.curveID = curveID;
        test_keygen_on_primary(sapi_context, &scenario, primary_handle);
    }

    Tss2_Sys_FlushContext(sapi_context, primary_handle);
}
