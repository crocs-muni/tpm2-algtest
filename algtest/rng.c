#include "rng.h"
#include "object_util.h"
#include "logging.h"
#include "util.h"
#include "status.h"

#include <string.h>
#include <stdlib.h>
#include <time.h>

static
bool alloc_result(
        const struct rng_scenario *scenario,
        struct rng_result *result)
{
    result->data_points = calloc(scenario->parameters.repetitions, sizeof(struct rng_data_point));
    return result->data_points != NULL;
}

static
void free_result(struct rng_result *result)
{
    free(result->data_points);
}

static
void output_results(
        const struct rng_scenario *scenario,
        const struct rng_result *result)
{
    char filename[256];
    switch (scenario->command_code) {
    case TPM2_CC_GetRandom:
        snprintf(filename, 256, "Rng:%d.csv", scenario->bytes_number);
        break;
    default:
        log_error("Rng: (output_results) Command not supported.");
        return;
    }

    FILE *out = open_csv(filename, "bytes_number,data,duration,return_code");
    for (int i = 0; i < result->size; ++i) {
        struct rng_data_point *dp = &result->data_points[i];
        fprintf(out, "%d,", dp->bytes_number);
        for(uint16_t j = 0; j < dp->bytes_number; ++j) {
            fprintf(out, "%02x", dp->data[j]);
        }
        fprintf(out, ",%f,%04x\n", dp->duration_s, dp->rc);
    }
    fclose(out);
}


TPM2_RC getrandom_bytes(
        TSS2_SYS_CONTEXT *sapi_context,
        TPM2B_DIGEST *buffer,
        uint16_t bytesRequested,
        double *duration)
{
    TSS2L_SYS_AUTH_RESPONSE rspAuthsArray;

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    TPM2_RC rc = Tss2_Sys_GetRandom(sapi_context, NULL, bytesRequested, buffer,
                                    &rspAuthsArray);

    clock_gettime(CLOCK_MONOTONIC, &end);
    if (duration != NULL) {
        *duration = get_duration_s(&start, &end);
    }
    return rc;
}


void run_rng_getrandom(
        TSS2_SYS_CONTEXT *sapi_context,
        const struct rng_scenario *scenario,
        struct progress *prog)
{
    struct rng_result result;
    if (!alloc_result(scenario, &result)) {
        log_error("Rng: cannot allocate memory for result.");
        return;
    }
    int failures = 0;
    result.size = 0;
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (unsigned i = 0; i < scenario->parameters.repetitions; ++i) {
        clock_gettime(CLOCK_MONOTONIC, &end);
        if (get_duration_s(&start, &end) > scenario->parameters.max_duration_s) {
            break;
        }

        TPM2B_DIGEST buffer = { .size = 0 };
        result.data_points[i].rc = getrandom_bytes(sapi_context, &buffer, scenario->bytes_number, &result.data_points[i].duration_s);
        result.data_points[i].bytes_number = buffer.size;
        memcpy(result.data_points[i].data, buffer.buffer, buffer.size);

        if(result.data_points[i].rc != TPM2_RC_SUCCESS) {
            ++failures;
        }
        ++result.size;
        log_info("Rng %d: duration %f | rc %04x",
                 i, result.data_points[i].duration_s, result.data_points[i].rc);
        printf("%lu%%\n", increase_progress(prog));

        if(failures >= FAILURE_LIMIT) {
            log_error("Rng: Too many failures. Skipping remaining iterations.");
            skip_progress(prog, scenario->parameters.repetitions - i - 1);
            free_result(&result);
            return;
        }
    }

    output_results(scenario, &result);
    free_result(&result);
}

unsigned long count_supported_rng_scenarios(const struct scenario_parameters *parameters)
{
    if (command_in_options("getrandom")) {
        return parameters->repetitions * 2;
    }
    return 0;
}

void run_rng_scenarios(
        TSS2_SYS_CONTEXT *sapi_context,
        const struct scenario_parameters *parameters)
{
    struct rng_scenario scenario = {
        .parameters = *parameters,
    };
    struct progress prog;

    prog.total = count_supported_rng_scenarios(parameters);
    prog.current = 0;

    TPMI_DH_OBJECT primary_handle;
    log_info("Rng: Creating primary key...");
    TPM2_RC rc = create_primary_ECC_NIST_P256(sapi_context, &primary_handle);
    if (rc != TPM2_RC_SUCCESS) {
        log_error("Rng: Failed to create primary key!");
        return;
    } else {
        log_info("Rng: Created primary key with handle %08x", primary_handle);
    }

    if (command_in_options("getrandom")) {
        scenario.command_code = TPM2_CC_GetRandom;
        scenario.bytes_number = 32;
        run_rng_getrandom(sapi_context, &scenario, &prog);
        scenario.bytes_number = 64;
        run_rng_getrandom(sapi_context, &scenario, &prog);
    }

    Tss2_Sys_FlushContext(sapi_context, primary_handle);
}
