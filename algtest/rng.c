/* SPDX-License-Identifier: BSD-2-Clause */
#include "rng.h"
#include "object_util.h"
#include "logging.h"
#include "util.h"
#include "status.h"

#include <string.h>
#include <stdlib.h>
#include <time.h>

static
void output_result(
        const struct rng_scenario *scenario,
        const uint8_t *result)
{
    FILE *out = open_bin("Rng.bin");
    if(!out) {
        log_error("Rng: cannot open output file.");
        return;
    }
    fwrite(result, scenario->bytes_number, scenario->parameters.repetitions, out);
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
    uint8_t* result = (uint8_t*) calloc(scenario->bytes_number, scenario->parameters.repetitions);
    if (!result) {
        log_error("Rng: cannot allocate memory for result.");
        return;
    }
    int failures = 0;
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (unsigned i = 0; i < scenario->parameters.repetitions; ++i) {
        clock_gettime(CLOCK_MONOTONIC, &end);
        if (get_duration_s(&start, &end) > scenario->parameters.max_duration_s) {
            log_error("Rng: Max duration reached. Skipping remaining iterations.");
            skip_progress(prog, scenario->parameters.repetitions - i);
            break;
        }

        double duration;
        TPM2B_DIGEST buffer = { .size = 0 };
        TPM2_RC rc = getrandom_bytes(sapi_context, &buffer, scenario->bytes_number, &duration);

        if (rc == TPM2_RC_SUCCESS) {
            if (buffer.size != scenario->bytes_number) {
                log_error("Rng: requested %d B | received %d B", scenario->bytes_number, buffer.size);
            }
            memcpy(result + i * scenario->bytes_number, buffer.buffer, buffer.size);
        } else {
            ++failures;
        }

        log_info("Rng %d: duration %.9f | rc %04x", i, duration, rc);
        printf("%lu%%\n", increase_progress(prog));

        if(failures >= FAILURE_LIMIT) {
            log_error("Rng: Too many failures. Skipping remaining iterations.");
            skip_progress(prog, scenario->parameters.repetitions - i - 1);
            free(result);
            return;
        }
    }

    output_result(scenario, result);
    free(result);
}

unsigned long count_supported_rng_scenarios(const struct scenario_parameters *parameters)
{
    if (command_in_options("getrandom")) {
        return parameters->repetitions;
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
    }

    Tss2_Sys_FlushContext(sapi_context, primary_handle);
}
