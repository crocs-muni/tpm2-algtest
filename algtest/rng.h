#pragma once
#include "scenario.h"
#include "options.h"

#include <tss2/tss2_sys.h>


struct rng_scenario {
    struct scenario_parameters parameters;
    TPM2_CC command_code;
    uint16_t bytes_number;
};


struct rng_data_point {
    uint8_t data[sizeof(TPMU_HA)];
    uint16_t bytes_number;

    double duration_s;
    TPM2_RC rc;
};


struct rng_result {
    int size;
    struct rng_data_point *data_points;
};

void run_rng_scenarios(
        TSS2_SYS_CONTEXT *sapi_context,
        const struct scenario_parameters *parameters);
