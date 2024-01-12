/* SPDX-License-Identifier: BSD-2-Clause */
#pragma once
#include "scenario.h"

#include <tss2/tss2_sys.h>
#include <stdbool.h>

struct keygen_scenario {
    struct scenario_parameters parameters;
    TPMT_PUBLIC_PARMS key_params;
    bool no_export;
};

struct keygen_data_point {
    double duration_s;
    TPM2_RC rc;
};

struct keygen_keypair {
    TPMU_PUBLIC_ID public_key;
    TPMU_SENSITIVE_COMPOSITE private_key;
};

struct keygen_result {
    int size;
    struct keygen_data_point *data_points;
    struct keygen_keypair *keypairs;
};

void run_keygen(
        TSS2_SYS_CONTEXT *sapi_context,
        const struct keygen_scenario *scenario);

void run_keygen_scenarios(
        TSS2_SYS_CONTEXT *sapi_context,
        const struct scenario_parameters *parameters);
