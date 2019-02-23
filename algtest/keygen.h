#pragma once
#include "scenario.h"

#include <tss2/tss2_sys.h>
#include <stdbool.h>

struct keygen_scenario {
    struct scenario_parameters parameters;
    TPM2_ALG_ID type;
    TPMI_RSA_KEY_BITS keyBits;
    TPM2_ECC_CURVE curveID;
    bool export_public;
    bool export_private;
};

struct keygen_data_point {
    double duration_s;
    TPM2_RC rc;
};

struct keygen_result {
    unsigned size;
    struct keygen_data_point *data_points;
    TPMU_PUBLIC_ID *public_keys;
};

bool test_keygen(TSS2_SYS_CONTEXT *sapi_context,
        const struct keygen_scenario *scenario);

void test_keygen_all(TSS2_SYS_CONTEXT *sapi_context,
        const struct scenario_parameters *parameters);
