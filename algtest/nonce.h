#pragma once
#include "scenario.h"
#include "options.h"

#include <tss2/tss2_sys.h>

struct nonce_sign_scenario {
    TPMT_PUBLIC_PARMS key_params;
    TPMT_SIG_SCHEME scheme;
    TPM2B_DIGEST digest;
};


struct nonce_scenario {
    struct scenario_parameters parameters;
    TPM2_CC command_code;
    bool no_export;
    union {
        struct nonce_sign_scenario sign;
    };
};


struct nonce_keypair {
    TPMU_PUBLIC_ID public_key;
    TPMU_SENSITIVE_COMPOSITE private_key;
};


struct nonce_data_point {
    TPMI_ALG_SIG_SCHEME algorithm_id;
    TPMI_ECC_CURVE curve_id;
    uint16_t digest_size;
    uint8_t digest[sizeof(TPMU_HA)];
    uint16_t signature_r_size;
    uint8_t signature_r[TPM2_MAX_ECC_KEY_BYTES];
    uint16_t signature_s_size;
    uint8_t signature_s[TPM2_MAX_ECC_KEY_BYTES];
    uint16_t private_key_size;
    uint8_t private_key[TPM2_MAX_ECC_KEY_BYTES];
    uint16_t public_key_x_size;
    uint8_t public_key_x[TPM2_MAX_ECC_KEY_BYTES];
    uint16_t public_key_y_size;
    uint8_t public_key_y[TPM2_MAX_ECC_KEY_BYTES];

    double duration_s;
    TPM2_RC rc;
};


struct nonce_result {
    int size;
    struct nonce_data_point *data_points;
};

void run_nonce_scenarios(
        TSS2_SYS_CONTEXT *sapi_context,
        const struct scenario_parameters *parameters);
