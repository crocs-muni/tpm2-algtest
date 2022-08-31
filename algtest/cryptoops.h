#pragma once
#include "scenario.h"
#include "options.h"

#include <tss2/tss2_sys.h>


struct cryptoops_nonce_scenario {
    bool no_export;
    TPMT_PUBLIC_PARMS key_params;
    TPMT_SIG_SCHEME scheme;
    TPM2B_DIGEST digest;
};

struct cryptoops_scenario {
    struct scenario_parameters parameters;
    TPM2_CC command_code;
    union {
        struct cryptoops_nonce_scenario nonce;
    };
};

struct nonce_keypair {
    TPMU_PUBLIC_ID public_key;
    TPMU_SENSITIVE_COMPOSITE private_key;
};

struct cryptoops_nonce_data_point {
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
};

struct cryptoops_data_point {
    double duration_s;
    TPM2_RC rc;
    union {
        struct cryptoops_nonce_data_point nonce;
    };
};

struct cryptoops_result {
    int size;
    struct cryptoops_data_point *data_points;
};

void run_cryptoops_scenarios(
        TSS2_SYS_CONTEXT *sapi_context,
        const struct scenario_parameters *parameters);
