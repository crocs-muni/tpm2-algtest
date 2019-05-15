#pragma once
#include "scenario.h"
#include "options.h"

#include <tss2/tss2_sys.h>

struct perf_sign_scenario {
    TPMT_PUBLIC_PARMS key_params;
    TPMT_SIG_SCHEME scheme;
    TPM2B_DIGEST digest;
};

struct perf_verifysignature_scenario {
    TPMT_PUBLIC_PARMS key_params;
    TPMT_SIG_SCHEME scheme;
    TPM2B_DIGEST digest;
};

struct perf_rsa_encrypt_scenario {
    TPMI_RSA_KEY_BITS keylen;
    TPMT_RSA_DECRYPT scheme;
    TPM2B_PUBLIC_KEY_RSA message;
};

struct perf_rsa_decrypt_scenario {
    TPMI_RSA_KEY_BITS keylen;
    TPMT_RSA_DECRYPT scheme;
    TPM2B_PUBLIC_KEY_RSA message;
};

struct perf_encryptdecrypt_scenario {
    TPMT_SYM_DEF_OBJECT sym;
    TPMI_YES_NO decrypt;
};

struct perf_scenario {
    struct scenario_parameters parameters;
    TPM2_CC command_code;
    union {
        struct perf_sign_scenario sign;
        struct perf_verifysignature_scenario verifysignature;
        struct perf_rsa_encrypt_scenario rsa_encrypt;
        struct perf_rsa_decrypt_scenario rsa_decrypt;
        struct perf_encryptdecrypt_scenario encryptdecrypt;
    };
};


struct perf_data_point {
    double duration_s;
    TPM2_RC rc;
};

struct perf_result {
    int size;
    struct perf_data_point *data_points;
};


void run_perf_scenarios(
        TSS2_SYS_CONTEXT *sapi_context,
        const struct scenario_parameters *parameters);
