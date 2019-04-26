#pragma once
#include <tss2/tss2_sys.h>
#include <stdbool.h>

struct tpm_algtest_options {
    int repetitions;
    int max_duration_s;
    bool no_export;
    char* scenario;
    char* command;
    char* type;
    char* algorithm;
    int keylen;
    int curveid;
    int verbose;
    char* outdir;
};

bool scenario_in_options(const char* scenario);

bool command_in_options(const char* command);

bool type_in_options(const char* type);

bool keylen_in_options(TPMI_RSA_KEY_BITS keylen);

bool curve_in_options(TPM2_ECC_CURVE curveID);
