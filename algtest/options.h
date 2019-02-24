#pragma once
#include <stdbool.h>

struct tpm_algtest_options {
    int repetitions;
    int max_duration_s;
    bool export_keys;
    char* scenario;
    char* command;
    char* type;
    char* algorithm;
    int keylen;
    int curveid;
    int verbose;
};
