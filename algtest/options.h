#pragma once
#include <stdbool.h>

struct tpm_algtest_options {
    unsigned repetitions;
    unsigned max_duration_s;
    bool export_public;
    bool export_private;
    char* scenario;
    char* command;
    char* type;
    char* algorithm;
    unsigned keylen;
    unsigned curveid;
    unsigned verbose;
};
