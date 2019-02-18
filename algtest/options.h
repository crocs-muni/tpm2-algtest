#pragma once

struct tpm_algtest_options {
    unsigned repetitions;
    unsigned max_duration_s;
    char* scenario;
    char* command;
    char* type;
    char* algorithm;
    unsigned keylen;
    unsigned verbose;
};
