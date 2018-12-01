#pragma once
#include <tss2/tss2_sys.h>

#include <time.h>
#include <stdio.h>

const int max_num_handles;
const int max_num_error_codes;
const int handles_string_size;
const int error_codes_string_size;

double get_duration_sec(struct timespec *start, struct timespec *end);
double mean(double values[], int num_values);
void update_error_codes(TPM2_RC rc, TPM2_RC error_codes[], int *num_error_codes);
void update_handles(TPM2_HANDLE handle, TPM2_HANDLE handles[], int *num_handles);
void fill_handles_string(char handles_string[], TPM2_HANDLE handles[],
        int num_handles);
void fill_error_codes_string(char erorr_codes_string[], TPM2_RC error_codes[],
        int num_error_codes);
FILE *open_csv(char filename[], char header[], char mode[]);
