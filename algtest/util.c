#include "util.h"

#include <time.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

const int max_num_handles = 32;
const int max_num_error_codes = 10;

const int handles_string_size = max_num_handles * 11 + 1;
const int error_codes_string_size = max_num_error_codes * 5 + 1;

double get_duration_sec(struct timespec *start, struct timespec *end)
{
    return (end->tv_sec - start->tv_sec)
         + (double)(end->tv_nsec - start->tv_nsec)
         / 1000000000;
}

double mean(double values[], int num_values)
{
    double sum = 0.0;
    for (int i = 0; i < num_values; ++i) {
        sum += values[i];
    }
    return sum / num_values;
}

void update_error_codes(TPM2_RC rc, TPM2_RC error_codes[], int *num_error_codes)
{
    assert(*num_error_codes <= max_num_error_codes);
    if (*num_error_codes == max_num_error_codes)
        return;
    for (int i = 0; i < *num_error_codes; ++i) {
        if (error_codes[i] == rc)
            return;
    }
    error_codes[(*num_error_codes)++] = rc;
}

void update_handles(TPM2_HANDLE handle, TPM2_HANDLE handles[], int *num_handles)
{
    assert(*num_handles <= max_num_handles);
    if (*num_handles == max_num_handles)
        return;
    for (int i = 0; i < *num_handles; ++i) {
        if (handles[i] == handle)
            return;
    }
    handles[(*num_handles)++] = handle;
}

void fill_handles_string(char handles_string[], TPM2_HANDLE handles[],
        int num_handles)
{
    handles_string[0] = '\0';
    for (int i = 0; i < num_handles; ++i) {
        char handle_string[10];
        snprintf(handle_string, 10, "%08x", handles[i]);
        if (i != num_handles - 1) {
            strcat(handle_string, ",");
        }
        strcat(handles_string, handle_string);
    }
}

void fill_error_codes_string(char error_codes_string[], TPM2_RC error_codes[],
        int num_error_codes)
{
    error_codes_string[0] = '\0';
    for (int i = 0; i < num_error_codes; ++i) {
        char error_code_string[10];
        snprintf(error_code_string, 10, "%04x", error_codes[i]);
        if (i != num_error_codes - 1) {
            strcat(error_code_string, ",");
        }
        strcat(error_codes_string, error_code_string);
    }
}

FILE *open_csv(char filename[], char header[], char mode[])
{
    FILE *file = fopen(filename, mode);
    if (!file) {
        perror(strerror(errno));
        exit(1);
    }
    fprintf(file, "%s\n", header);
    return file;
}

