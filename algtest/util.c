#include "util.h"

#include <time.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

void init_summary(struct summary *summary)
{
    summary->measurements.count = 0;
    summary->seen_handles.count = 0;
    summary->seen_error_codes.count = 0;
}

double get_duration_s(struct timespec *start, struct timespec *end)
{
    return (end->tv_sec - start->tv_sec)
         + (end->tv_nsec - start->tv_nsec) / (double) (1000 * 1000 * 1000);
}

double mean(double values[], int num_values)
{
    double sum = 0.0;
    for (int i = 0; i < num_values; ++i) {
        sum += values[i];
    }
    return sum / num_values;
}

double measurements_mean(struct measurements *measurements)
{
    return mean(measurements->values, measurements->count);
}

void update_error_codes(TPM2_RC rc, struct rc_array *seen_error_codes)
{
    assert(seen_error_codes->count <= MAX_NUM_RETURN_CODES);
    if (seen_error_codes->count == MAX_NUM_RETURN_CODES)
        return;
    for (int i = 0; i < seen_error_codes->count; ++i) {
        if (seen_error_codes->values[i] == rc)
            return;
    }
    seen_error_codes->values[seen_error_codes->count++] = rc;
}

void update_handles(TPM2_HANDLE handle, struct handle_array *seen_handles)
{
    assert(seen_handles->count <= MAX_NUM_HANDLES);
    if (seen_handles->count == MAX_NUM_HANDLES)
        return;
    for (int i = 0; i < seen_handles->count; ++i) {
        if (seen_handles->values[i] == handle)
            return;
    }
    seen_handles->values[seen_handles->count++] = handle;
}

void add_measurement(double new_measurement, struct measurements *measurements)
{
    assert(measurements->count <= MAX_NUM_MEASUREMENTS);
    if (measurements->count == MAX_NUM_MEASUREMENTS)
        return;
    measurements->values[measurements->count++] = new_measurement;
}

void fill_handles_string(char *handles_string, struct handle_array *handles)
{
    handles_string[0] = '\0';
    for (int i = 0; i < handles->count; ++i) {
        char handle_string[10];
        snprintf(handle_string, 10, "%08x", handles->values[i]);
        if (i != handles->count - 1) {
            strcat(handle_string, ",");
        }
        strcat(handles_string, handle_string);
    }
}

void fill_error_codes_string(char *error_codes_string, struct rc_array *error_codes)
{
    error_codes_string[0] = '\0';
    for (int i = 0; i < error_codes->count; ++i) {
        char error_code_string[10];
        snprintf(error_code_string, 10, "%04x", error_codes->values[i]);
        if (i != error_codes->count - 1) {
            strcat(error_code_string, ",");
        }
        strcat(error_codes_string, error_code_string);
    }
}

FILE *open_csv(const char *filename, const char *header)
{
    struct stat sb;
    if (stat("out", &sb) == -1) {
        umask(0000);
        mkdir("out", 0777);
    }

    char path[256] = "out/";
    FILE *file = fopen(strncat(path, filename, 251), "w"); // 256 - csv/ - nul
    if (!file) {
        perror(strerror(errno));
        exit(1);
    }
    fprintf(file, "%s\n", header);
    return file;
}

void print_summary_to_file(FILE *out, char *param_fields, struct summary *summary)
{
    char handles_string[summary->seen_handles.count * 11 + 1];
    fill_handles_string(handles_string, &summary->seen_handles);
    char error_codes_string[summary->seen_error_codes.count * 5 + 1];
    fill_error_codes_string(error_codes_string, &summary->seen_error_codes);
    fprintf(out, "%s; %f; %s; %s\n", param_fields,
            measurements_mean(&summary->measurements),
            error_codes_string, handles_string);
}

