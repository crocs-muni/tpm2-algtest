#pragma once
#include <tss2/tss2_sys.h>

#include <time.h>
#include <stdio.h>

#define MAX_NUM_MEASUREMENTS 100
struct measurements {
    unsigned count;
    double values[MAX_NUM_MEASUREMENTS];
};

#define MAX_NUM_HANDLES 32
struct handle_array {
    unsigned count;
    TPM2_HANDLE values[MAX_NUM_HANDLES];
};

#define MAX_NUM_RETURN_CODES 10
struct rc_array {
    unsigned count;
    TPM2_RC values[MAX_NUM_RETURN_CODES];
};

// TODO: rename
struct summary {
    struct measurements measurements;
    struct rc_array seen_error_codes;
    struct handle_array seen_handles;
};

void init_summary(struct summary *summary);

double get_duration_sec(struct timespec *start, struct timespec *end);
double mean(double values[], int num_values);
double measurements_mean(struct measurements *measurements);
void update_error_codes(TPM2_RC rc, struct rc_array *seen_error_codes);
void update_handles(TPM2_HANDLE handle, struct handle_array *seen_handles);
void add_measurement(double measurement, struct measurements *measurements);
void fill_handles_string(char *handles_string, struct handle_array *handles);
void fill_error_codes_string(char *error_codes_string, struct rc_array *error_codes);
FILE *open_csv(const char *filename, const char *header, const char *mode);


void print_summary_to_file(FILE *out, char *param_fields, struct summary *summary);

