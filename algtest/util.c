#include "util.h"

#include <time.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

void init_summary(struct summary *summary)
{
    summary->measurements.count = 0;
    summary->seen_handles.count = 0;
    summary->seen_error_codes.count = 0;
}

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

FILE *open_csv(char *filename, char *header, char *mode)
{
    FILE *file = fopen(filename, mode);
    if (!file) {
        perror(strerror(errno));
        exit(1);
    }
    fprintf(file, "%s\n", header);
    return file;
}

bool test_parms(TSS2_SYS_CONTEXT *sapi_context, struct create_params *params)
{
    TPMT_PUBLIC_PARMS parameters = {
        .type = params->inPublic.publicArea.type,
        .parameters = params->inPublic.publicArea.parameters
    };
    TPM2_RC rc = Tss2_Sys_TestParms(sapi_context, NULL, &parameters, NULL);
    return rc == TPM2_RC_SUCCESS;
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

void prepare_create_primary_params(struct create_params *params)
{
    /* Create password session, w/ 0-length password */
    TPMS_AUTH_COMMAND sessionData = {
        .sessionHandle = TPM2_RS_PW,                // TPMI_SH_AUTH_SESSION
        .nonce = { .size = 0, /* .buffer */ },      // TPM2B_NONCE
        .sessionAttributes = TPMA_SESSION_CONTINUESESSION, // TPMA_SESSION
        .hmac = { .size = 0, /* .buffer */ }        // TPM2B_AUTH
    };
    params->sessionData = sessionData;

    TSS2L_SYS_AUTH_COMMAND cmdAuthsArray = {
        .count = 1,
        .auths = { sessionData }
    };
    params->cmdAuthsArray = cmdAuthsArray;

    /* No key authorization */
    TPM2B_SENSITIVE_CREATE inSensitive = {
        .size = 0,
        .sensitive = {                              // TPMS_SENSITIVE_CREATE
            .userAuth = { .size = 0, /* buffer */ },    // TPM2B_AUTH
            .data = { .size = 0, /* buffer */ },        // TPM2B_SENSITIVE_DATA
        }
    };
    params->inSensitive = inSensitive;
    params->outsideInfo.size = 0;
    params->creationPCR.count = 0;

    TPM2B_PUBLIC inPublic = {
        .size = 0, // doesn't need to be set
        .publicArea = {                         // TPMT_PUBLIC
            .nameAlg = TPM2_ALG_SHA256,             // TPMI_ALG_HASH
            .objectAttributes =                     // TPMA_OBJECT
                TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT
                | TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT
                | TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH,
            .authPolicy = { .size = 0, /* buffer */ }, // TPM2B_DIGEST
        }
    };
    params->inPublic = inPublic;
}

void prepare_create_params(struct create_params *params)
{
    /* Create password session, w/ 0-length password */
    TPMS_AUTH_COMMAND sessionData = {
        .sessionHandle = TPM2_RS_PW,                // TPMI_SH_AUTH_SESSION
        .nonce = { .size = 0, /* .buffer */ },      // TPM2B_NONCE
        .sessionAttributes = TPMA_SESSION_CONTINUESESSION, // TPMA_SESSION
        .hmac = { .size = 0, /* .buffer */ }        // TPM2B_AUTH
    };
    params->sessionData = sessionData;

    TSS2L_SYS_AUTH_COMMAND cmdAuthsArray = {
        .count = 1,
        .auths = { sessionData }
    };
    params->cmdAuthsArray = cmdAuthsArray;

    /* No key authorization */
    TPM2B_SENSITIVE_CREATE inSensitive = {
        .size = 0,
        .sensitive = {                              // TPMS_SENSITIVE_CREATE
            .userAuth = { .size = 0, /* buffer */ },    // TPM2B_AUTH
            .data = { .size = 0, /* buffer */ },        // TPM2B_SENSITIVE_DATA
        }
    };
    params->inSensitive = inSensitive;
    params->outsideInfo.size = 0;
    params->creationPCR.count = 0;

    TPM2B_PUBLIC inPublic = {
        .size = 0, // doesn't need to be set
        .publicArea = {                         // TPMT_PUBLIC
            .nameAlg = TPM2_ALG_SHA256,             // TPMI_ALG_HASH
            .objectAttributes =                     // TPMA_OBJECT
                TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_DECRYPT
                | TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT
                | TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH,
            .authPolicy = { .size = 0, /* buffer */ }, // TPM2B_DIGEST
        }
    };
    params->inPublic = inPublic;
}
