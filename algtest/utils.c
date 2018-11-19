#include "utils.h"

#include <time.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

const int maxNumHandles = 32;
const int maxNumErrorCodes = 10;

const int handlesStringSize = maxNumHandles * 11 + 1;
const int errorCodesStringSize = maxNumErrorCodes * 5 + 1;

double get_duration_sec(struct timespec *start, struct timespec *end)
{
    return (end->tv_sec - start->tv_sec)
         + (double)(end->tv_nsec - start->tv_nsec)
         / 1000000000;
}

double mean(double values[], int numValues)
{
    double sum = 0.0;
    for (int i = 0; i < numValues; ++i) {
        sum += values[i];
    }
    return sum / numValues;
}

void updateErrorCodes(TPM2_RC rc, TPM2_RC errorCodes[], int *numErrorCodes)
{
    assert(*numErrorCodes <= maxNumErrorCodes);
    if (*numErrorCodes == maxNumErrorCodes)
        return;
    for (int i = 0; i < *numErrorCodes; ++i) {
        if (errorCodes[i] == rc)
            return;
    }
    errorCodes[(*numErrorCodes)++] = rc;
}

void updateHandles(TPM2_HANDLE handle, TPM2_HANDLE handles[], int *numHandles)
{
    assert(*numHandles <= maxNumHandles);
    if (*numHandles == maxNumHandles)
        return;
    for (int i = 0; i < *numHandles; ++i) {
        if (handles[i] == handle)
            return;
    }
    handles[(*numHandles)++] = handle;
}

void fillHandlesString(char handlesString[], TPM2_HANDLE handles[],
        int numHandles)
{
    handlesString[0] = '\0';
    for (int i = 0; i < numHandles; ++i) {
        char handleString[10];
        snprintf(handleString, 10, "%08x", handles[i]);
        if (i != numHandles - 1) {
            strcat(handleString, ",");
        }
        strcat(handlesString, handleString);
    }
}

void fillErrorCodesString(char errorCodesString[], TPM2_RC errorCodes[],
        int numErrorCodes)
{
    errorCodesString[0] = '\0';
    for (int i = 0; i < numErrorCodes; ++i) {
        char errorCodeString[10];
        snprintf(errorCodeString, 10, "%04x", errorCodes[i]);
        if (i != numErrorCodes - 1) {
            strcat(errorCodeString, ",");
        }
        strcat(errorCodesString, errorCodeString);
    }
}

FILE *openCSV(char filename[], char header[], char mode[])
{
    FILE *file = fopen(filename, mode);
    if (!file) {
        perror(strerror(errno));
        exit(1);
    }
    fwrite(header, 1, strlen(header), file);
    return file;
}

