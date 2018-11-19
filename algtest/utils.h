#pragma once
#include <tss2/tss2_sys.h>

#include <time.h>
#include <stdio.h>

const int maxNumHandles;
const int maxNumErrorCodes;
const int handlesStringSize;
const int errorCodesStringSize;

double get_duration_sec(struct timespec *start, struct timespec *end);
double mean(double values[], int numValues);
void updateErrorCodes(TPM2_RC rc, TPM2_RC errorCodes[], int *numErrorCodes);
void updateHandles(TPM2_HANDLE handle, TPM2_HANDLE handles[], int *numHandles);
void fillHandlesString(char handlesString[], TPM2_HANDLE handles[],
        int numHandles);
void fillErrorCodesString(char errorCodesString[], TPM2_RC errorCodes[],
        int numErrorCodes);
FILE *openCSV(char filename[], char header[], char mode[]);
