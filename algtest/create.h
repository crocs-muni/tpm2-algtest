#pragma once
#include <tss2/tss2_sys.h>
#include <stdbool.h>

struct create_params {
    TPMS_AUTH_COMMAND sessionData;
    TSS2L_SYS_AUTH_COMMAND cmdAuthsArray;
    TPM2B_SENSITIVE_CREATE inSensitive;
    TPM2B_PUBLIC inPublic;
    TPM2B_DATA outsideInfo;
    TPML_PCR_SELECTION creationPCR;
};

void prepare_create_params(struct create_params *params);
bool test_parms(TSS2_SYS_CONTEXT *sapi_context, struct create_params *params);

void test_Create(TSS2_SYS_CONTEXT *sapi_context);
