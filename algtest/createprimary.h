#pragma once
#include "tpm2_util.h"

#include <tss2/tss2_sys.h>

struct createPrimaryParams {
    TPMI_RH_HIERARCHY primaryHandle;
    TPMS_AUTH_COMMAND sessionData;
    TSS2L_SYS_AUTH_COMMAND cmdAuthsArray;
    TPM2B_SENSITIVE_CREATE inSensitive;
    TPM2B_PUBLIC inPublic;
    TPM2B_DATA outsideInfo;
    TPML_PCR_SELECTION creationPCR;
};

void measure_CreatePrimary_RSA(TSS2_SYS_CONTEXT *sapi_context,
        struct createPrimaryParams params);

void measure_CreatePrimary(TSS2_SYS_CONTEXT *sapi_context);
