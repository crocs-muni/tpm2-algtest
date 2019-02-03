#pragma once
#include <tss2/tss2_sys.h>

struct create_params {
    TPMS_AUTH_COMMAND sessionData;
    TSS2L_SYS_AUTH_COMMAND cmdAuthsArray;
    TPM2B_SENSITIVE_CREATE inSensitive;
    TPM2B_PUBLIC inPublic;
    TPM2B_DATA outsideInfo;
    TPML_PCR_SELECTION creationPCR;
};

TPMI_DH_OBJECT create_RSA_parent(TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT *parentHandle);

void prepare_create_params(struct create_params *params);
TPM2_RC test_parms(TSS2_SYS_CONTEXT *sapi_context, struct create_params *params);

void test_Create(TSS2_SYS_CONTEXT *sapi_context);
