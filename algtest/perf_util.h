#pragma once
#include <tss2/tss2_sys.h>

TPM2_RC sign(
        TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT keyHandle,
        const TPM2B_DIGEST *digest,
        TPMT_SIGNATURE *signature,
        double *duration);

TPM2_RC verifysignature(
        TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT keyHandle,
        const TPM2B_DIGEST *digest,
        const TPMT_SIGNATURE *signature,
        double *duration);
