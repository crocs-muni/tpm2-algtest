#pragma once
#include <tss2/tss2_sys.h>
#include "create.h"

TPM2_RC test_parms(
        TSS2_SYS_CONTEXT *sapi_context,
        const TPMT_PUBLIC *publicArea);

TPM2B_PUBLIC prepare_template_RSA_primary(TPMI_RSA_KEY_BITS keyBits);
TPM2B_PUBLIC prepare_template_SYMCIPHER_primary();

TPM2B_PUBLIC prepare_template_RSA(TPMI_RSA_KEY_BITS keyBits);
TPM2B_PUBLIC prepare_template_ECC(TPMI_ECC_CURVE curveID);

TPM2B_PUBLIC prepare_template(const TPMT_PUBLIC_PARMS *parameters);

TSS2L_SYS_AUTH_COMMAND prepare_session();

TPM2_RC create_primary(
        TSS2_SYS_CONTEXT *sapi_context,
        const TPM2B_PUBLIC *inPublic,
        TPMI_DH_OBJECT *parent_handle);

TPM2_RC create_some_primary(TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT *primary_handle);

TPM2_RC create(
        TSS2_SYS_CONTEXT *sapi_context,
        const TPM2B_PUBLIC *inPublic,
        TPMI_DH_OBJECT primary_handle,
        TPM2B_PUBLIC *outPublic,
        TPM2B_PRIVATE *outPrivate,
        double *duration);

TPM2_RC load(
        TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT parentHandle,
        const TPM2B_PRIVATE *inPrivate,
        const TPM2B_PUBLIC *inPublic,
        TPM2_HANDLE *objectHandle);

TPM2_RC create_loaded(
        TSS2_SYS_CONTEXT *sapi_context,
        const TPM2B_PUBLIC *inPublic,
        TPMI_DH_OBJECT primary_handle,
        TPM2_HANDLE *objectHandle);

TPM2_RC extract_sensitive(
        TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT objectHandle,
        TPMU_SENSITIVE_COMPOSITE *sensitive);

TPM2B_DIGEST get_dup_policy(TSS2_SYS_CONTEXT *sapi_context);
