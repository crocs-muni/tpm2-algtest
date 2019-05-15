#pragma once
#include <tss2/tss2_sys.h>

TPM2_RC sign(
        TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT keyHandle,
        const TPMT_SIG_SCHEME *inScheme,
        const TPM2B_DIGEST *digest,
        TPMT_SIGNATURE *signature,
        double *duration);

TPM2_RC verifysignature(
        TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT keyHandle,
        const TPM2B_DIGEST *digest,
        const TPMT_SIGNATURE *signature,
        double *duration);

TPM2_RC rsa_encrypt(
        TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT keyHandle,
        const TPM2B_PUBLIC_KEY_RSA *message,
        const TPMT_RSA_DECRYPT *inScheme,
        TPM2B_PUBLIC_KEY_RSA *outData,
        double *duration);

TPM2_RC rsa_decrypt(
        TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT keyHandle,
        const TPM2B_PUBLIC_KEY_RSA *cipherText,
        const TPMT_RSA_DECRYPT *inScheme,
        TPM2B_PUBLIC_KEY_RSA *message,
        double *duration);

TPM2_RC getrandom(
        TSS2_SYS_CONTEXT *sapi_context,
        double *duration);

TPM2_RC encryptdecrypt(
        TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT keyHandle,
        const TPM2B_IV *inIv,
        const TPM2B_MAX_BUFFER *inData,
        double *duration);
