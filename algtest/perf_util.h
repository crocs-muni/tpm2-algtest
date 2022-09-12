#pragma once
#include <tss2/tss2_sys.h>

TPM2_RC sign(
        TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT keyHandle,
        const TPMT_SIG_SCHEME *inScheme,
        const TPM2B_DIGEST *digest,
        TPMT_SIGNATURE *signature,
        TPM2B_ECC_POINT *noncePoint,
        double *duration,
        double *duration_extra);

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
        TPMI_YES_NO decrypt,
        const TPM2B_IV *inIv,
        const TPM2B_MAX_BUFFER *inData,
        double *duration);

TPM2_RC hmac(
        TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT handle,
        const TPM2B_MAX_BUFFER *buffer,
        TPMI_ALG_HASH hashAlg,
        double *duration);

TPM2_RC hash(
        TSS2_SYS_CONTEXT *sapi_context,
        const TPM2B_MAX_BUFFER *data,
        TPMI_ALG_HASH hashAlg,
        double *duration);

TPM2_RC ec_ephemeral(
        TSS2_SYS_CONTEXT *sapi_context,
        TPMI_ECC_CURVE curveID,
        TPM2B_ECC_POINT *outPoint,
        UINT16 *counter,
        double *duration);

TPM2_RC zgen_2phase(
        TSS2_SYS_CONTEXT *sapi_context,
        TPMI_DH_OBJECT keyHandle,
        const TPM2B_ECC_POINT *inQsB,
        const TPM2B_ECC_POINT *inQeB,
        TPMI_ECC_KEY_EXCHANGE inScheme,
        UINT16 counter,
        TPM2B_ECC_POINT *outZ1,
        TPM2B_ECC_POINT *outZ2,
        double *duration);
