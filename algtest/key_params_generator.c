#include "options.h"
#include "logging.h"
#include "key_params_generator.h"

extern struct tpm_algtest_options options;

bool get_next_rsa_keylen(TPMI_RSA_KEY_BITS *keylen)
{
    while (*keylen <= 4096) {
        *keylen += 32;
        if (keylen_in_options(*keylen)) {
            return true;
        }
    }
    return false;
}

bool get_next_ecc_curve(TPMI_ECC_CURVE *curve)
{
    while (*curve <= 0x0020) {
        ++(*curve);
        if (curve_in_options(*curve)) {
            return true;
        }
    }
    return false;
}

bool get_next_key_type(TPMT_PUBLIC_PARMS *key_params)
{
    switch (key_params->type) {
    case TPM2_ALG_NULL:
        key_params->type = TPM2_ALG_RSA;
        if (type_in_options("rsa")) {
            key_params->parameters.rsaDetail = (TPMS_RSA_PARMS) {
                .symmetric = TPM2_ALG_NULL,
                .scheme = TPM2_ALG_NULL,
                .keyBits = 0,
                .exponent = 0
            };
            return true;
        }
    case TPM2_ALG_RSA:
        key_params->type = TPM2_ALG_ECC;
        if (type_in_options("ecc")) {
            key_params->parameters.eccDetail = (TPMS_ECC_PARMS) {
                .symmetric = TPM2_ALG_NULL,
                .scheme = TPM2_ALG_NULL,
                .curveID = 0x0000,
                .kdf = TPM2_ALG_NULL
            };
            return true;
        }
    case TPM2_ALG_ECC:
        return false;
    default:
        return false;
    }
}

bool get_next_key_params(TPMT_PUBLIC_PARMS *key_params)
{
    switch (key_params->type) {
    case TPM2_ALG_NULL:
        return get_next_key_type(key_params);
    case TPM2_ALG_RSA:
        if (get_next_rsa_keylen(&key_params->parameters.rsaDetail.keyBits)) {
            return true;
        } else {
            return get_next_key_type(key_params);
        }
    case TPM2_ALG_ECC:
        if (get_next_ecc_curve(&key_params->parameters.eccDetail.curveID)) {
            return true;
        } else {
            return get_next_key_type(key_params);
        }
    default:
        return false;
    }
}

bool get_next_rsa_scheme(TPMT_SIG_SCHEME *scheme)
{
    switch (scheme->scheme) {
    case TPM2_ALG_NULL:
        scheme->scheme = TPM2_ALG_RSASSA;
        scheme->details = (TPMU_SIG_SCHEME) { .rsassa = { .hashAlg = TPM2_ALG_SHA256 } };
        return true;
    case TPM2_ALG_RSASSA:
        scheme->scheme = TPM2_ALG_RSAPSS;
        scheme->details = (TPMU_SIG_SCHEME) { .rsapss = { .hashAlg = TPM2_ALG_SHA256 } };
        return true;
    default:
        return false;
    }
}

bool get_next_ecc_scheme(TPMT_SIG_SCHEME *scheme)
{
    switch (scheme->scheme) {
    case TPM2_ALG_NULL:
        scheme->scheme = TPM2_ALG_ECDSA;
        scheme->details = (TPMU_SIG_SCHEME) { .ecdsa = { .hashAlg = TPM2_ALG_SHA256 } };
        return true;
    case TPM2_ALG_ECDSA:
        scheme->scheme = TPM2_ALG_SM2;
        scheme->details = (TPMU_SIG_SCHEME) { .sm2 = { .hashAlg = TPM2_ALG_SHA256 } };
        return true;
    case TPM2_ALG_SM2:
        scheme->scheme = TPM2_ALG_ECSCHNORR;
        scheme->details = (TPMU_SIG_SCHEME) { .ecschnorr = { .hashAlg = TPM2_ALG_SHA256 } };
        return true;
    default:
        return false;
    }
}

bool get_next_sign_scheme(TPMT_SIG_SCHEME *scheme, TPM2_ALG_ID type)
{
    switch (type) {
    case TPM2_ALG_RSA:
        return get_next_rsa_scheme(scheme);
    case TPM2_ALG_ECC:
        return get_next_ecc_scheme(scheme);
    default:
        log_error("get_next_sign_scheme: Invalid algorithm type");
        return false;
    }
}
