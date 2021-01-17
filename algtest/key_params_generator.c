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

bool get_next_sym_keylen(TPM2_KEY_BITS *keylen)
{
    while (*keylen <= 256) {
        *keylen += 32;
        if (keylen_in_options(*keylen)) {
            return true;
        }
    }
    return false;
}

bool get_next_ecc_curve(TPMI_ECC_CURVE *curve)
{
    while (*curve <= 0x0080) {
        ++(*curve);
        if (curve_in_options(*curve)) {
            return true;
        }
    }
    return false;
}

bool get_next_asym_key_type(TPMT_PUBLIC_PARMS *key_params)
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

bool get_next_sym_mode(TPMI_ALG_SYM_MODE *mode)
{
    switch (*mode) {
    case TPM2_ALG_NULL:
        *mode = TPM2_ALG_CTR; return true;
    case TPM2_ALG_CTR:
        *mode = TPM2_ALG_OFB; return true;
    case TPM2_ALG_OFB:
        *mode = TPM2_ALG_CBC; return true;
    case TPM2_ALG_CBC:
        *mode = TPM2_ALG_CFB; return true;
    case TPM2_ALG_CFB:
        *mode = TPM2_ALG_ECB; return true;
    default:
        return false;
    }
}

bool get_next_sym_key_type(TPMT_PUBLIC_PARMS *key_params)
{
    switch (key_params->type) {
    case TPM2_ALG_NULL:
        key_params->type = TPM2_ALG_KEYEDHASH;
        if (type_in_options("keyedhash")) {
            key_params->parameters.keyedHashDetail = (TPMS_KEYEDHASH_PARMS) {
                .scheme = {
                    .scheme = TPM2_ALG_HMAC,
                    .details = { .hmac = { .hashAlg = TPM2_ALG_SHA256 } },
                }
            };
            return true;
        }
    case TPM2_ALG_KEYEDHASH:
        key_params->type = TPM2_ALG_SYMCIPHER;
        if (type_in_options("symcipher")) {
            key_params->parameters.symDetail = (TPMS_SYMCIPHER_PARMS) {
                .sym = {
                    .algorithm = TPM2_ALG_NULL,
                    .keyBits = 0,
                    .mode = TPM2_ALG_NULL,
                }
            };
            return true;
        }
    default:
        return false;
    }
}

bool get_next_sym_algorithm(TPMT_SYM_DEF_OBJECT *sym)
{
    switch (sym->algorithm) {
    case TPM2_ALG_NULL:
        *sym = (TPMT_SYM_DEF_OBJECT) {
            .algorithm = TPM2_ALG_AES,
            .keyBits = 0,
            .mode = TPM2_ALG_NULL
        };
        return true;
    case TPM2_ALG_AES:
        *sym = (TPMT_SYM_DEF_OBJECT) {
            .algorithm = TPM2_ALG_CAMELLIA,
            .keyBits = 0,
            .mode = TPM2_ALG_NULL,
        };
        return true;
    case TPM2_ALG_CAMELLIA:
        *sym = (TPMT_SYM_DEF_OBJECT) {
            .algorithm = TPM2_ALG_SM4,
            .keyBits = 0,
            .mode = TPM2_ALG_NULL
        };
        return true;
    default:
        return false;
    }
}

bool get_next_symcipher(TPMT_SYM_DEF_OBJECT *sym)
{
    switch (sym->algorithm) {
    case TPM2_ALG_NULL:
        return get_next_sym_algorithm(sym);
    case TPM2_ALG_AES:
        if (get_next_sym_keylen(&sym->keyBits.sym)) {
            return true;
        } else {
            return get_next_sym_algorithm(sym);
        }
    case TPM2_ALG_CAMELLIA:
        if (get_next_sym_keylen(&sym->keyBits.sym)) {
            return true;
        } else {
            return get_next_sym_algorithm(sym);
        }
    case TPM2_ALG_SM4:
        if (get_next_sym_keylen(&sym->keyBits.sym)) {
            return true;
        } else {
            return get_next_sym_algorithm(sym);
        }
    default:
        return false;
    }
}

bool get_next_sym_key_params(TPMT_PUBLIC_PARMS *key_params)
{
    switch (key_params->type) {
    case TPM2_ALG_NULL:
        return get_next_sym_key_type(key_params);
    case TPM2_ALG_KEYEDHASH:
        return get_next_sym_key_type(key_params);
    case TPM2_ALG_SYMCIPHER:
        return get_next_symcipher(&key_params->parameters.symDetail.sym);
    default:
        return false;
    }
}

bool get_next_asym_key_params(TPMT_PUBLIC_PARMS *key_params)
{
    switch (key_params->type) {
    case TPM2_ALG_NULL:
        return get_next_asym_key_type(key_params);
    case TPM2_ALG_RSA:
        if (get_next_rsa_keylen(&key_params->parameters.rsaDetail.keyBits)) {
            return true;
        } else {
            return get_next_asym_key_type(key_params);
        }
    case TPM2_ALG_ECC:
        if (get_next_ecc_curve(&key_params->parameters.eccDetail.curveID)) {
            return true;
        } else {
            return get_next_asym_key_type(key_params);
        }
    default:
        return false;
    }
}

bool get_next_key_params(TPMT_PUBLIC_PARMS *key_params)
{
    switch (key_params->type) {
    case TPM2_ALG_NULL:
    case TPM2_ALG_RSA:
    case TPM2_ALG_ECC:
        if (get_next_asym_key_params(key_params)) {
            return true;
        } else {
            key_params->type = TPM2_ALG_NULL;
            return get_next_sym_key_params(key_params);
        }
    case TPM2_ALG_KEYEDHASH:
    case TPM2_ALG_SYMCIPHER:
        return get_next_sym_key_params(key_params);
    default:
        return false;
    }
}

bool get_next_rsa_enc_scheme(TPMT_RSA_DECRYPT *scheme)
{
    switch (scheme->scheme) {
    case TPM2_ALG_NULL:
        scheme->scheme = TPM2_ALG_RSAES;
        return true;
    case TPM2_ALG_RSAES:
        scheme->scheme = TPM2_ALG_OAEP;
        scheme->details = (TPMU_ASYM_SCHEME) { .oaep = { .hashAlg = TPM2_ALG_SHA1 } };
        return true;
    default:
        return false;
    }
}

bool get_next_rsa_sign_scheme(TPMT_SIG_SCHEME *scheme)
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

bool get_next_ecc_sign_scheme(TPMT_SIG_SCHEME *scheme)
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
        return get_next_rsa_sign_scheme(scheme);
    case TPM2_ALG_ECC:
        return get_next_ecc_sign_scheme(scheme);
    default:
        log_error("get_next_sign_scheme: Invalid algorithm type");
        return false;
    }
}

bool get_next_hash_algorithm(TPMI_ALG_HASH *hash_alg)
{
    switch (*hash_alg) {
    case TPM2_ALG_NULL:
        *hash_alg = TPM2_ALG_SHA1; return true;
    case TPM2_ALG_SHA1:
        *hash_alg = TPM2_ALG_MGF1; return true;
    case TPM2_ALG_MGF1:
        *hash_alg = TPM2_ALG_SHA256; return true;
    case TPM2_ALG_SHA256:
        *hash_alg = TPM2_ALG_SHA384; return true;
    case TPM2_ALG_SHA384:
        *hash_alg = TPM2_ALG_SHA512; return true;
    case TPM2_ALG_SHA512:
        *hash_alg = TPM2_ALG_SM3_256; return true;
    case TPM2_ALG_SM3_256:
        *hash_alg = TPM2_ALG_SHA3_256; return true;
    case TPM2_ALG_SHA3_256:
        *hash_alg = TPM2_ALG_SHA3_384; return true;
    case TPM2_ALG_SHA3_384:
        *hash_alg = TPM2_ALG_SHA3_512; return true;
    case TPM2_ALG_SHA3_512:
        return false;
    default:
        return false;
    }
}
