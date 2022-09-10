#pragma once

#include <tss2/tss2_sys.h>

bool get_next_key_params(TPMT_PUBLIC_PARMS *key_params);

bool get_next_asym_key_params(TPMT_PUBLIC_PARMS *key_params);

bool get_next_sign_scheme(TPMT_SIG_SCHEME *scheme, TPM2_ALG_ID type);

bool get_next_rsa_enc_scheme(TPMT_RSA_DECRYPT *scheme);

bool get_next_rsa_keylen(TPMI_RSA_KEY_BITS *keylen);

bool get_next_symcipher(TPMT_SYM_DEF_OBJECT *sym);

bool get_next_sym_mode(TPMI_ALG_SYM_MODE *mode);

bool get_next_hash_algorithm(TPMI_ALG_HASH *hash_alg);

bool get_next_ecc_curve(TPMI_ECC_CURVE *curve);

bool get_next_zgen_scheme(TPMI_ECC_KEY_EXCHANGE *scheme);
