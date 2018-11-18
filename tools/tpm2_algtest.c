#include "createprimary.h"

#include "tpm2_tool.h"
#include "tpm2_session.h"
#include "tpm2_options.h"
#include "tpm2_util.h"

#include <time.h>
#include <string.h>

#include <unistd.h>

bool tpm2_tool_onstart(tpm2_options **opts)
{
    const struct option topts[] = {
    };
    *opts = tpm2_options_new("", ARRAY_LEN(topts), topts, NULL, NULL, 0);

    return *opts != NULL;
}

#if 0
void update_rc_values(TPM2_RC rc_values[], TPM2_RC value, int *idx)
{
    bool exists = false;
    for (int i = 0; i < *idx; ++i) {
        if (rc_values[i] == value) {
            exists = true;
            break;
        }
    }
    if (!exists) {
        rc_values[(*idx)++] = value;
    }
}
#endif
#if 0
void measure_TestParms_rsa(TSS2_SYS_CONTEXT *sapi_context)
{
    TPMT_PUBLIC_PARMS parameters = {
        .type = TPM2_ALG_RSA,
        .parameters = {
            .rsaDetail = {
                .symmetric = TPM2_ALG_NULL,
                .scheme = TPM2_ALG_NULL,
                .keyBits = 1024,
                .exponent = 0
            }
        }
    };

    TPM2_RC rc_values[32];
    int idx = 0;

    printf("  Key lengths:\n");
    for (int key_size = 0; key_size < 4100; key_size += 32) {
        parameters.parameters.rsaDetail.keyBits = key_size;
        TPM2_RC ret = Tss2_Sys_TestParms(sapi_context, NULL, &parameters, NULL);
        update_rc_values(rc_values, ret, &idx);
        if (ret == TPM2_RC_SUCCESS) {
            printf("  %d\n", key_size);
        }
    }

    printf("\n  Return codes:\n");
    for (int i = 0; i < idx; ++i) {
        printf("  %04x\n", rc_values[i]);
    }
}

void measure_TestParms_symcipher(TSS2_SYS_CONTEXT *sapi_context)
{
    TPMT_PUBLIC_PARMS parameters = {
        .type = TPM2_ALG_SYMCIPHER,
        .parameters = {
            .symDetail = {
                .sym = {
                    .algorithm = TPM2_ALG_AES,
                    .mode = TPM2_ALG_CBC
                }
            }
        }
    };

    TPM2_RC rc_values[32];
    int idx = 0;

    printf("  Key lengths:\n");
    for (int key_size = 0; key_size < 500; key_size += 32) {
        parameters.parameters.symDetail.sym.keyBits.aes = key_size;
        TPM2_RC ret = Tss2_Sys_TestParms(sapi_context, NULL, &parameters, NULL);
        update_rc_values(rc_values, ret, &idx);
        if (ret == TPM2_RC_SUCCESS) {
            printf("  %d\n", key_size);
        }
    }

    printf("\n  Return codes:\n");
    for (int i = 0; i < idx; ++i) {
        printf("  %04x\n", rc_values[i]);
    }
}
#endif

# if 0
void measure_TestParms_ecc(TSS2_SYS_CONTEXT *sapi_context)
{
    TPMT_PUBLIC_PARMS parameters = {
        .type = TPM2_ALG_ECC,
        .parameters = {
            .eccDetail = {
                .symmetric = TPM2_ALG_NULL,
                .scheme = TPM2_ALG_NULL,

            }
        }
    };

    TPM2_RC rc_values[32];
    int idx = 0;

    printf("  Key lengths:\n");
    for (int key_size = 0; key_size < 4100; key_size += 32) {
        parameters.parameters.rsaDetail.keyBits = key_size;
        TPM2_RC ret = Tss2_Sys_TestParms(sapi_context, NULL, &parameters, NULL);
        update_rc_values(rc_values, ret, &idx);
        if (ret == TPM2_RC_SUCCESS) {
            printf("  %d\n", key_size);
        }
    }

    printf("\n  Return codes:\n");
    for (int i = 0; i < idx; ++i) {
        printf("  %04x\n", rc_values[i]);
    }
}

void measure_TestParms(TSS2_SYS_CONTEXT *sapi_context)
{
    printf("TPM2_TestParms:\n");
    measure_TestParms_rsa(sapi_context);
//    measure_TestParms_symcipher(sapi_context);
}

void measure_Create(TSS2_SYS_CONTEXT *sapi_context)
{

}

#endif
int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags)
{
    //test_GetCap(sapi_context);
    //measure_TestParms(sapi_context);
    measure_CreatePrimary(sapi_context);
    //measure_Create(sapi_context);
    //measure_CreateLoaded();
    //measure_RSA_Encrypt();
    //measure_RSA_Decrypt();
    //measure_ECDH_KeyGen();
    //measure_ECDH_ZGen();
    //measure_ZGen_2Phase();
    //measure_EncryptDecrypt();
    //measure_EncryptDecrypt2();
    //measure_Hash();
    //measure_HMAC();

    return 0;
}

