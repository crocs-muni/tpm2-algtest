#include "createprimary.h"

#include "tpm2_tool.h"
#include "tpm2_session.h"
#include "tpm2_options.h"
#include "tpm2_util.h"

#include <time.h>
#include <string.h>

bool tpm2_tool_onstart(tpm2_options **opts)
{
    const struct option topts[] = {
    };
    *opts = tpm2_options_new("", ARRAY_LEN(topts), topts, NULL, NULL, 0);

    return *opts != NULL;
}

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

