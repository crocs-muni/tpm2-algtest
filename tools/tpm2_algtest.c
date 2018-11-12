#include "tpm2_tool.h"
#include "tpm2_util.h"
#include "tpm2_session.h"

#include <tss2/tss2_sys.h>
#include <time.h>

#include <unistd.h>

#if 0
bool tpm2_tool_onstart(tpm2_options **opts)
{
    return true;
}
#endif

double get_duration(struct timespec *start, struct timespec *end)
{
    return (end->tv_sec - start->tv_sec) + (double)(end->tv_nsec - start->tv_nsec) / 1000000000;
}

void measure_TestParms(TSS2_SYS_CONTEXT *sapi_context)
{
    TSS2_RC ret;
#if 1

    TPMT_PUBLIC_PARMS parameters = {
        .type = TPM2_ALG_RSA,
        .parameters = {
            .rsaDetail = {
                .symmetric = TPM2_ALG_NULL,
                .scheme = TPM2_ALG_NULL,
                .keyBits = 0,
                .exponent = 0
            }
        }
    };
    ret = Tss2_Sys_TestParms(sapi_context, NULL, &parameters, NULL);

    struct timespec start, end;
    for (int key_size = 0; key_size < 5000; ++key_size) {
        TPMT_PUBLIC_PARMS parameters = {
            .type = TPM2_ALG_RSA,
            .parameters = {
                .rsaDetail = {
                    .symmetric = TPM2_ALG_NULL,
                    .scheme = TPM2_ALG_NULL,
                    .keyBits = key_size,
                    .exponent = 0
                }
            }
        };

        clock_gettime(CLOCK_MONOTONIC_RAW, &start);
        ret = Tss2_Sys_TestParms(sapi_context, NULL, &parameters, NULL);
        clock_gettime(CLOCK_MONOTONIC_RAW, &end);
        if (ret != 0x01c4)
            //printf("%d, %f\n", key_size, get_duration(&start, &end));
            printf("%04x, %d\n", ret, key_size);
    //    usleep(100);
    }
#endif

#if 0
    for (size_t i = 0; i <= 256; ++i) {

        TPMT_PUBLIC_PARMS aes_parameters = {
            .type = TPM2_ALG_AES,
            .parameters = {
                .symDetail = {
                    .sym = {
                        .algorithm = TPM2_ALG_AES,
                        .keyBits = { .sym = i },
                        .mode = { .sym = TPM2_ALG_CFB }
                    }
                }
            }
        };
        ret = Tss2_Sys_TestParms(sapi_context, NULL, &aes_parameters, NULL);
        //if (ret != 0x01ca)
        printf("aes: %d: %04x\n", i, ret);
    }
#endif

}

typedef struct tpm2_hierarchy_pdata tpm2_hierarchy_pdata;
struct tpm2_hierarchy_pdata {
    struct {
        TPMI_RH_HIERARCHY hierarchy;
        TPM2B_SENSITIVE_CREATE sensitive;
        TPM2B_PUBLIC public;
        TPM2B_DATA outside_info;
        TPML_PCR_SELECTION creation_pcr;
        TPM2_HANDLE object_handle;
    } in;
    struct {
        TPM2_HANDLE handle;
        TPM2B_PUBLIC public;
        TPM2B_DIGEST hash;
        struct {
            TPM2B_CREATION_DATA data;
            TPMT_TK_CREATION ticket;
        } creation;
        TPM2B_NAME name;
    } out;
};

typedef struct tpm_createprimary_ctx tpm_createprimary_ctx;
struct tpm_createprimary_ctx {
    struct {
        TPMS_AUTH_COMMAND session_data;
        tpm2_session *session;
    } auth;
    tpm2_hierarchy_pdata objdata;
    char *context_file;
    struct {
        UINT8 P :1;
        UINT8 p :1;
    } flags;
    char *parent_auth_str;
    char *key_auth_str;

    char *alg;
    char *halg;
    char *attrs;
    char *policy;
};

static tpm_createprimary_ctx ctx = {
    //.alg = DEFAULT_PRIMARY_KEY_ALG,
    .auth = { .session_data = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW) },
    .objdata = {
        .in = {
            .sensitive = TPM2B_SENSITIVE_CREATE_EMPTY_INIT,
            .hierarchy = TPM2_RH_OWNER
        },
    },
};

void test_rsa(TSS2_SYS_CONTEXT *sapi_context)
{
    TSS2L_SYS_AUTH_COMMAND sessionsData = TSS2L_SYS_AUTH_COMMAND_INIT(1, {ctx.auth.session_data});

    printf("sending command\n");
    TPM2_RC ret = Tss2_Sys_CreatePrimary(sapi_context, ctx.objdata.in.hierarchy,
            &sessionsData, &ctx.objdata.in.sensitive, &ctx.objdata.in.public,
            &ctx.objdata.in.outside_info, &ctx.objdata.in.creation_pcr,
            &ctx.objdata.out.handle, &ctx.objdata.out.public,
            &ctx.objdata.out.creation.data, &ctx.objdata.out.hash,
            &ctx.objdata.out.creation.ticket, &ctx.objdata.out.name,
            NULL);
    printf("finished, %04x\n", ret);
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags)
{
    measure_TestParms(sapi_context);
    //test_rsa(sapi_context);
    return 0;
}

