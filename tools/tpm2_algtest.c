#include "options.h"
#include "createprimary.h"
#include "create.h"
#include "createloaded.h"
#include "ecdh_keygen.h"
#include "sign.h"
#include "verifysignature.h"
#include "util.h"
#include "scenario.h"
#include "logging.h"
#include "keygen.h"

#include "tpm2_tool.h"
#include "tpm2_session.h"
#include "tpm2_options.h"
#include "tpm2_util.h"

#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <limits.h>

struct tpm_algtest_options options = {
    .repetitions = 0,
    .max_duration_s = 0,
    .export_public = false,
    .export_private = false,
    .scenario = "none",
    .command = "all",
    .type = "all",
    .algorithm = "all",
    .keylen = 0,
    .verbose = TPM2_ALGTEST_VERBOSE_INFO
};

static
bool on_option(char key, char *value)
{
    switch (key) {
    case 's':
        options.scenario = value;
        break;
    case 'd':
        options.max_duration_s = atoi(value);
        break;
    case 't':
        options.type = value;
        break;
    case 'c':
        options.command = value;
        break;
    case 'l':
        options.keylen = atoi(value);
        break;
    case 'C':
        options.curveid = strtol(value, NULL, 0);
        break;
    case 'n':
        options.repetitions = atoi(value);
        break;
    case 'a':
        options.algorithm = value;
        break;
    case 'p':
        options.export_public = true;
        break;
    case 'P':
        options.export_private = true;
        break;
    }
    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts)
{
    const struct option topts[] = {
        { "scenario", required_argument, NULL, 's' },
        { "duration", required_argument, NULL, 'd' },
        { "type", required_argument, NULL, 't' },
        { "command", required_argument, NULL, 'c' },
        { "keylen", required_argument, NULL, 'l' },
        { "curveid", required_argument, NULL, 'C' },
        { "algorithm", required_argument, NULL, 'a' },
        { "exportpublic", no_argument, NULL, 'p' },
        { "exportprivate", no_argument, NULL, 'P' },
    };
    *opts = tpm2_options_new("s:d:n:t:c:l:C:a:", ARRAY_LEN(topts), topts, on_option, NULL, 0);

    return *opts != NULL;
}

#if 0
void run_all(TSS2_SYS_CONTEXT *sapi_context)
{
    test_CreatePrimary(sapi_context);
    test_Create(sapi_context);
    test_ECDH_KeyGen(sapi_context);
    test_VerifySignature(sapi_context);
    test_Sign(sapi_context);
}
#endif

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags)
{
#if 0
    if (strcmp(options.command, "all") == 0) {
        run_all(sapi_context);
    } else if (strcmp(options.command, "createprimary") == 0) {
        test_CreatePrimary(sapi_context);
    } else if (strcmp(options.command, "create") == 0) {
        test_Create(sapi_context);
// TODO: CreateLoaded has weird unmarshalling and is not working
//    } else if (strcmp(options.command, "createloaded") == 0) {
//        test_CreateLoaded(sapi_context);
    } else if (strcmp(options.command, "ecdh_keygen") == 0) {
        test_ECDH_KeyGen(sapi_context);
    } else if (strcmp(options.command, "verifysignature") == 0) {
        test_VerifySignature(sapi_context);
    } else if (strcmp(options.command, "sign") == 0) {
        test_Sign(sapi_context);
    } else {
        fprintf(stderr, "Unknown command!\n");
        exit(1);
    }
#endif
#if 0
    struct keygen_scenario scenario = {
        .common = {
            .repetitions = 10,
            .max_duration_s = 0,
        },
        .type = TPM2_ALG_RSA,
        .keyBits = 1024,
        .output_keys = false,
    };
    test_keygen(sapi_context, &scenario);
#endif
    struct scenario_parameters parameters = {
        .repetitions = options.repetitions,
        .max_duration_s = options.max_duration_s,
    };
    set_default_parameters(&parameters, 100, UINT_MAX);

    if (strcmp(options.scenario, "keygen") == 0) {
        if (strcmp(options.type, "all") == 0) {
            test_keygen_all(sapi_context, &parameters);
        } else {
            struct keygen_scenario scenario = {
                .parameters = parameters,
                .export_public = options.export_public,
                .export_private = options.export_private
            };
            if (strcmp(options.type, "rsa") == 0) {
                scenario.type = TPM2_ALG_RSA;
                scenario.keyBits = options.keylen;
            } else if (strcmp(options.type, "ecc") == 0) {
                scenario.type = TPM2_ALG_ECC;
                scenario.curveID = options.curveid;
            }
            test_keygen(sapi_context, &scenario);
        }
    }
    return 0;
}

