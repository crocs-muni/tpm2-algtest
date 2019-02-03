#include "context.h"
#include "createprimary.h"
#include "create.h"
#include "createloaded.h"
#include "ecdh_keygen.h"
#include "util.h"

#include "tpm2_tool.h"
#include "tpm2_session.h"
#include "tpm2_options.h"
#include "tpm2_util.h"

#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

struct tpm_algtest_ctx ctx = {
    .command = "all",
    .type = "all",
    .algorithm = "all",
    .repetitions = 0,
    .keylen = 0
};

static
bool on_option(char key, char *value)
{
    switch (key) {
    case 't':
        ctx.type = value;
        break;
    case 'c':
        ctx.command = value;
        break;
    case 'l':
        ctx.keylen = atoi(value);
        break;
    case 'n':
        ctx.repetitions = atoi(value);
        break;
    case 'a':
        ctx.algorithm = value;
        break;
    }
    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts)
{
    const struct option topts[] = {
        { "type", required_argument, NULL, 't' },
        { "command", required_argument, NULL, 'c' },
        { "keylen", required_argument, NULL, 'l' },
        { "algorithm", required_argument, NULL, 'a' }
    };
    *opts = tpm2_options_new("n:t:c:l:a:", ARRAY_LEN(topts), topts, on_option, NULL, 0);

    return *opts != NULL;
}

void run_all(TSS2_SYS_CONTEXT *sapi_context)
{
    test_CreatePrimary(sapi_context);
    test_Create(sapi_context);
    test_ECDH_KeyGen(sapi_context);
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags)
{
    struct stat sb;
    if (stat("csv", &sb) == -1) {
        umask(0000);
        mkdir("csv", 0770);
    }

    if (strcmp(ctx.command, "all") == 0) {
        run_all(sapi_context);
    } else if (strcmp(ctx.command, "createprimary") == 0) {
        test_CreatePrimary(sapi_context);
    } else if (strcmp(ctx.command, "create") == 0) {
        test_Create(sapi_context);
    } else if (strcmp(ctx.command, "createloaded") == 0) {
        test_CreateLoaded(sapi_context);
    } else if (strcmp(ctx.command, "ecdh_keygen") == 0) {
        test_ECDH_KeyGen(sapi_context);
    } else {
        fprintf(stderr, "Unknown command!\n");
        exit(1);
    }
    return 0;
}

