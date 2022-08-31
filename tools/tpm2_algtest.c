#include "options.h"
#include "util.h"
#include "scenario.h"
#include "logging.h"
#include "keygen.h"
#include "perf.h"
#include "cryptoops.h"
#include "rng.h"

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
    .no_export = false,
    .scenario = "all",
    .command = "all",
    .type = "all",
    .algorithm = "all",
    .keylen = 0,
    .curveid = TPM2_ECC_NONE,
    .verbose = TPM2_ALGTEST_VERBOSE_INFO,
    .outdir = "out",
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
    case 'x':
        options.no_export = true;
        break;
    case 'o':
        options.outdir = value;
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
        { "no_export", no_argument, NULL, 'x' },
        { "outdir", required_argument, NULL, 'o' },
    };
    *opts = tpm2_options_new("s:d:n:t:c:l:C:a:xo:", ARRAY_LEN(topts), topts, on_option, NULL, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags)
{
    umask(0000);
    struct stat sb;
    if (stat(options.outdir, &sb) == -1) {
        if (mkdir(options.outdir, 0777) != 0) {
            perror("Cannot create output directory");
            exit(1);
        }
    }

    struct scenario_parameters parameters = {
        .repetitions = 100,
        .max_duration_s = UINT_MAX,
    };

    if (scenario_in_options("keygen")) {
        set_parameters_from_options(&parameters);
        run_keygen_scenarios(sapi_context, &parameters);
    }

    if (scenario_in_options("cryptoops")) {
        set_parameters_from_options(&parameters);
        run_cryptoops_scenarios(sapi_context, &parameters);
    }

    if (scenario_in_options("rng")) {
        set_parameters_from_options(&parameters);
        run_rng_scenarios(sapi_context, &parameters);
    }

    if (scenario_in_options("perf")) {
        set_parameters_from_options(&parameters);
        run_perf_scenarios(sapi_context, &parameters);
    }

    return 0;
}
