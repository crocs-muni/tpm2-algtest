#include "options.h"

#include <string.h>

extern struct tpm_algtest_options options;

bool command_in_options(const char* command)
{
    return strcmp(options.command, "all") == 0
        || strcmp(options.command, command) == 0;
}

bool type_in_options(const char* type)
{
    return strcmp(options.type, "all") == 0
        || strcmp(options.type, type) == 0;
}

bool keylen_in_options(TPMI_RSA_KEY_BITS keylen)
{
    return options.keylen == 0 || options.keylen == keylen;
}

bool curve_in_options(TPM2_ECC_CURVE curveID)
{
    return options.curveid == TPM2_ECC_NONE || options.curveid == curveID;
}
