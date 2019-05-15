#include "logging.h"
#include "options.h"

#include <stdarg.h>
#include <stdio.h>

extern struct tpm_algtest_options options;

void log_info(const char* format, ...)
{
    if (options.verbose < TPM2_ALGTEST_VERBOSE_INFO) {
        return;
    }

    va_list args;
    va_start(args, format);
    fprintf(stdout, "INFO: ");
    vfprintf(stdout, format, args);
    fprintf(stdout, "\n");
    va_end(args);
}

void log_warning(const char* format, ...)
{
    if (options.verbose < TPM2_ALGTEST_VERBOSE_WARNING) {
        return;
    }

    va_list args;
    va_start(args, format);
    fprintf(stdout, "WARNING: ");
    vfprintf(stdout, format, args);
    fprintf(stdout, "\n");
    va_end(args);
}

void log_error(const char* format, ...)
{
    if (options.verbose < TPM2_ALGTEST_VERBOSE_ERROR) {
        return;
    }

    va_list args;
    va_start(args, format);
    fprintf(stdout, "ERROR: ");
    vfprintf(stdout, format, args);
    fprintf(stdout, "\n");
    va_end(args);
}
