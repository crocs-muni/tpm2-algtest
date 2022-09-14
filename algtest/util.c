#include "util.h"
#include "options.h"
#include "logging.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

extern struct tpm_algtest_options options;

double get_duration_s(struct timespec *start, struct timespec *end)
{
    return (end->tv_sec - start->tv_sec)
         + (end->tv_nsec - start->tv_nsec) / (double) (1000 * 1000 * 1000);
}

FILE *open_csv(const char *filename, const char *header)
{
    char path[256];
    strncpy(path, options.outdir, strlen(options.outdir) + 1);
    strncat(path, "/",  255 - strlen(path));
    strncat(path, filename, 255 - strlen(path));
    FILE *file = fopen(path, "w");
    if (!file) {
        log_error("Cannot open output file %s: %s", path, strerror(errno));
        exit(1);
    }
    fprintf(file, "%s\n", header);
    return file;
}
