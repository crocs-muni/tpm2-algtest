/*
 * Copyright (c) 2016-2018, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of Intel Corporation nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>

#include <linux/limits.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "log.h"
#include "tpm2_options.h"
#include "tpm2_tcti_ldr.h"
#include "tpm2_util.h"

#ifndef VERSION
  #warning "VERSION Not known at compile time, not embedding..."
  #define VERSION "UNKNOWN"
#endif

#define TPM2TOOLS_ENV_TCTI      "TPM2TOOLS_TCTI"
#define TPM2TOOLS_ENV_ENABLE_ERRATA  "TPM2TOOLS_ENABLE_ERRATA"

tpm2_options *tpm2_options_new(const char *short_opts, size_t len,
        const struct option *long_opts, tpm2_option_handler on_opt,
        tpm2_arg_handler on_arg, UINT32 flags) {

    tpm2_options *opts = calloc(1, sizeof(*opts) + (sizeof(*long_opts) * len));
    if (!opts) {
        LOG_ERR("oom");
        return NULL;
    }

    /*
     * On NULL, just make it a zero length string so we don't have to keep
     * checking it for NULL.
     */
    if (!short_opts) {
        short_opts = "";
    }

    opts->short_opts = strdup(short_opts);
    if (!opts->short_opts) {
        LOG_ERR("oom");
        free(opts);
        return NULL;
    }

    opts->callbacks.on_opt = on_opt;
    opts->callbacks.on_arg = on_arg;
    opts->len = len;
    opts->flags = flags;
    memcpy(opts->long_opts, long_opts, len * sizeof(*long_opts));

    return opts;
}

bool tpm2_options_cat(tpm2_options **dest, tpm2_options *src) {

    tpm2_options *d = *dest;

    /* move the nested char * pointer first */
    size_t opts_len = strlen(d->short_opts) + strlen(src->short_opts) + 1;
    char *tmp_short = realloc(d->short_opts, opts_len);
    if (!tmp_short) {
        LOG_ERR("oom");
        return false;
    }

    strcat(tmp_short, src->short_opts);

    d->short_opts = tmp_short;

    /* now move the enclosing structure */
    size_t long_opts_len = d->len + src->len;
    /* +1 for a terminating NULL at the end of options array for getopt_long */
    tpm2_options *tmp = realloc(d, sizeof(*d) + ((long_opts_len + 1) * sizeof(d->long_opts[0])));
    if (!tmp) {
        LOG_ERR("oom");
        return false;
    }

    *dest = d = tmp;

    d->callbacks.on_arg = src->callbacks.on_arg;
    d->callbacks.on_opt = src->callbacks.on_opt;
    d->flags = src->flags;

    memcpy(&d->long_opts[d->len], src->long_opts, src->len * sizeof(src->long_opts[0]));

    /* length must be updated post memcpy as we need d->len to be the original offset */
    d->len = long_opts_len;

    /* NULL term for getopt_long */
    memset(&d->long_opts[d->len], 0, sizeof(d->long_opts[0]));

    return true;
}

void tpm2_options_free(tpm2_options *opts) {
    free(opts->short_opts);
    free(opts);
}
typedef struct tcti_conf tcti_conf;
struct tcti_conf {
    const char *name;
    const char *opts;
};

static inline const char *fixup_name(const char *name) {

    return !strcmp(name, "abrmd") ? "tabrmd" : name;
}

static const char *find_default_tcti(void) {

    const char *defaults[] = {
        "tabrmd",
        "device",
        "mssim"
    };

    size_t i;
    for(i=0; i < ARRAY_LEN(defaults); i++) {
        const char *name = defaults[i];
        bool is_present = tpm2_tcti_ldr_is_tcti_present(name);
        if (is_present) {
            return name;
        }
    }

    return NULL;
}

static tcti_conf tcti_get_config(const char *optstr) {

    /* set up the default configuration */
    tcti_conf conf = {
        .name = find_default_tcti()
    };

    /* no tcti config supplied, get it from env */
    if (!optstr) {
        optstr = getenv (TPM2TOOLS_ENV_TCTI);
        if (!optstr) {
            /* nothing user supplied, use default */
            return conf;
        }
    }

    char *split = strchr(optstr, ':');
    if (!split) {
        /* --tcti=device */
        conf.name = fixup_name(optstr);
        return conf;
    }

    /*
     * If it has a ":", it could be either one of the following:
     * case A: --tcti=:               --> default name and default (null) config
     * case B: --tcti=:/dev/foo       --> default name, custom config
     * case C: --tcti=device:         --> custom name, default (null) config
     * case D: --tcti=device:/dev/foo --> custom name, custom config
     */

    split[0] = '\0';

    /* Case A */
    if (!optstr[0] && !split[1]) {
        return conf;
    }

    /* Case B */
    if (!optstr[0]) {
        conf.opts = &split[1];
        return conf;
    }

    /* Case C */
    if (!split[1]) {
        conf.name = fixup_name(optstr);
        return conf;
    }

    /* Case D */
    conf.name = fixup_name(optstr);
    conf.opts = &split[1];
    return conf;
}

static bool execute_man(char *prog_name, bool show_errors) {

    pid_t  pid;
    int status;

    if ((pid = fork()) < 0) {
        LOG_ERR("Could not fork process to execute man, error: %s",
                strerror(errno));
        return false;
    }

    if (pid == 0) {

        if (!show_errors) {
            /* redirect manpager errors to stderr */
            int fd = open("/dev/null", O_WRONLY);
            dup2(fd, 2);
            close(fd);
        }

        char *manpage = basename(prog_name);
        execlp("man", "man", manpage, NULL);
    } else {
        if ((pid = waitpid(pid, &status, 0)) == -1) {
            LOG_ERR("Waiting for child process that executes man failed, error: %s",
                    strerror(errno));
            return false;
        }

        return WEXITSTATUS(status) == 0;
    }

    return true;
}

static void show_version (const char *name) {

#ifdef DISABLE_DLCLOSE
    char *dlconfig="disabled";
#else
    char *dlconfig="enabled";
#endif

    const char *tcti_default = find_default_tcti();
    if (!tcti_default) {
        tcti_default = "none";
    }

    printf("tool=\"%s\" version=\"%s\" tctis=\"dynamic\" tcti-default=%s dlclose=%s\n",
            name, VERSION, tcti_default, dlconfig);
}

void tpm2_print_usage(const char *command, struct tpm2_options *tool_opts) {
    unsigned int i;
    bool indent = true;
    char *command_copy;

    if (!tool_opts) {
        return;
    }

    command_copy = strdup(command);
    printf("Usage: %s%s%s\n", basename(command_copy),
           tool_opts->callbacks.on_opt ? " [<options>]" : "",
           tool_opts->callbacks.on_arg ? " <arguments>" : "");
    free(command_copy);

    if (tool_opts->callbacks.on_opt) {
        printf("Where <options> are:\n");
        for (i = 0; i < tool_opts->len; i++) {
            struct option *opt = &tool_opts->long_opts[i];

            if (indent) {
                printf("    ");
                indent = false;
            } else {
                printf(" ");
            }
            printf("[ -%c | --%s%s]", opt->val, opt->name,
                   opt->has_arg ? "=<value>" : "");
            if ((i + 1) % 4 == 0) {
                printf("\n");
                indent = true;
            }
        }
        if (i % 4 != 0) {
            printf("\n");
        }
    }
}

tpm2_option_code tpm2_handle_options (int argc, char **argv,
        tpm2_options *tool_opts, tpm2_option_flags *flags,
        TSS2_TCTI_CONTEXT **tcti) {

    tpm2_option_code rc = tpm2_option_code_err;
    bool result = false;
    bool show_help = false;
    bool manpager = true;
    bool explicit_manpager = false;

    /*
     * Handy way to *try* and find all used options:
     * grep -rn case\ \'[a-zA-Z]\' | awk '{print $3}' | sed s/\'//g | sed s/\://g | sort | uniq | less
     */
    struct option long_options [] = {
        { "tcti",          required_argument, NULL, 'T' },
        { "help",          optional_argument, NULL, 'h' },
        { "verbose",       no_argument,       NULL, 'V' },
        { "quiet",         no_argument,       NULL, 'Q' },
        { "version",       no_argument,       NULL, 'v' },
        { "enable-errata", no_argument,       NULL, 'Z' },
    };

    const char *tcti_conf_option = NULL;


    /* handle any options */
    const char* common_short_opts = "T:h::vVQZ";
    tpm2_options *opts = tpm2_options_new(common_short_opts,
            ARRAY_LEN(long_options), long_options, NULL, NULL, true);
    if (!opts) {
        return tpm2_option_code_err;
    }

    /* Get the options from the tool */
    if (tool_opts) {
        result = tpm2_options_cat(&opts, tool_opts);
        if (!result) {
            goto out;
        }
    }

    /* Parse the options, calling the tool callback if unknown */
    int c;
    while ((c = getopt_long (argc, argv, opts->short_opts, opts->long_opts, NULL))
           != -1)
    {
        switch (c) {
        case 'T':
            if (opts->flags & TPM2_OPTIONS_NO_SAPI) {
                LOG_ERR("%s: tool doesn't support the TCTI option", argv[0]);
                goto out;
            }
            /* only attempt to get options from tcti option string */
            tcti_conf_option = optarg;
            break;
        case 'h':
            show_help = true;
            if (argv[optind]) {
                if (!strcmp(argv[optind], "man")) {
                    manpager = true;
                    explicit_manpager = true;
                    optind++;
                } else if (!strcmp(argv[optind], "no-man")) {
                    manpager = false;
                    optind++;
                } else {
                    show_help=false;
                    LOG_ERR("Unknown help argument, got: \"%s\"", argv[optind]);
                }
            }
            goto out;
        break;
        case 'V':
            flags->verbose = 1;
            break;
        case 'Q':
            flags->quiet = 1;
            break;
        case 'v':
            show_version(argv[0]);
            rc = tpm2_option_code_stop;
            goto out;
            break;
        case 'Z':
            flags->enable_errata = 1;
            break;
        case '?':
            goto out;
        default:
            /* NULL on_opt handler and unknown option specified is an error */
            if (!tool_opts || !tool_opts->callbacks.on_opt) {
                LOG_ERR("Unknown options found: %c", c);
                goto out;
            }
            result = tool_opts->callbacks.on_opt(c, optarg);
            if (!result) {
                goto out;
            }
        }
    }

    char **tool_args = &argv[optind];
    int tool_argc = argc - optind;

    /* have args and no handler, error condition */
    if (tool_argc && (!tool_opts || !tool_opts->callbacks.on_arg)) {
        LOG_ERR("Got arguments but the tool takes no arguments");
        show_help = true;
        goto out;
    }
    /* have args and a handler to process */
    else if (tool_argc && tool_opts->callbacks.on_arg) {
        result = tool_opts->callbacks.on_arg(tool_argc, tool_args);
        if (!result) {
            goto out;
        }
	}

    /* Only init a TCTI if the tool needs it and if the -h/--help option isn't present */
    if (!show_help){
      if (!tool_opts || !(tool_opts->flags & TPM2_OPTIONS_NO_SAPI)) {
          tcti_conf conf = tcti_get_config(tcti_conf_option);

          *tcti = tpm2_tcti_ldr_load(conf.name, conf.opts);
          if (!*tcti) {
              LOG_ERR("Could not load tcti, got: \"%s\"", conf.name);
              goto out;
          }

          if (!flags->enable_errata) {
              flags->enable_errata = !!getenv (TPM2TOOLS_ENV_ENABLE_ERRATA);
          }
      }
    }

    rc = tpm2_option_code_continue;
out:

    /*
     * If help output is selected via -h or indicated by an error that help output
     * is desirable, show it.
     *
     * However, 3 conditions are possible:
     * 1. Try manpager and success -- done, no need to show short help output.
     * 2. Try manpager and failure -- show short help output.
     * 3. Do not use manpager -- show short help output.
     *
     */
    if (show_help) {
        bool did_manpager = false;
        if (manpager) {
            did_manpager = execute_man(argv[0], explicit_manpager);
        }

        if (!did_manpager) {
            tpm2_print_usage(argv[0], tool_opts);
        }

        const TSS2_TCTI_INFO *info = tpm2_tcti_ldr_getinfo();
        if (info) {
            printf("\ntcti-help(%s): %s\n", info->name, info->config_help);
        }
        rc = tpm2_option_code_stop;
    }

    tpm2_options_free(opts);

    return rc;
}
