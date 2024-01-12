/* SPDX-License-Identifier: BSD-2-Clause */
#pragma once

#define TPM2_ALGTEST_VERBOSE_INFO 3
#define TPM2_ALGTEST_VERBOSE_WARNING 2
#define TPM2_ALGTEST_VERBOSE_ERROR 1
#define TPM2_ALGTEST_VERBOSE_QUIET 0

void log_info(const char* format, ...);
void log_warning(const char* format, ...);
void log_error(const char* format, ...);
