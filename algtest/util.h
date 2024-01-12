/* SPDX-License-Identifier: BSD-2-Clause */
#pragma once
#include <time.h>
#include <stdio.h>

double get_duration_s(struct timespec *start, struct timespec *end);
FILE *open_csv(const char *filename, const char *header);
FILE *open_bin(const char *filename);
int read_cyclic(FILE *fp, char *buffer, size_t size);
