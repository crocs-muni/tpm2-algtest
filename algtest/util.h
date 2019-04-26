#pragma once
#include <time.h>
#include <stdio.h>

double get_duration_s(struct timespec *start, struct timespec *end);
FILE *open_csv(const char *filename, const char *header);
