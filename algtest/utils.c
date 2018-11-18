#include "utils.h"

double get_duration_sec(struct timespec *start, struct timespec *end)
{
    return (end->tv_sec - start->tv_sec)
         + (double)(end->tv_nsec - start->tv_nsec)
         / 1000000000;
}
