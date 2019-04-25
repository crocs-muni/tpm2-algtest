#pragma once
#include <tss2/tss2_sys.h>
#include <stdbool.h>

struct scenario_parameters {
    unsigned repetitions;
    unsigned max_duration_s;
};

void set_parameters_from_options(struct scenario_parameters *parameters);
