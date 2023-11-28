#pragma once
#include <tss2/tss2_sys.h>
#include <stdbool.h>
#include "options.h"

struct scenario_parameters {
    unsigned repetitions;
    unsigned max_duration_s;
    INPUT_TYPE input_type;
};

void set_parameters_from_options(struct scenario_parameters *parameters);
