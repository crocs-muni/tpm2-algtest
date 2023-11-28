#include "scenario.h"
#include "options.h"

extern struct tpm_algtest_options options;

void set_parameters_from_options(struct scenario_parameters *parameters)
{
    if (options.repetitions) {
        parameters->repetitions = options.repetitions;
    }
    if (options.max_duration_s) {
        parameters->max_duration_s = options.max_duration_s;
    }
    parameters->input_type = options.input_type;
}
