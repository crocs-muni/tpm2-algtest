#include "scenario.h"

void set_default_parameters(struct scenario_parameters *parameters,
        unsigned repetitions, unsigned max_duration_s)
{
    if (!parameters->repetitions) {
        parameters->repetitions = repetitions;
    }
    if (!parameters->max_duration_s) {
        parameters->max_duration_s = max_duration_s;
    }
}
