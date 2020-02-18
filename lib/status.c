#include "status.h"

unsigned get_progress_percentage(struct progress *prog) {
	return (double) prog->current / prog->total;
}

unsigned inc_and_get_progress_percentage(struct progress *prog) {
	prog->current++;
	return (double) prog->current / prog->total;
}
