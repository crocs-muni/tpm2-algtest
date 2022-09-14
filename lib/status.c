#include "status.h"

unsigned long get_progress_percentage(struct progress *prog) {
	return ((double) prog->current / prog->total) * 100;
}

unsigned long inc_and_get_progress_percentage(struct progress *prog) {
	prog->current++;
	return get_progress_percentage(prog);
}
