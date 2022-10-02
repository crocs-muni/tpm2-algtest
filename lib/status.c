#include "status.h"

unsigned long get_progress_percentage(struct progress *prog) {
	return ((double) prog->current / prog->total) * 100;
}

unsigned long increase_progress(struct progress *prog) {
	prog->current++;
	return get_progress_percentage(prog);
}

unsigned long skip_progress(struct progress *prog, unsigned long steps) {
	prog->current += steps;
	return get_progress_percentage(prog);
}
