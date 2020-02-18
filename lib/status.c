#include "status.h"

unsigned get_progress_percentage(struct progress *prog) {
	return (double) prog->current / prog->total;
}
