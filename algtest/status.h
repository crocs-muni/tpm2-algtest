/* SPDX-License-Identifier: BSD-2-Clause */
#define FAILURE_LIMIT 3

struct progress {
	unsigned long total;
	unsigned long current;
};

unsigned long get_progress_percentage(struct progress *prog);
unsigned long increase_progress(struct progress *prog);
unsigned long skip_progress(struct progress *prog, unsigned long steps);
