struct progress {
	unsigned long total;
	unsigned long current;
};

unsigned long get_progress_percentage(struct progress *prog);
unsigned long inc_and_get_progress_percentage(struct progress *prog);
