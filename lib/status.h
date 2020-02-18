struct progress {
	unsigned long total;
	unsigned long current;
};

unsigned get_progress_percentage(struct progress *prog);
unsigned inc_and_get_progress_percentage(struct progress *prog);
