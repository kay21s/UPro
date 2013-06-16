#ifndef UPRO_TRANSWORKER_H
#define UPRO_TRANSWORKER_H

typedef struct upro_transworker_context_s {
	int core_id;
	int initialized;
} upro_transworker_context_t;

void upro_transworker_main(upro_transworker_context_t *context);

#endif
