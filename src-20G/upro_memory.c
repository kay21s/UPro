#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#include "upro_memory.h"
#include "upro_macros.h"

ALLOCSZ_ATTR(1)
void *upro_mem_malloc(const size_t size)
{
	void *aux = malloc(size);

	if (upro_unlikely(!aux && size)) {
		perror("malloc");
		return NULL;
	}

	return aux;
}

ALLOCSZ_ATTR(1)
void *upro_mem_calloc(const size_t size)
{
	void *buf = calloc(1, size);
	if (upro_unlikely(!buf)) {
		return NULL;
	}

	return buf;
}

ALLOCSZ_ATTR(2)
void *upro_mem_realloc(void *ptr, const size_t size)
{
	void *aux = realloc(ptr, size);

	if (upro_unlikely(!aux && size)) {
		perror("realloc");
		return NULL;
	}

	return aux;
}

void upro_mem_free(void *ptr)
{
	free(ptr);
}
