#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "upro_log.h"
#include "upro_memory.h"
#include "upro_config.h"

extern upro_config_t *config;

#define LOG_PRINT 1

// Add "num" variable based on original version
void upro_sample_set_msg(upro_log_sample_t *sample, const char *fmt, const char *msg, double num)
{
	sample->isMsg = 1;

	sample->fmt = upro_mem_malloc(strlen(fmt)+1);
	strcpy(sample->fmt, fmt);

	sample->msg = upro_mem_malloc(strlen(msg)+1);
	strcpy(sample->msg, msg);

	sample->num = num;
}

void upro_sample_set_timer(upro_log_sample_t *sample, const char *fmt, const char *msg, double timer, unsigned int nbytes, int loops)
{
	sample->isMsg = 0;
	sample->timer = timer;

	if (loops != 0)	sample->loops = loops;
	if (nbytes > 0)	sample->nbytes = nbytes;

	if (strlen(msg) > 0) {
		sample->fmt = upro_mem_malloc(strlen( fmt ) + 1);
		strcpy(sample->fmt, fmt);
	}

	if (strlen(msg) > 0) {
		sample->msg = upro_mem_malloc(strlen( msg ) + 1);
		strcpy(sample->msg, msg);
	}
}

void upro_sample_print(upro_log_sample_t *sample)
{
	if(sample->isMsg == 1) {
		printf(sample->fmt, sample->msg, sample->num);
	} else {
		double bwd = (((double) sample->nbytes * sample->loops )/ sample->timer) / 1e9;
		printf(sample->fmt, sample->msg, sample->timer, bwd) ;
	}
}

/* ---------------------------------------------------------------------- */

void upro_log_init(upro_log_t *log)
{
	log->idx = 0;
	log->loops = 0;
	log->loop_entries = 0;
	log->loop_timers = 0;
	log->samples = upro_mem_malloc(config->log_sample_num * sizeof(upro_log_sample_t));
}

void upro_log_loop_marker(upro_log_t *log)
{
	log->loop_timers = 0;
	log->loops ++;
#if defined(LOG_PRINT)
	printf("\n---------------------------%d\n", log->loops);
#endif
}

void upro_log_msg(upro_log_t *log, const char *format, const char *msg, const double num)
{
#if defined(LOG_PRINT)
	printf(format, msg, num);
#else
	upro_sample_set_msg(&(log->samples[log->idx ++]), format, msg, num);
	log->loop_entries ++;
#endif
}

void upro_log_timer(upro_log_t *log, const char *format, const char *msg, double timer, unsigned int nbytes, int loops)
{
	upro_sample_set_timer(&(log->samples[log->idx ++]), format, msg, timer, nbytes, loops);
	log->loop_entries ++;
	log->loop_timers ++;
}

void upro_log_print(upro_log_t *log)
{
	int i;

	for(i = 0; i < log->loop_entries; i++) {
		upro_sample_print(&(log->samples[i]));
	}
}
