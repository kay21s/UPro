#include "upro_timer.h"

#include <sys/time.h>
#include <time.h>

int upro_timer_init(upro_timer_t *timer)
{
	timer->freq = 1000;

	return 0;
}

int upro_timer_start(upro_timer_t *timer)
{
	struct timespec s;
	clock_gettime(CLOCK_REALTIME, &s);
	timer->start = (uint64_t)s.tv_sec * 1e9 + (uint64_t)s.tv_nsec;

	return 0;
}

int upro_timer_restart(upro_timer_t *timer)
{
	struct timespec s;
	clock_gettime(CLOCK_REALTIME, &s);
	timer->start = (uint64_t)s.tv_sec * 1e9 + (uint64_t)s.tv_nsec;

	timer->clocks = 0;

	return 0;
}

int upro_timer_stop(upro_timer_t *timer)
{
	uint64_t n;

	struct timespec s;
	clock_gettime(CLOCK_REALTIME, &s);
	n = (uint64_t)s.tv_sec * 1e9 + (uint64_t)s.tv_nsec;

	n -= timer->start;
	timer->start = 0;
	timer->clocks += n;

	return 0;
}

int upro_timer_reset(upro_timer_t *timer)
{
	timer->clocks = 0;

	return 0;
}

double upro_timer_get_total_time(upro_timer_t *timer)
{
	//returns millisecond as unit -- second * 1000
	return (double)(timer->clocks * 1000) / (double) 1e9;
}

double upro_timer_get_elapsed_time(upro_timer_t *timer)
{
	uint64_t n;

	struct timespec s;
	clock_gettime(CLOCK_REALTIME, &s);
	n = (uint64_t)s.tv_sec * 1e9 + (uint64_t)s.tv_nsec;

	return (double)((n - timer->start) * 1000) / (double) 1e9;
}

