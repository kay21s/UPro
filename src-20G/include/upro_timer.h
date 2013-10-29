#ifndef UPRO_TIMER_H
#define UPRO_TIMER_H

#include <stdint.h>

/**
 * \file Timer.h
 * \brief A timer class that provides a cross platform timer for use
 * in timing code progress with a high degree of accuracy.
 * FIXME:
 * 1s = 1000ms (millisecond)
 * 1ms = 1000us (microsecond)
 * 1us = 1000ns (nanosecond)
 * this counter returns in terms of us
 */


typedef struct upro_timer_s {
    uint64_t freq;
    uint64_t clocks;
    uint64_t start;
} upro_timer_t;

int upro_timer_init();
int upro_timer_start(upro_timer_t *timer);
int upro_timer_restart(upro_timer_t *timer);
int upro_timer_stop(upro_timer_t *timer);
int upro_timer_reset(upro_timer_t *timer);
double upro_timer_get_total_time(upro_timer_t *timer);
double upro_timer_get_elapsed_time(upro_timer_t *timer);

#endif

