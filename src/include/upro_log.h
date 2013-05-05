#ifndef UPRO_LOG_H
#define UPRO_LOG_H

typedef struct upro_log_sample_s {
	unsigned int	isMsg;
	unsigned int	isErr;
	double        timer;
	unsigned int  nbytes;
	int           loops;
	char *        fmt;
	char *        msg;
	int           num;
} upro_log_sample_t;

typedef struct upro_log_s {
	unsigned int idx;
	unsigned int loops;
	unsigned int loop_entries;
	unsigned int loop_timers;
 
	upro_log_sample_t *samples;
} upro_log_t;

void upro_log_init(upro_log_t *log);
void upro_log_loop_marker(upro_log_t *log);
void upro_log_msg(upro_log_t *log, const char *format, const char *msg, const int num);
void upro_log_timer(upro_log_t *log, const char *format, const char *msg, double timer, unsigned int nbytes, int loops);
void upro_log_print(upro_log_t *log);
#endif
