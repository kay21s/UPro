#ifndef UPRO_JOB_H
#define UPRO_JOB_H

typedef struct upro_job_s
{
	int hdr_length;
	int pkt_length;
	char *hdr_ptr;
	char *pkt_ptr;
} upro_job_t;

#endif
