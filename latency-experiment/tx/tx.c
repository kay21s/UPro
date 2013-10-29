#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define __USE_GNU

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sched.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include <sys/wait.h>
#include <sys/time.h>
#include "pkt_buff.h"
#include <numa.h>

#include "../../include/psio.h"

#define PS_MAX_CPUS 8

int sleep_time;

int num_devices;
struct ps_device devices[PS_MAX_DEVICES];

int num_devices_attached;
int devices_attached[PS_MAX_DEVICES];

struct ps_handle handles[PS_MAX_CPUS];

int my_cpu;

struct timeval startime;
struct timeval endtime;
uint64_t total_packets = 0;

int get_num_cpus()
{
	return sysconf(_SC_NPROCESSORS_ONLN);
}

int bind_cpu(int cpu)
{
	cpu_set_t *cmask;
	struct bitmask *bmask;
	cpu_set_t mask;
	size_t n;
	int ret;

	n = get_num_cpus();

        if (cpu < 0 || cpu >= (int)n) {
		errno = -EINVAL;
		return -1;
	}

	CPU_ZERO(&mask);
	CPU_SET(cpu, &mask);

	ret = sched_setaffinity(0, sizeof(cpu_set_t), &mask);

	cmask = CPU_ALLOC(n);
	if (cmask == NULL)
		return -1;

        CPU_ZERO_S(n, cmask);
        CPU_SET_S(cpu, n, cmask);

        ret = sched_setaffinity(0, n, cmask);

	CPU_FREE(cmask);

	/* skip NUMA stuff for UMA systems */
	if (numa_max_node() == 0)
		return ret;

	bmask = numa_bitmask_alloc(16);
	assert(bmask);

	numa_bitmask_setbit(bmask, cpu % 2);
	numa_set_membind(bmask);
	numa_bitmask_free(bmask);

	return ret;
}

void print_usage(char *argv0)
{
	fprintf(stderr, "Usage: %s <interface to echo> <...>",
			argv0);

	exit(2);
}

void parse_opt(int argc, char **argv)
{
	int i, j;

	if (argc < 2)
		print_usage(argv[0]);

	for (i = 1; i < argc; i++) {
		int ifindex = -1;

		for (j = 0; j < num_devices; j++) {
			if (strcmp(argv[i], devices[j].name) != 0)
				continue;

			ifindex = devices[j].ifindex;
			break;
		}

		if (ifindex == -1) {
			fprintf(stderr, "Interface %s does not exist!\n", argv[i]);
			exit(4);
		}

		for (j = 0; j < num_devices_attached; j++) {
			if (devices_attached[j] == ifindex)
				goto already_attached;
		}

		devices_attached[num_devices_attached] = ifindex;
		num_devices_attached++;

already_attached:
		;
	}

	assert(num_devices_attached > 0);
}

void handle_signal(int signal)
{
	struct ps_handle *handle = &handles[my_cpu];

	uint64_t total_tx_packets = 0;
	uint64_t total_tx_bytes = 0;

	int i;
	int ifindex;

	struct timeval subtime;

	gettimeofday(&endtime, NULL);
	timersub(&endtime, &startime, &subtime);

	usleep(10000 * (my_cpu + 1));

	assert (num_devices_attached == 1);
	for (i = 0; i < num_devices_attached; i++) {
		ifindex = devices_attached[i];
		total_tx_packets += handle->tx_packets[ifindex];
		total_tx_bytes += handle->tx_bytes[ifindex];
	}

	printf("----------\n");
    /*
	printf("CPU %d: %ld packets transmitted, elapse time : %lds, Send Speed : %lf Mpps, %5.2f Gbps, Aveage Len. = %ld\n", 
			my_cpu, total_tx_packets, subtime.tv_sec, 
			(double)(total_tx_packets) / (double) (subtime.tv_sec*1000000+subtime.tv_usec),
			(double)(total_tx_bytes*8) / (double) ((subtime.tv_sec*1000000+subtime.tv_usec) * 1000),
			total_tx_bytes/total_tx_packets);
*/
	printf("CPU %d: %ld packets transmitted, elapse time : %lds, Send Speed : %lf Mpps, %5.2f Gbps, Aveage Len. = %ld\n", 
			my_cpu, total_packets, subtime.tv_sec, 
			(double)(total_packets) / (double) (subtime.tv_sec*1000000+subtime.tv_usec),
			(double)(total_packets * 1370 *8) / (double) ((subtime.tv_sec*1000000+subtime.tv_usec) * 1000),
			1370);
	
	for (i = 0; i < num_devices_attached; i++) {
		char *dev = devices[devices_attached[i]].name;
		ifindex = devices_attached[i];

		if (handle->tx_packets[ifindex] == 0)
			continue;

		printf("  %s: ", dev);
		
		printf("TX %ld packets "
				"(%ld chunks, %.2f packets per chunk)\n", 
				handle->tx_packets[ifindex],
				handle->tx_chunks[ifindex],
				handle->tx_packets[ifindex] / 
				  (double)handle->tx_chunks[ifindex]);
	}

	exit(0);
}

int packet_write(void *ptr, int length, FILE *fd)
{
    int i;
    for (i = 0; i < length/4 + 1; i ++) {
        fprintf(fd, "%x ", ((int *)ptr)[i]);
        if (i % 16 == 0) {
            fprintf(fd, "\n");
        }
    }
    return 0;
}

void echo()
{
	struct ps_handle *handle = &handles[my_cpu];
	struct ps_chunk chunk;
	file_cache_t *fct;
	unsigned int pktlen;
	u_char *pktdata;

	int i;
	int working = 0;


	assert(ps_init_handle(handle) == 0);
	assert(ps_alloc_chunk(handle, &chunk) == 0);

	assert(num_devices_attached == 1);

/*
	for (i = 0; i < num_devices_attached; i++) {
		working = 1;
		chunk.queue.ifindex = devices_attached[i];
		chunk.queue.qidx = my_cpu;
        printf("attach ifindex : %d\n", devices_attached[i]);

		printf("attaching RX queue xge%d:%d to CPU%d\n", chunk.queue.ifindex, chunk.queue.qidx, my_cpu);
		assert(ps_attach_rx_device(handle, &(chunk.queue)) == 0);
	}

	if (!working)
		goto done;
*/

	//Preload pcap file --Kay
	if ((fct = preload_pcap_file(my_cpu)) != NULL) {
		//printf("Loading done, core %d\n", my_cpu);
		if (!check_pcap(fct))
			printf("It is not trace file, core %d\n", my_cpu);
	} else {
		printf("Loading failed, core %d\n", my_cpu);
	}



    char *ip;
    struct timeval start, end;
    struct timespec test;
    double diff;
    unsigned int this_packets = 0;
    int ctr = 1;
    int mark = 0;

	chunk.cnt = 128; // Change this chunk size to improve TX performance --Kay
	chunk.recv_blocking = 1;
    chunk.queue.ifindex = devices_attached[0];
	chunk.queue.qidx = my_cpu;

	pktdata = prep_next_skb(fct, &pktlen);
    pktlen = 1370;

	gettimeofday(&startime, NULL);
	for (;;) {
		// 20G, 2*4 -> usleep(50)
		usleep(sleep_time);
        gettimeofday(&start,NULL);
        chunk.cnt = 128; // Change this chunk size to improve TX performance --Kay
        chunk.recv_blocking = 1;
// ===========================================================
		for (i = 0; i < chunk.cnt; i++) {
			chunk.info[i].offset = i * PS_MAX_PACKET_SIZE;
			chunk.info[i].len = pktlen;
            
            ip = pktdata + 26;
            *(uint32_t *)ip = *(uint32_t *)ip + 1;
            ip = pktdata + 30;
            *(uint32_t *)ip = *(uint32_t *)ip + 1;


			memcpy_aligned(chunk.buf + chunk.info[i].offset,
							pktdata,
							pktlen);
            
            if (ctr % 5000 == 0) {
                *((int *)(chunk.buf+chunk.info[i].offset + 44)) = mark;

                clock_gettime(CLOCK_MONOTONIC, &test);
                uint64_t a = test.tv_sec * 1000000 + test.tv_nsec / 1000;
                printf("%d %ld\n", mark, a);

                /*
                packet_write(chunk.buf + chunk.info[i].offset, chunk.info[i].len, fd);
                fprintf(fd, "\n--------------%d++%d\n\n", mark, *((int *)(chunk.buf +chunk.info[i].offset + 42)));
                */

                mark ++;
            }
            ctr ++;
		}

// ===========================================================
		int ret = ps_send_chunk(handle, &chunk);
		assert(ret >= 0);
        total_packets += ret;

        //if (total_packets == 256) break;
	}

done:
	ps_close_handle(handle);
}


int main(int argc, char **argv)
{
	int num_cpus = 4;
	int i=0;

    sleep_time = atoi(argv[2]);
    argc = 2;

	num_cpus = get_num_cpus();
	assert(num_cpus >= 1);

	num_devices = ps_list_devices(devices);
	if (num_devices == -1) {
		perror("ps_list_devices");
		exit(1);
	}

	parse_opt(argc, argv);

	for (i = 0; i < num_cpus; i ++) {
//        int ret = fork();
//      assert(ret >= 0);

		my_cpu = i;

	    bind_cpu(i);
		signal(SIGINT, handle_signal);
			
		echo();
		return 0;

	}

	signal(SIGINT, SIG_IGN);

	while (1) {
		int ret = wait(NULL);
		if (ret == -1 && errno == ECHILD)
			break;

	}
}
