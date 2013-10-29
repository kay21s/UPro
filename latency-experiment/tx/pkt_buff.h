#ifndef _PKT_BUFF_H
#define _PKT_BUFF_H
#include <stdio.h>
#include <sys/types.h>

/*pcap file format*/
typedef struct pf_hdr {
	u_int32_t	 magic;
	u_int16_t	 version_major;
	u_int16_t	 tversion_minor;
	int32_t	 thiszone;  /* gmt to local correction */
	u_int32_t	 sigfigs; /* accuracy of timestamps */
	u_int32_t	 snaplen; /* max length saved portion of each pkt */
	u_int32_t	 linktype;   /* data link type (LINKTYPE_*) */
} pf_hdr_t;

typedef struct pcaprec_hdr_s {
	 u_int32_t	 ts_sec;         /* timestamp seconds */
	 u_int32_t	 ts_usec;        /* timestamp microseconds */
	 u_int32_t	 ncl_len;       /* number of octets of packet saved in file */
	 u_int32_t	 rig_len;       /* actual length of packet */
} p_hdr_t;

struct file_cache{
	char *fcache;
	unsigned long offset;
	unsigned long size;
	struct file_cache *next;
	/*pcap header*/
	pf_hdr_t hdr;
};

typedef struct file_cache 	file_cache_t;

extern u_char *prep_next_skb(file_cache_t *fct,u_int32_t *pktlen); 
extern int	 	check_pcap(file_cache_t *fct); 
extern void 	hex_printk(unsigned char *str,int len);
extern void 	release_pkt_buff_part(void);
extern file_cache_t*	preload_pcap_file(int queue_map);

#endif 
