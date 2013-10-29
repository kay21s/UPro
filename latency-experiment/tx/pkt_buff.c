#include "pkt_buff.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define QUEUE_NUM	8
#define FILE_CACHE_SIZE	(1024*1024*500) /*BYTE*/


char fname[QUEUE_NUM][256]={
	"rtp1.pcap",
	"rtp1.pcap",
	"rtp1.pcap",
	"rtp1.pcap",
	"rtp1.pcap",
	"rtp1.pcap",
	"rtp1.pcap",
	"rtp1.pcap",
#if 0
	"/home/kay/trace/fix_split0.pcap",
	"/home/kay/trace/fix_split1.pcap",
	"/home/kay/trace/fix_split2.pcap",
	"/home/kay/trace/fix_split3.pcap",
	"/home/kay/trace/fix_split4.pcap",
	"/home/kay/trace/fix_split5.pcap",
	"/home/kay/trace/fix_split6.pcap",
	"/home/kay/trace/fix_split7.pcap",
	"/home/kay/trace/split0.pcap",
	"/home/kay/trace/split1.pcap",
	"/home/kay/trace/split2.pcap",
	"/home/kay/trace/split3.pcap",
	"/home/kay/trace/split4.pcap",
	"/home/kay/trace/split5.pcap",
	"/home/kay/trace/split6.pcap",
	"/home/kay/trace/split7.pcap",
#endif
}; /*trace file*/

file_cache_t 					*file_cache_head=NULL;


void 	prep_skb(file_cache_t *fct,char** pdata); 
int 	check_pcap(file_cache_t *fct); 
void 	hex_printf(unsigned char *str,int len);
void 	release_pkt_buff_part(void);
file_cache_t*	preload_pcap_file(int queue_map);

#define FOFFSET(n) fct->offset+=n
#define TCPDUMP_MAGIC      0xa1b2c3d4 /*no swap, and tcpdump pcap format*/
/*
 *build next skb from buffer cache
 */
u_char *prep_next_skb(file_cache_t *fct,u_int32_t *pktlen)
{	
	if (fct == NULL) {
		printf("<1>no file buffer cache \n");return NULL;
	}
	/* if end */
	if (fct->offset == fct->size) 
		fct->offset = sizeof(pf_hdr_t);
	
	/*set packet data and hdr pointer,? no copy*/
	p_hdr_t *hdr = (p_hdr_t*)(fct->fcache + fct->offset);
	u_int32_t caplen = hdr->ncl_len; 
	FOFFSET(sizeof(p_hdr_t));
	u_char *pktdata = fct->fcache + fct->offset;
	FOFFSET(hdr->ncl_len);
	
	if (fct->offset > fct->size) {
		printf("<1>pcap file is not integrated\n");
		return NULL;
	}

	*pktlen = caplen;

	return pktdata;
}

int check_pcap(file_cache_t *fct)
{
	u_int32_t magic;
	memcpy(&magic, fct->fcache + fct->offset, sizeof(magic));
	FOFFSET(sizeof(magic));
	if (magic != TCPDUMP_MAGIC) {
		printf("<1> not a tcpdump file\n");
		return 0;
	}
	fct->hdr.magic = magic;

	memcpy(&(fct->hdr)+sizeof(magic), fct->fcache+fct->offset, sizeof(fct->hdr)-sizeof(magic));
	FOFFSET(sizeof(fct->hdr) - sizeof(magic));

	if (fct->offset >= fct->size) {
		printf("<1> not a complete pcap file\n");
		return 0;
	}
	return 1;
}

/*
 *one thread one trace 
 */
file_cache_t *preload_pcap_file(int queue_map)
{

	FILE	*fp;
	const char 		*fcache=NULL;
	unsigned long 	size; 
	file_cache_t 	*fct;
	char errbuf[256];

	fp = fopen(fname[queue_map], "r");

	if(fp != NULL) {

		fcache = malloc(FILE_CACHE_SIZE);
		if (fcache == NULL) {
			printf("<1> vmalloc file cache failed!\n");
			fclose(fp);
			return NULL;
		}

		if ((size = fread((void *)fcache, (size_t)1, (size_t)FILE_CACHE_SIZE, fp)) == 0) {
			free(fcache);
			printf("<1>kernel file read failed.\n");
			fclose(fp);
			return NULL;
		} else if (size == FILE_CACHE_SIZE){
			free(fcache);
			fclose(fp);
			printf("<1>file cache size is not enough to buffer file\n");
			return NULL;
		} else {
			printf("<1>loading %ld BYTE size from trace\n",size);
		}

		fclose(fp);

	} else {
		printf("<1>fopen failed!\n");
		return NULL;
	}

	/*save malloc pointer for vfree*/
	fct = malloc(sizeof(file_cache_t));
	memset(fct, 0, sizeof(file_cache_t));

	if (file_cache_head == NULL) {
		fct->next = NULL;
		fct->size = size;
		fct->fcache = fcache;
		file_cache_head = fct;
	} else {
		fct->next = file_cache_head;
		fct->fcache = fcache;
		fct->size = size;
		file_cache_head = fct;
	}
	/* avoid warning in compliation*/
	if (errbuf[0] != 0);
	return fct;
}

void release_pkt_buff_part(){

	/*free vmalloc buffer cache*/
	file_cache_t *fct=file_cache_head;
	file_cache_t *next=file_cache_head->next;
	while(fct!=NULL) {
		free(fct->fcache);
		free(fct);
		fct=next;
		if(next!=NULL)
			next=next->next;
	}

	printf("<1>buffer cache free done!\n");
	return ;
}

void hex_printf(unsigned char *str,int len){

	int times=len/16;
	int last=len%16;
	unsigned char *p=str;
	int i=0;
	for(i=0;i<times;i++){
		printf("<1>data:%2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x\n", \
			p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7],p[8],p[9],p[10],p[11],p[12],p[13],p[14],p[15]);
		p+=16;
	}
	printf("<1>remained %d data have been shown\n",last);

}
