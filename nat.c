#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>  
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "nat_table.h"

/*
 * Callback function installed to netfilter queue
 */
static int Callback(struct nfq_q_handle *qh, struct nfgenmsg *msg, 
		struct nfq_data *pkt, void *data) {
        int i;
        unsigned int id = 0;
	struct nfqnl_msg_packet_hdr *header;
        struct nfqnl_msg_packet_hw *hwph;
        int accept[20]= {1,1,0,1,1,
                         1,1,1,1,1,
                         1,1,1,1,1,
                         1,1,0,0,1};

	// print hw_protocol, hook and id
        
        printf("\n");
	if ((header = nfq_get_msg_packet_hdr(pkt))) {
		id = ntohl(header->packet_id);
                printf("hw_protocol=0x%04x hook=%u id=%u ",
                        ntohs(header->hw_protocol), header->hook, id);
        }
	
	// print hw_address

         hwph = nfq_get_packet_hw(pkt);
         if (hwph) {
                 int i, hlen = ntohs(hwph->hw_addrlen);
                  printf("hw_src_addr=");
                 for (i = 0; i < hlen-1; i++)
                         printf("%02x:", hwph->hw_addr[i]);
                 printf("%02x ", hwph->hw_addr[hlen-1]);
         }

	// Print the payload; 
	
	printf("\n[");
	unsigned char *pktData;
	int len = nfq_get_payload(pkt, (char**)&pktData);
	if (len > 0) {
		for (i=0; i<len; i++) {
			printf("%02x ", pktData[i]);
		}
	}
	printf("]\n");

        // for the first 20 packeks, a packet[id] is accept, if 
        // accept[id-1] = 1.
        // All packets with id > 20, will be accepted

        if (id <= 20) {
	      if (accept[id-1]) {
                  printf("ACCEPT\n");
	          return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	      }
	      else {
		  printf("DROP\n");
	          return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	      }
	}
	else {
              printf("ACCEPT\n");
   	      return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
 	}

}

/*
 * Main program
 */
int main(int argc, char **argv){
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
        int len;
	char buf[4096];

	// Open library handle
	if (!(h = nfq_open())) {
		fprintf(stderr, "Error: nfq_open()\n");
		exit(-1);
	}

	// Unbind existing nf_queue handler (if any)
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "Error: nfq_unbind_pf()\n");
		exit(1);
	}

	// Bind nfnetlink_queue as nf_queue handler of AF_INET
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "Error: nfq_bind_pf()\n");
		exit(1);
	}

	// bind socket and install a callback on queue 0
	if (!(qh = nfq_create_queue(h,  0, &Callback, NULL))) {
		fprintf(stderr, "Error: nfq_create_queue()\n");
		exit(1);
	}

	// Setting packet copy mode
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "Could not set packet copy mode\n");
		exit(1);
	}

        fd = nfq_fd(h);

	while ((len = recv(fd, buf, sizeof(buf), 0)) && len >= 0) {
		nfq_handle_packet(h, buf, len);

	}

        printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

	nfq_close(h);

	return 0;

}

