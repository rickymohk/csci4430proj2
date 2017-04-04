#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>  
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "nat_table.h"
#include "checksum.h"


struct cbarg
{
	unsigned long public_addr;
	unsigned long local_mask;
	unsigned long local_net;
	nat_t *nat;
};

void trans_out(struct iphdr *iph, struct tcphdr *tcph, unsigned long addr, unsigned short port)
{
	iph->saddr = htonl(addr);
	tcph->source = htons(port);
	iph->check = 0;
	tcph->check = 0;
	tcph->check = tcp_checksum((unsigned char *)iph);
	iph->check = ip_checksum((unsigned char *)iph);

}

void trans_in(struct iphdr *iph, struct tcphdr *tcph, unsigned long addr, unsigned short port)
{
	iph->daddr = htonl(addr);
	tcph->dest = htons(port);
	iph->check = 0;
	tcph->check = 0;
	tcph->check = tcp_checksum((unsigned char *)iph);
	iph->check = ip_checksum((unsigned char *)iph);
}
/*
 * Callback function installed to netfilter queue
 */
static int Callback(struct nfq_q_handle *qh, struct nfgenmsg *msg, struct nfq_data *pkt, struct cbarg *arg) 
{
    unsigned int id = 0;
	struct nfqnl_msg_packet_hdr *header;
	struct iphdr *iph;
	struct tcphdr *tcph;

	unsigned long public_addr = arg->public_addr;
	unsigned long local_mask = arg->local_mask;
	unsigned long local_net = arg->local_net;
	nat_t *nat = arg->nat;	

	int accept = 1;

	if ((header = nfq_get_msg_packet_hdr(pkt))) 
	{
		id = ntohl(header->packet_id);
        //printf("hw_protocol=0x%04x hook=%u id=%u \n",ntohs(header->hw_protocol), header->hook, id);
    }
    else
    {
    	fprintf(stderr,"Error getting packet header\n");
    }

	unsigned char *pktData;
	int len = nfq_get_payload(pkt, (unsigned char **)&pktData);
	if (len > 0) 
	{
		iph = (struct iphdr *)pktData;
		if(iph->protocol == IPPROTO_TCP)
		{
			//is tcp packet
			tcph = (struct tcphdr *)(((char *)iph)+(iph->ihl<<2));
			nat_entry *ne;
			if((ntohl(iph->saddr) & local_mask)==local_net)
			{
				//outbound packet
				if((ne = nat_searchByLocal(nat,ntohl(iph->saddr),ntohs(tcph->source))))
				{
					//Matched entry found
					trans_out(iph,tcph,public_addr,ne->out_port);
					if( ne->state==SFIN1 && (tcph->ack))
					{
						ne->state = CACK1;
					}
					if( ne->state==SFIN2 && (tcph->ack))
					{
						ne->state = CACK2;
					}

					if(tcph->fin)
					{
						//is FIN
						if(ne->state == ACTIVE)
						{
							ne->state = CFIN1;
						}
						else if(ne->state == CACK1)
						{
							ne->state =CFIN2;
						}
					}

				}
				else if(tcph->syn)
				{
					//is SYN
					ne = nat_insert(nat,ntohl(iph->saddr),ntohs(tcph->source));
					trans_out(iph,tcph,public_addr,ne->out_port);
					nat_dump(nat,public_addr);
				}
				else
				{
					accept = 0;
				}
			}
			else if((ne = nat_searchByOutPort(nat,ntohs(tcph->dest))))
			{
				//inbound packet
				trans_in(iph,tcph,ne->local_addr,ne->local_port);
				if( ne->state==CFIN1 && (tcph->ack))
				{
					ne->state = SACK1;
				}
				if( ne->state==CFIN2 && (tcph->ack))
				{
					ne->state = SACK2;
				}

				if(tcph->fin)
				{
					//is FIN
					if(ne->state == ACTIVE)
					{
						ne->state = SFIN1;
					}
					else if(ne->state == SACK1)
					{
						ne->state = SFIN2;
					}
				}

			}
			else
			{
				accept = 0;
			}

			if(ne && (ne->state==SACK2 || ne->state==CACK2 || (tcph->rst)))
			{
				nat_delete(nat,ne);
				nat_dump(nat,public_addr);
			}
		}
	}
	if (accept) 
	{
	    //printf("ACCEPT\n");
	    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
	else 
	{
		//printf("DROP\n");
	    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}

}


/*
 * Main program
 */
int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
//	struct nfnl_handle *nh;
	int fd;
    int len;
	char buf[4096];

	struct cbarg arg;
	struct in_addr public_ip;
	struct in_addr internal_ip;
	int mask_int;
	if(argc<4)
	{
		printf("usage: %s <public_ip> <internal ip> <subnet mask>\n",argv[0]);
		return 0;
	}
	if(!inet_pton(AF_INET,(const char *)argv[1],&public_ip))
	{
		fprintf(stderr,"Invalid public address\n");
		exit(-1);
	}
	if(!inet_pton(AF_INET,(const char *)argv[2],&internal_ip))
	{
		fprintf(stderr,"Invalid internal address\n");
		exit(-1);
	}
	mask_int=atoi(argv[3]);
	if(mask_int>32 || mask_int<0)
	{
		fprintf(stderr,"Invalid subnet mask\n");
		exit(-1);
	}
	arg.public_addr = public_ip.s_addr;
	arg.local_mask = 0xffffffff << (32 - mask_int);
	arg.local_net = internal_ip.s_addr & arg.local_mask;
	arg.nat = nat_create();

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
	if (!(qh = nfq_create_queue(h,  0, (nfq_callback *)&Callback, &arg))) {
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

    //printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

	nfq_close(h);

	return 0;

}

