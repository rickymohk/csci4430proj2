#include "nat_table.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

nat_t *nat_create()
{
	nat_t *n = (nat_t *)malloc(sizeof(nat_t));
	memset(n,0,sizeof(nat_t));
	nat_entry **opt = (nat_entry **)malloc(sizeof(nat_entry *)*2048);
	memset(opt,0,sizeof(nat_entry *)*2048);
	n->out_port_table = opt;
	return n;
}

nat_entry *nat_insert(nat_t *nat, unsigned long addr, unsigned short port)
{
	int i;
	for(i=0;nat->out_port_table[i]!=NULL;i++);	//find first unused out_port;
	nat_entry *ne;
	
	ne = nat->out_port_table[i] = (nat_entry *)malloc(sizeof(nat_entry));
	ne->local_addr = addr;
	ne->local_port = port;
	ne->out_port = i+10000;
	ne->next_addr = NULL;
	ne->next_port = NULL;	
	if(nat && nat->next_addr && nat->next_addr->local_addr!=addr)
	{
		nat_entry *parent;
		//find nat_entry of same ip
		for(parent=nat->next_addr;parent->next_addr!=NULL && parent->next_addr->local_addr!=addr;parent=parent->next_addr);	
		if(parent->next_addr)	//existing nat_entry of same ip found
		{
			ne->next_port = parent->next_addr;
			parent->next_addr = ne;
			ne->next_addr = ne->next_port->next_addr;
			ne->next_port->next_addr = NULL;
		}
		else				//no existing nat_entry have same ip
		{
			parent->next_addr = ne;
		}
	}
	else if(nat && nat->next_addr && nat->next_addr->local_addr==addr)
	{
		ne->next_port = nat->next_addr;
		nat->next_addr = ne;
		ne->next_addr = ne->next_port->next_addr;
		ne->next_port->next_addr = NULL;		
	}
	else if(nat)
	{
		nat->next_addr = ne;
	}
	else
	{
		perror("nat_insert(): invalid nat\n");
	}
	return ne;

}

nat_entry *nat_searchByLocal(nat_t *nat, unsigned long addr, unsigned short port)
{
	nat_entry *ne = NULL;
	if(nat && nat->next_addr)
		for(ne=nat->next_addr;ne!=NULL && ne->local_addr!=addr;ne=ne->next_addr);	//find nat_entry of same ip
	for(;ne!=NULL && ne->local_port!=port;ne=ne->next_port);		//find nat_entry of same port
	return ne;
}

nat_entry *nat_searchByOutPort(nat_t *nat, unsigned short port)
{
	if(nat && port>=10000 && port<=12000)
		return nat->out_port_table[port-10000];
	else
		return NULL;
}

void nat_delete(nat_t *nat, nat_entry *ne)
{
	nat_entry *parent = NULL;
	if(nat && nat->next_addr!=ne)
	{
		for(parent=nat->next_addr;parent!=NULL && parent->next_addr!=NULL && parent->next_addr->local_addr!=ne->local_addr;parent=parent->next_addr);
		if(parent && parent->next_addr!=ne)
			for(parent=parent->next_addr;parent!=NULL && parent->next_port!=ne;parent=parent->next_port);
		if(parent)
		{
			if(parent->next_addr==ne)
			{
				if(ne->next_port)
				{
					ne->next_port->next_addr = ne->next_addr;
					parent->next_addr = ne->next_port;
				}
				else
				{
					parent->next_addr = ne->next_addr;
				}
			}
			else if(parent->next_port==ne)
			{
				parent->next_port = ne->next_port;
			}
		}
	}
	else if(nat)
	{
		if(ne->next_port)
		{
			ne->next_port->next_addr = ne->next_addr;
			nat->next_addr = ne->next_port;
		}
		else
		{
			nat->next_addr = ne->next_addr;
		}
	}
	else
	{
		perror("nat_expire(): invalid nat\n");
	}
	nat->out_port_table[ne->out_port-10000] = NULL;
	free(ne);
}


void nat_dump(nat_t *nat)
{
	if(nat && nat->next_addr)
	{
		printf("Internal IP\t\tInternal port\tExternal port\n");
		nat_entry *ne;
		for(ne=nat->next_addr;ne!=NULL;ne=ne->next_addr)
		{
			nat_entry *tmp;
			for(tmp=ne;tmp!=NULL;tmp=tmp->next_port)
			{
				printf("%d.%d.%d.%d\t\t%d\t\t%d\n",(tmp->local_addr>>24)&0xff,(tmp->local_addr>>16)&0xff,(tmp->local_addr>>8)&0xff,tmp->local_addr&0xff,tmp->local_port,tmp->out_port);
			}

		}
	}
	else
	{
		printf("NAT is empty.\n");
	}
}

void nat_print(nat_entry *ne)
{	if(ne)
	{

		printf("Internal IP\t\tInternal port\tExternal port\n");
		printf("%d.%d.%d.%d\t\t%d\t\t%d\n",(ne->local_addr>>24)&0xff,(ne->local_addr>>16)&0xff,(ne->local_addr>>8)&0xff,ne->local_addr&0xff,ne->local_port,ne->out_port);
	
	}
}