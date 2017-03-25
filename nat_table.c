#include "nat_table.h"
#include <stdio.h>
#include <stdlib.h>
//#include <unistd.h>


nat_t *nat_crate()
{
	nat_t *n = (nat_t *)malloc(sizeof(nat_t));
	memset(n,0,sizeof(nat_t));
	nat_entry **opt = (nat_entry **)malloc(sizeof(nat_entry *)*2048);
	memset(opt,0,sizeof(nat_entry *)*2048);
	n->out_port_table = opt;
	return n;
}

nat_entry *nat_insert(nat_t *nat, unsigned short port, unsigned long addr)
{
	int i;
	for(i=0;nat->out_port_table[i]!=NULL;i++);	//find first unused out_port;
	nat_entry *ne;
	nat_entry *parent;
	
	ne = nat->out_port_table[i] = (nat_entry *)malloc(sizeof(nat_entry));
	ne->local_addr = addr;
	ne->local_port = port;
	ne->out_port = i+10000;
	ne->next_addr = NULL;
	ne->next_port = NULL;	
	
	for(parent=nat;parent->next_addr!=NULL && parent->next_addr->local_addr!=addr;parent=parent->next_addr);	//find nat_entry of same ip
	if(parent->next_addr)	//existing nat_entry of same ip found
	{
		ne->next_port = parent->next_addr;
		parent->next_addr = ne;
		ne->next_addr = parent->next_addr->next_addr;
		ne->next_port->next_addr = NULL;
	}
	else				//no existing nat_entry have same ip
	{
		parent->next_addr = ne;
	}
	return ne;

}

nat_entry *nat_searchByLocal(nat_t *nat, unsigned short port, unsigned long addr)
{
	nat_entry *ne;
	for(ne=nat;ne!=NULL && ne->local_addr!=addr;ne=ne->next_addr);	//find nat_entry of same ip
	for(;ne!=NULL && ne->local_port!=port;ne=ne->next_port);		//find nat_entry of same port
	return ne;
}

nat_entry *nat_searchByOutPort(nat_t *nat, unsigned short port)
{
	return nat->out_port_table[port-10000];
}

void nat_expire(nat_t *nat, nat_entry *ne)
{
	nat_entry *parent;
	for(parent=nat;parent!=NULL && parent->next_addr!=NULL && parent->next_addr->local_addr!=ne->local_addr;parent=parent->next_addr);
	if(parent->next_addr!=ne)
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
	nat->out_port_table[ne->out_port-10000] = NULL;
	free(ne->next_addr);
	free(ne->next_port);
	free(ne);
}
