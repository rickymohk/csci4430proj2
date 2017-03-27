#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "nat_table.h"

int main()
{
	nat_t *nat = nat_create();
	nat_insert(nat,12345678,8080);
	nat_insert(nat,12345678,8082);
	nat_insert(nat,12523163,8081);
	nat_insert(nat,8589934591,1235);
	nat_insert(nat,0xc0A80001,65535);
	nat_insert(nat,0xc0A80001,65534);
	nat_insert(nat,0xdddddddd,24);
	nat_dump(nat,0xaaaaaaaa);
	nat_entry *ne = nat_searchByLocal(nat,12345678,8082);
	nat_print(ne,0xaaaaaaaa);
	nat_delete(nat,ne);

	ne = nat_searchByOutPort(nat,10003);
	nat_print(ne,0xaaaaaaaa);
	nat_delete(nat,ne);
	nat_dump(nat,0xaaaaaaaa);

	nat_insert(nat,0xc0a80001,1001);
	nat_insert(nat,0xc0a80001,1002);
	nat_insert(nat,0xdddddddd,25);
	nat_dump(nat,0xaaaaaaaa);
	return 0;
}