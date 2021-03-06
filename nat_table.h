typedef enum {ACTIVE,SFIN1,CACK1,CFIN2,SACK2,CFIN1,SACK1,SFIN2,CACK2} tcp_state_t;

typedef struct nat_entry_s
{
	unsigned short out_port;		//translated port
	unsigned short local_port;		//Internal port
	unsigned long local_addr;		//Internal IP
	tcp_state_t state;				//TCP state
	struct nat_entry_s *next_addr;	//point to entry of next ip addr
	struct nat_entry_s *next_port;	//point to entry of same ip with differnet port
}nat_entry;

typedef struct nat_s
{
	nat_entry **out_port_table;	//point to array of nat_entry * with out_port-10000 as index
	nat_entry *next_addr;				//point to first nat_entry *
}nat_t;

nat_t *nat_create();

nat_entry *nat_insert(nat_t *nat, unsigned long addr, unsigned short port);

nat_entry *nat_searchByLocal(nat_t *nat, unsigned long addr, unsigned short port);

nat_entry *nat_searchByOutPort(nat_t *nat, unsigned short port);

void nat_delete(nat_t *nat, nat_entry *ne);

void nat_dump(nat_t* nat, unsigned long public_addr);

void nat_print(nat_entry *ne, unsigned long public_addr);
