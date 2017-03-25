test:
	gcc -o test test.c nat_table.c

all:
	gcc -o nftest nftest.c -lnfnetlink -lnetfilter_queue

clean:
	@rm -f nftest
