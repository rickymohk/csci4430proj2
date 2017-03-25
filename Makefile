all:
	gcc -o nftest nftest.c -lnfnetlink -lnetfilter_queue

clean:
	@rm -f nftest
