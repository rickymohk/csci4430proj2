CC=gcc
CFLAGS=-Wall -I.
LDFLAGS=-lnfnetlink -lnetfilter_queue

EXE=nat

OBJ=nat.o nat_table.o checksum.o

${EXE}: ${OBJ}
	${CC} ${CFLAGS} -o ${EXE} ${OBJ} ${LDFLAGS}

test: test.o nat_table.o
	${CC} ${CFLAGS} -o test test.o nat_table.o ${LDFLAGS}

clean:
	rm -f ${EXE} ${OBJ}