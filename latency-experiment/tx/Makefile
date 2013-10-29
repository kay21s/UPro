LIBS = -lpsio -lnuma -lrt
LIB_DIR = -L../../lib

.PHONY: clean

all: tx

tx: tx.c pkt_buff.c
	gcc -g -Wall -o tx tx.c pkt_buff.c $(LIB_DIR) $(LIBS)

clean:
	rm -f tx
