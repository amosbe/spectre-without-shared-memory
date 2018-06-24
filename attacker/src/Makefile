LIB=libmastik.a
LIBSRCS=vlist.c l3.c timestats.c  util.c 
LIBOBJS=${LIBSRCS:.c=.o}
VERSION=$(shell cut -f 1 -d \  ../VERSION)

all: ${LIB} ${TARGETS}

include LocalMakefile



CFLAGS=-g -std=gnu99 -O2 -DNDEBUG ${EXTRA_CFLAGS} 





${LIB}:${LIBOBJS}
	ar crv ${LIB} ${LIBOBJS}
	ranlib ${LIB}

l3.o: l3.h vlist.h timestats.h low.h config.h

vlist.o: vlist.h config.h

timestats.o: timestats.h config.h


LocalMakefile:
	touch LocalMakefile

clean:
	rm -f ${LIB} ${LIBOBJS}

distclean: clean
	rm Makefile config.h
