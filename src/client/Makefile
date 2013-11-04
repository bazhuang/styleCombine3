#
#Makefile
# Created on: Nov 3, 2013
#     Author: zhiwenmizw
#


# lowercase are commandline args (eg make apr=/usr/bin/apr)

ifneq ($(apr),)
APR=$(apr)
else
APR=$(shell which apr-config 2>/dev/null)
endif

ifeq ($(APR),)
APR=$(shell which apr-1-config 2>/dev/null)
endif

CC=$(shell $(APR) --cc)
CFLAGS=$(shell $(APR) --cflags --cppflags --link-ld)
LIB=../lib
INCLUDES=$(shell $(APR) --includes) -I. -I${LIB}

StyleVersionUpdator: sc_conjoin.o sc_string.o sc_buffer.o sc_socket.o 
	${CC} -Wall StyleVersionUpdator.c -o $@ -g $(CFLAGS) $^ ${INCLUDES} 

StyleVersionUpdator.o: StyleVersionUpdator.c
	${CC} -c $< ${INCLUDES}

sc_buffer.o: ${LIB}/sc_buffer.c
	${CC} -c $< ${INCLUDES}
sc_string.o: ${LIB}/sc_string.c
	${CC} -c $< ${INCLUDES}
sc_socket.o: ${LIB}/sc_socket.c
	${CC} -c $< ${INCLUDES}
sc_conjoin.o: sc_conjoin.c
	${CC} -c $< ${INCLUDES}

clean:
	rm -f StyleVersionUpdator
	rm -rf *.dSYM
	rm -f `find . -name \*.o -o -name \*.so -o -name \*~ -o -name \*.slo -o -name \*.lo -o -name \*.la -o -name \*.loT`
	rm -f `find ${LIB}/ -name \*.o -o -name \*.so -o -name \*~ -o -name \*.slo -o -name \*.lo -o -name \*.la -o -name \*.loT`
	