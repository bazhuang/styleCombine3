#
#Makefile
# Created on: Nov 3, 2013
#     Author: zhiwenmizw
#

CC=gcc
CFLAGS= $(apr-1-config --cflags --cppflags --includes --link-ld) 

lib=../lib
conjoin_lib=../apache

INCLUDES=-I. -I${lib} -I${conjoin_lib} -I/usr/include/apr-1

StyleVersionUpdator: StyleVersionUpdator.o sc_conjoin.o sc_string.o sc_buffer.o sc_socket.o 
	${CC} -Wall StyleVersionUpdator.c ${INCLUDES} -o $@ $^ 

StyleVersionUpdator.o: StyleVersionUpdator.c
	${CC} -c $< ${INCLUDES} ${CFLAGS}

sc_buffer.o: ${lib}/sc_buffer.c
	${CC} -c $< ${INCLUDES} ${CFLAGS}

sc_string.o: ${lib}/sc_string.c
	${CC} -c $< ${INCLUDES} ${CFLAGS}

sc_socket.o: ${lib}/sc_socket.c
	${CC} -c $< ${INCLUDES} ${CFLAGS}
	
sc_conjoin.o: ${conjoin_lib}/sc_conjoin.c
	${CC} -c $< ${INCLUDES} ${CFLAGS}

clean:
	rm -f `find . -name \*.o -o -name \*.so -o -name \*~ -o -name \*.slo -o -name \*.lo -o -name \*.la -o -name \*.loT`
	rm -f `find ${lib}/ -name \*.o -o -name \*.so -o -name \*~ -o -name \*.slo -o -name \*.lo -o -name \*.la -o -name \*.loT`