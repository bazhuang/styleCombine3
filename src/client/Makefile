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

ifneq ($(apu),)
APU=$(apu)
else
APU=$(shell which apu-config 2>/dev/null)
endif

ifeq ($(APU),)
APU=$(shell which apu-1-config 2>/dev/null)
endif

CC=$(shell $(APR) --cc)
CFLAGS_APR=$(shell $(APR) --cflags --cppflags --link-ld)
CFLAGS_APU=$(shell $(APU) --link-ld --libs)
CFLAGS_PLATFORM=-DSC_HTTPD_PLATFORM
LIB=../lib
INCLUDES=$(shell $(APR) --includes) -I. -I${LIB}

StyleVersionUpdator: sc_conjoin.o sc_string.o sc_buffer.o sc_socket.o 
	${CC} -Wall StyleVersionUpdator.c -o $@ -g $^ $(CFLAGS_APR) $(CFLAGS_APU) \
		$(CFLAGS_PLATFORM) ${INCLUDES} 

StyleVersionUpdator.o: StyleVersionUpdator.c
	${CC} -c $< ${INCLUDES} $(CFLAGS_APR) $(CFLAGS_PLATFORM)

sc_buffer.o: ${LIB}/sc_buffer.c
	${CC} -c $< ${INCLUDES} $(CFLAGS_APR) $(CFLAGS_PLATFORM)
sc_string.o: ${LIB}/sc_string.c
	${CC} -c $< ${INCLUDES} $(CFLAGS_APR) $(CFLAGS_PLATFORM)
sc_socket.o: ${LIB}/sc_socket.c
	${CC} -c $< ${INCLUDES} $(CFLAGS_APR) $(CFLAGS_PLATFORM)
sc_conjoin.o:${LIB}/sc_conjoin.c
	${CC} -c $< ${INCLUDES} $(CFLAGS_APR) $(CFLAGS_PLATFORM)

clean:
	rm -f StyleVersionUpdator
	rm -rf *.dSYM
	rm -f `find . -name \*.o -o -name \*.so -o -name \*~ -o -name \*.slo -o -name \*.lo -o -name \*.la -o -name \*.loT`
	rm -f `find ${LIB}/ -name \*.o -o -name \*.so -o -name \*~ -o -name \*.slo -o -name \*.lo -o -name \*.la -o -name \*.loT`
	
