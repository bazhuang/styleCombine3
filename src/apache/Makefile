#
#Makefile
# Created on: Nov 3, 2013
#     Author: zhiwenmizw
#

# lowercase are commandline args (eg make apxs=/usr/sbin/apxs)

ifneq ($(apxs),)
APXS=$(apxs)
else
APXS=$(shell which apxs 2>/dev/null)
endif

ifeq ($(APXS),)
APXS=$(shell locate /bin/apxs|tail -1)
endif

# Note that gcc flags are passed through apxs, so preface with -Wc


#CFLAGS=-Wc,-Wall,-O2
CFLAGS=-DSC_HTTPD_PLATFORM

lib=../lib
INCLUDES=-I${lib} -I.

SOURCE_FILES=mod_styleCombine.c ${lib}/sc_conjoin.c ${lib}/sc_buffer.c ${lib}/sc_config.c ${lib}/sc_linked_list.c ${lib}/sc_socket.c ${lib}/sc_mod_filter.c ${lib}/sc_version.c ${lib}/sc_html_parser.c ${lib}/sc_combine.c ${lib}/sc_string.c ${lib}/sc_hash.c
HEAD_FILES=${lib}/sc_conjoin.h ${lib}/sc_common.h ${lib}/sc_buffer.h ${lib}/sc_config.h ${lib}/sc_linked_list.h ${lib}/sc_socket.h ${lib}/sc_mod_filter.h ${lib}/sc_version.h ${lib}/sc_html_parser.h ${lib}/sc_combine.h ${lib}/sc_string.h ${lib}/sc_log.h ${lib}/sc_hash.h 

mod_styleCombine.so: $(SOURCE_FILES) $(HEAD_FILES)
	$(APXS) -c $(INCLUDES) $(CFLAGS) -o mod_styleCombine.so $(SOURCE_FILES)

install: mod_styleCombine.la
	$(APXS) -i $<

clean:
	rm -rf .libs
	rm -f `find . -name \*.o -o -name \*.so -o -name \*~ -o -name \*.slo -o -name \*.lo -o -name \*.la -o -name \*.loT`
	rm -f `find ${lib}/ -name \*.o -o -name \*.so -o -name \*~ -o -name \*.slo -o -name \*.lo -o -name \*.la -o -name \*.loT`
