ifeq ($(APXS),)
APXS=/Users/zhiwenmizw/pub/installed/httpd-2.2.15/bin/apxs
endif

# Note that gcc flags are passed through apxs, so preface with -Wc

MY_CFLAGS=-Wc,-Wc,-Wall,-O2

BASE_LIB_DIR=/Users/zhiwenmizw/pub/dev/workspace_c/styleCombine/styleCombine

LIB_DIR=$(BASE_LIB_DIR)/lib

INCLUDES=-I$(LIB_DIR) -I.

## ls -s *.h |awk '{print "$(LIB_DIR)/"$2" \\"}'
HEAD_FILES = sc_conjoin.h $(LIB_DIR)/sc_common.h $(LIB_DIR)/sc_buffer.h $(LIB_DIR)/sc_log.h $(LIB_DIR)/sc_linked_list.h $(LIB_DIR)/sc_mod_filter.h $(LIB_DIR)/sc_config.h $(LIB_DIR)/sc_combine.h $(LIB_DIR)/sc_html_parser.h $(LIB_DIR)/sc_socket.h $(LIB_DIR)/sc_string.h $(LIB_DIR)/sc_version.h

SOURCE_FILES = $(LIB_DIR)/sc_buffer.c $(LIB_DIR)/sc_linked_list.c $(LIB_DIR)/sc_mod_filter.c $(LIB_DIR)/sc_config.c $(LIB_DIR)/sc_combine.c $(LIB_DIR)/sc_html_parser.c $(LIB_DIR)/sc_socket.c $(LIB_DIR)/sc_version.c mod_styleCombine.c

mod_styleCombine.so: $(SOURCE_FILES) $(HEAD_FILES)
	$(APXS) -c $(INCLUDES) -o mod_styleCombine.so $(MY_CFLAGS) $(SOURCE_FILES)

install: mod_styleCombine.la
	$(APXS) -i $<

clean:
	rm -f `find $(BASE_LIB_DIR) -name \*.o -o -name \*.so -o -name \*~ -o -name \*.slo -o -name \*.lo -o -name \*.la -o -name \*.loT`
	rm -rf .libs
	rm -rf $(BASE_LIB_DIR)/.libs
