/*
 * sc_common.h
 *
 *  Created on: Oct 19, 2013
 *      Author: zhiwenmizw
 */

#ifndef SC_COMMON_H_
#define SC_COMMON_H_

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "sc_conjoin.h"

#define STYLE_COMBINE_NAME                    "styleCombine"
#define STYLE_COMBINE_VS                      "3.0.0"

#define MODULE_BRAND                          STYLE_COMBINE_NAME STYLE_COMBINE_VS

#define SC_SOCKET_FILE_NAME                   "/tmp/SC_server_socket"
#define SC_MAX_STRING_LEN                     8192
#define DOMAINS_COUNT                         2
#define DEFAULT_CONTENT_LEN                   262144 //1024 << 8

static const char ZERO_END = '\0';

#define SC_ALIGN(size, boundary) \
    (((size) + ((boundary) - 1)) & ~((boundary) - 1))

#define SC_ALIGN_DEFAULT(size) SC_ALIGN(size, 8)

#endif /* SC_COMMON_H_ */
