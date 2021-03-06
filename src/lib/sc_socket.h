/*
 * sc_socket.h
 *
 *  Created on: Oct 19, 2013
 *      Author: zhiwenmizw
 */

#ifndef SC_SOCKET_H_
#define SC_SOCKET_H_

#include <sys/socket.h>
#include "sc_common.h"
#include "sc_buffer.h"

/* order DOES matter!!! */
enum DataProtocol {
        ERROR_PROTOCAL, 
        STYLE_UPDATOR_CHECK, 
        AMD_UPDATOR_CHECK, 
        STYLE_VERSION_GET, 
        AMD_VERSION_GET
};


typedef struct {
	int       protocol;
	int       length;
} HeadInfo;

void read_head_info(int socketFd, HeadInfo *headInfo);

Buffer *read_data(int socketFd, Buffer *buff, int length);

short write_data(int socketFd, enum DataProtocol protocolEM, char *data, size_t len);

Buffer *get_data(sc_pool_t *pool, enum DataProtocol protocol, void *data, size_t len);

#endif /* SC_SOCKET_H_ */
