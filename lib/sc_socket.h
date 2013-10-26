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

enum DataProtocol {
	ERROR_PROTOCAL, UPDATOR_CHECK, VERSION_GET
};

typedef struct {
	int       protocol;
	int       length;
} HeadInfo;

void readHeadInfo(int socketFd, HeadInfo *headInfo);

Buffer *readData(int socketFd, Buffer *buff, int length);

short writeData(int socketFd, enum DataProtocol protocolEM, char *data, size_t len);

Buffer *getData(sc_pool_t *pool, enum DataProtocol protocol, void *data, size_t len);

#endif /* SC_SOCKET_H_ */
