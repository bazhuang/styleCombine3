/*
 * sc_socket.c
 *
 *  Created on: Oct 19, 2013
 *      Author: zhiwenmizw
 */

#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "sc_log.h"
#include "sc_socket.h"

void readHeadInfo(int socketFd, HeadInfo *headInfo) {
	int bytes = read(socketFd, headInfo, sizeof(HeadInfo));
	if (-1 == bytes) {
		sc_log_error("NET socket read error [%s]", strerror(errno));
		return;
	}
	sc_log_debug(LOG_NET_READ, "NET readed HeadInfo bytes=[%d] p=[%d] len=[%d]", bytes, headInfo->protocol, headInfo->length);
}

Buffer *readData(int socketFd, Buffer *buff, int length) {
	int bytes = 0;
	if(-1 == (bytes = read(socketFd, buff->ptr, length))) {
		sc_log_error("NET socket read error [%s]", strerror(errno));
		return NULL;
	}
	buff->used            = bytes;
	buff->ptr[buff->used] = ZERO_END;
	sc_log_debug(LOG_NET_READ, "NET readed Data bytes=[%d] data=[%s]", bytes, buff->ptr);
	return buff;
}

short writeData(int socketFd, enum DataProtocol protocolEM, char *data, size_t len) {
	HeadInfo headInfo;
	headInfo.protocol = (int) protocolEM;
	headInfo.length   = len;
	if(len <= 0) {
		headInfo.length   = 1;
	}
	int bytes = 0;
	if(-1 == (bytes = write(socketFd, &headInfo, sizeof(HeadInfo)))) {
		sc_log_error("NET write headInfo error %s", strerror(errno));
		return -1;
	}
	sc_log_debug(LOG_NET_WRITE, "NET writed headInfo p=[%d] len=[%d] bytes=[%d]", headInfo.protocol, headInfo.length, bytes);
	if(NULL == data || len <= 0) {
		if(-1 == (bytes = write(socketFd, "0", 1))) {
			sc_log_error("NET write NULL data error %s", strerror(errno));
			return -1;
		}
		return 0;
	}
	if(-1 == (bytes = write(socketFd, data, len))) {
		sc_log_error("NET write %s error %s", data, strerror(errno));
		return -1;
	}
	sc_log_debug(LOG_NET_WRITE, "NET writed Data bytes=[%d] data=[%s]", bytes, data);
	return 0;
}

Buffer *getData(sc_pool_t *pool, enum DataProtocol protocol, void *data, size_t len) {
	int socketFd  = 0;
	if (-1 == (socketFd = socket(AF_UNIX, SOCK_STREAM, 0))) {
		sc_log_error("create socket error [%s]", strerror(errno));
		return NULL;
	}
	struct sockaddr_un        address;
	address.sun_family      = AF_UNIX;
	strcpy(address.sun_path, SC_SOCKET_FILE_NAME);
	if(-1 == connect(socketFd, (struct sockaddr *) &address, sizeof(address))) {
		close(socketFd);
		sc_log_error("create connect error [%s][%s]", address.sun_path, strerror(errno));
		return NULL;
	}

	if(-1 == writeData(socketFd, protocol, data, len)) {
		return NULL;
	}

	HeadInfo                headInfo;
	readHeadInfo(socketFd, &headInfo);

	if(ERROR_PROTOCAL == headInfo.protocol) {
		sc_log_error("getData but Result is errorCode %s %ld", data, len);
		return NULL;
	}

	Buffer *result     = buffer_init_size(pool, headInfo.length + 1);
	readData(socketFd, result, headInfo.length);

	close(socketFd);
	return result;
}
