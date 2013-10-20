/*
 * sc_buffer.c
 *
 *  Created on: Oct 19, 2013
 *      Author: zhiwenmizw
 */

#include "sc_buffer.h"
#include "sc_log.h"

/**
 * buffer的操作
 */
int prepare_buffer_size(sc_pool_t *pool, Buffer *buf, size_t in_size) {
	if (NULL == buf) {
		return 0;
	}
	int size = SC_ALIGN_DEFAULT(in_size);
	if (size < in_size) {
		return 0;
	}
	buf->ptr = (char *) sc_pcalloc(pool, size);
	if (NULL == buf->ptr) {
		return 0;
	}
	buf->size = size;
	return size;
}

Buffer *buffer_init_size(sc_pool_t *pool, size_t in_size) {
	Buffer *buf = (Buffer *) sc_palloc(pool, sizeof(Buffer));
	if (NULL == buf) {
		return buf;
	}
	buf->ptr = NULL;
	buf->used = 0;
	buf->size = 0;
	if (!prepare_buffer_size(pool, buf, in_size)) {
		return NULL;
	}
	return buf;
}

void string_append(sc_pool_t *pool, Buffer *buf, char *str, int strLen) {
	if(NULL == buf || NULL == str || strLen <= 0) {
		return;
	}
	if(0 == buf->size) {
		return;
	}
	if(buf->used + strLen >= buf->size) {
		char *data = buf->ptr;
		if(!prepare_buffer_size(pool, buf, buf->size + (strLen + SC_BUFFER_PIECE_SIZE))) {
			sc_log_error("realloc error[%d] [%s]===[%ld]", getpid(), str, buf->size);
			return;
		}
		memcpy(buf->ptr, data, buf->used);
	}
	memcpy(buf->ptr + buf->used, str, strLen);
	buf->used += strLen;
	buf->ptr[buf->used] = ZERO_END;
}

int putValueToBuffer(Buffer *buf, char *str) {
	if (NULL == buf || NULL == str) {
		return 0;
	}
	buf->ptr = str;
	buf->used = strlen(str);
	buf->size = buf->used;
	return 1;
}
