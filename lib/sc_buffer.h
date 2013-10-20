/*
 * sc_buffer.h
 *
 *  Created on: Oct 19, 2013
 *      Author: zhiwenmizw
 */

#ifndef SC_BUFFER_H_
#define SC_BUFFER_H_

#include "sc_common.h"

typedef struct {
	char       *ptr;
	long        used;
	long        size;
} Buffer;

#define SC_BUFFER_PIECE_SIZE                     128

#define SC_BUFFER_CLEAN(buffer) { \
	if(NULL != buffer) { \
		buffer->used = 0; buffer->ptr[0] = ZERO_END; \
 	} \
}

#define SC_IS_EMPTY_BUFFER(buf) (NULL == buf || 0 == buf->used)

#define SC_FREE(buf) if(NULL != buf) free(buf);

#define SC_PATH_SLASH(pathBuf) { \
	if(NULL != pathBuf && '/' != pathBuf->ptr[pathBuf->used - 1]) { \
		pathBuf->ptr[pathBuf->used++] = '/'; \
		pathBuf->ptr[pathBuf->used] = '\0'; \
	} \
}

#define SC_STRING_APPEND_BUFFER(pool, buf, tbuf) string_append(pool, buf, tbuf->ptr, tbuf->used)

/**
 * buffer的操作
 */
int prepare_buffer_size(sc_pool_t *pool, Buffer *buf, size_t in_size);

Buffer *buffer_init_size(sc_pool_t *pool, size_t in_size);

void string_append(sc_pool_t *pool, Buffer *buf, char *str, int strLen);

int putValueToBuffer(Buffer *buf, char *str);

#endif /* SC_BUFFER_H_ */
