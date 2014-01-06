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
	char         *ptr;
	size_t        used;
	size_t        size;
} Buffer;

#define SC_BUFFER_PIECE_SIZE                     128

#define SC_BUFFER_CLEAN(buffer) { \
	if(NULL != buffer) { \
		buffer->used = 0; buffer->ptr[0] = ZERO_END; \
 	} \
}

#define SC_IS_EMPTY_BUFFER(buf) (NULL == buf || 0 == buf->used)

#define SC_BUFF_FREE(buf) { \
	if(NULL != buf) { \
		if(NULL != buf->ptr) { \
			free(buf->ptr); \
			buf->ptr = NULL; \
		} \
		free(buf); \
	} \
}

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

void string_append(sc_pool_t *pool, Buffer *buf, char *str, size_t strLen);

#ifdef SC_HTTPD_PLATFORM
void string_append_content(Buffer *buf, char *str, size_t strLen);
#endif

short put_value_to_buffer(Buffer *buf, char *str);

#endif /* SC_BUFFER_H_ */
