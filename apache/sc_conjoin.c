/*
 * sc_conjoin.c
 *
 *  Created on: Oct 24, 2013
 *      Author: zhiwenmizw
 */

#include <regex.h>

#include "sc_conjoin.h"
#include "sc_string.h"
#include "apr_strings.h"

short sc_pool_create(sc_pool_t **newpool, sc_pool_t *parent) {
	return apr_pool_create_ex(newpool, parent, NULL, NULL);
}

void sc_pool_destroy(sc_pool_t *pool) {
	apr_pool_destroy(pool);
}

void *sc_palloc(sc_pool_t *pool, long size) {
	return apr_palloc(pool, size);
}

void *sc_pcalloc(sc_pool_t *pool, long size) {
	return apr_pcalloc(pool, size);
}

short sc_thread_mutex_create(sc_thread_mutex_t **mutex, unsigned int flags,
		sc_pool_t *pool) {
	return apr_thread_mutex_create(mutex, flags, pool);
}

short sc_thread_mutex_lock(sc_thread_mutex_t *mutex) {
	return apr_thread_mutex_lock(mutex);
}

short sc_thread_mutex_unlock(sc_thread_mutex_t *mutex) {
	return apr_thread_mutex_unlock(mutex);
}

short sc_md5(unsigned char digest[SC_MD5_DIGESTSIZE], const void *input,
		size_t inputLen) {
	return sc_md5(digest, input, inputLen);
}
