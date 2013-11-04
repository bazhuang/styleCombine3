/*
 * sc_conjoin.h
 *
 *  Created on: Oct 18, 2013
 *      Author: zhiwenmizw
 */

#ifndef SC_CONJOIN_H_
#define SC_CONJOIN_H_

#include <string.h>
#include <pthread.h>

#include "apr_pools.h"
#include "apr_hash.h"

#define SC_THREAD_MUTEX_DEFAULT  0x0
#define SC_MD5_DIGESTSIZE 16

typedef apr_pool_t sc_pool_t;
typedef apr_thread_mutex_t sc_thread_mutex_t;

short sc_pool_create(sc_pool_t **newpool, sc_pool_t *parent);

void sc_pool_destroy(sc_pool_t *pool);

void *sc_palloc(sc_pool_t *pool, long size);

void *sc_pcalloc(sc_pool_t *pool, long size);

short sc_thread_mutex_create(sc_thread_mutex_t **mutex, unsigned int flags,
		apr_pool_t *pool);

short sc_thread_mutex_lock(sc_thread_mutex_t *mutex);

short sc_thread_mutex_unlock(sc_thread_mutex_t *mutex);

short sc_md5(unsigned char digest[SC_MD5_DIGESTSIZE], const void *input,
		size_t inputLen);

#endif /* SC_CONJOIN_H_ */
