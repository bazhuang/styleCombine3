/*
 * sc_conjoin.h
 *
 *  Created on: Oct 18, 2013
 *      Author: zhiwenmizw
 */

#ifndef SC_CONJOIN_H_
#define SC_CONJOIN_H_

#include <string.h>

#include "apr_pools.h"
#include "apr_hash.h"
#include "apr_thread_mutex.h"

typedef apr_pool_t   sc_pool_t;
typedef apr_hash_t   sc_hash_t;

typedef apr_thread_mutex_t sc_thread_mutex_t;

void *sc_palloc(sc_pool_t *pool, long size);

void *sc_pcalloc(sc_pool_t *pool, long size);

#endif /* SC_CONJOIN_H_ */
