/*
 * sc_conjoin.c
 *
 *  Created on: Oct 24, 2013
 *      Author: zhiwenmizw
 */

#include "sc_conjoin.h"

void *sc_palloc(sc_pool_t *pool, long size) {
	return apr_palloc(pool, size);
}

void *sc_pcalloc(sc_pool_t *pool, long size) {
	return apr_pcalloc(pool, size);
}

short sc_thread_mutex_create(sc_thread_mutex_t **mutex, unsigned int flags, sc_pool_t *pool) {
	return apr_thread_mutex_create(mutex, flags, pool);
}

short sc_thread_mutex_lock(sc_thread_mutex_t *mutex) {
	return apr_thread_mutex_lock(mutex);
}

short sc_thread_mutex_unlock(sc_thread_mutex_t *mutex) {
	return apr_thread_mutex_unlock(mutex);
}

