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


