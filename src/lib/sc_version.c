/*
 * sc_version.c
 *
 *  Created on: Oct 19, 2013
 *      Author: zhiwenmizw
 */

#include <time.h>
#include <stdlib.h>

#include "sc_version.h"
#include "sc_socket.h"
#include "sc_log.h"
#include "sc_hash.h"

void check_version_update(sc_pool_t *server_pool, sc_pool_t *req_pool, GlobalVariable *globalVariable) {
	time_t currentSec;
	time(&currentSec);
	//每隔20秒 将重新去执行加载版本信息，为了减少过多的版本信息检查带来性能开销
	if(0 != globalVariable->prevTime && (currentSec - globalVariable->prevTime) <= 20) {
		return;
	}

#ifndef SC_NGINX_PLATFORM
	sc_thread_mutex_lock(globalVariable->intervalCheckLock);
	if(0 != globalVariable->prevTime && (currentSec - globalVariable->prevTime) <= 20) {
		sc_thread_mutex_unlock(globalVariable->intervalCheckLock);
		return;
	}
#endif

	globalVariable->prevTime = currentSec;
#ifndef SC_NGINX_PLATFORM
	sc_thread_mutex_unlock(globalVariable->intervalCheckLock);
#endif

	//socket updator_check
	Buffer *data = get_data(req_pool, UPDATOR_CHECK, NULL, 0);
	if(SC_IS_EMPTY_BUFFER(data)) {
		return;
	}
	long newVsTime = atol(data->ptr);

	if(globalVariable->pConfig->printLog == LOG_VERSION_UPDATE) {
		sc_log_debug(LOG_VERSION_UPDATE, "version time equals local=[%ld] vs [%ld]", globalVariable->upateTime, newVsTime);
	}

	if(globalVariable->upateTime == newVsTime) {
		return;
	}
	/**
	 * 创建一个新的内存池来创建一个hashtable，用于存放所有的k,v。
	 * 并且将老的内存池和hashtable释放掉。
	 */
	sc_pool_t *newPool = NULL;
	sc_pool_create(&newPool, server_pool);
	if(NULL == newPool) {
		return;
	}
	globalVariable->newPool = newPool;
	sc_hash_t *newHtable  = sc_hash_make(newPool);
    if ( !newHtable ) {
        // alloc memory faild 
        return ;
    }
	globalVariable->styleVersionTable = newHtable;

	if(NULL != globalVariable->oldPool) {
		sc_pool_destroy(globalVariable->oldPool);
	}
	globalVariable->oldPool    = newPool;
	globalVariable->upateTime  = newVsTime;
	return;
}

static Buffer *get_if_null_and_put(Buffer *styleUri, GlobalVariable *globalVariable) {

	if(NULL == globalVariable->styleVersionTable) {
		sc_log_error("styleVersionTable is NULL or not Ready!");
		return NULL;
	}
	//先在当前的hash表里查询，查到了直接返回 。 没有查到再从网络获取，获取到后写入hash表中
	Buffer *buf = (Buffer *) sc_hash_get(globalVariable->styleVersionTable, styleUri->ptr, styleUri->used);
	if(NULL != buf) {
		return buf;
	}

#ifndef SC_NGINX_PLATFORM
	//写数据时锁住hash列表，避免多线程安全
	sc_thread_mutex_lock(globalVariable->getDataLock);
#endif
	buf = (Buffer *) sc_hash_get(globalVariable->styleVersionTable, styleUri->ptr, styleUri->used);
	if(NULL != buf) {
#ifndef SC_NGINX_PLATFORM
		sc_thread_mutex_unlock(globalVariable->getDataLock);
#endif
		return buf;
	}
	Buffer *data = get_data(globalVariable->newPool, VERSION_GET, styleUri->ptr, styleUri->used);
	if(!SC_IS_EMPTY_BUFFER(data)) {
		char *key = sc_pstrmemdup(globalVariable->newPool, styleUri->ptr, styleUri->used);
		sc_hash_set(globalVariable->styleVersionTable, key, styleUri->used, data);
	}
	if(globalVariable->pConfig->printLog == LOG_GET_VERSION) {
		sc_log_debug(LOG_GET_VERSION, "pid=%d get version URL [%s][%ld] vs[%s]", getpid(), styleUri->ptr, styleUri->used, ((NULL == data) ? "" : data->ptr));
	}
#ifndef SC_NGINX_PLATFORM
	sc_thread_mutex_unlock(globalVariable->getDataLock);
#endif
	return data;
}

Buffer *get_string_version(sc_pool_t *pool, char *uri, Buffer *styleUri, GlobalVariable *globalVariable) {
	Buffer *versionBuf = get_if_null_and_put(styleUri, globalVariable);
	if(SC_IS_EMPTY_BUFFER(versionBuf) || 1 == versionBuf->used) {
		sc_log_error("pid=%d styleCombine=can't getVersion:ReqURI:[%s]==>StyleURI:[%s]", getpid(), uri, styleUri->ptr);
		time_t currentSec;
		time(&currentSec);
		versionBuf     = buffer_init_size(pool, 64);
		//build a dynic version in 6 minutes
		snprintf(versionBuf->ptr, versionBuf->size, "%ld", (currentSec / 300));
		versionBuf->used = strlen(versionBuf->ptr);
	}
	return versionBuf;
}

void make_md5_version(sc_pool_t *pool, Buffer *buf, Buffer *versionBuf) {
	string_append(pool, buf, "?_v=", 4);
	if(!SC_IS_EMPTY_BUFFER(versionBuf)) {
		if(versionBuf->used > 32) {
			char md5[3];
			unsigned char digest[16];
			sc_md5(digest, (const void *)versionBuf->ptr, versionBuf->used);
			SC_BUFFER_CLEAN(versionBuf);
			int i = 0;
			for(i = 0; i < 16; i++) {
				snprintf(md5, 3, "%02x", digest[i]);
				string_append(pool, versionBuf, md5, 2);
			}
		}
		SC_STRING_APPEND_BUFFER(pool, buf, versionBuf);
	}
}
