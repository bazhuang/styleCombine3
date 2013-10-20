/*
 * sc_version.c
 *
 *  Created on: Oct 19, 2013
 *      Author: zhiwenmizw
 */

#include "sc_version.h"

void checkVersionUpdate(sc_pool_t *server_pool, sc_pool_t *req_pool, GlobalVariable *globalVariable) {
	time_t currentSec;
	time(&currentSec);
	//每隔20秒 将重新去执行加载版本信息，为了减少过多的版本信息检查带来性能开销
	if(0 != globalVariable.prevTime && (currentSec - globalVariable.prevTime) <= 20) {
		return;
	}

	apr_thread_mutex_lock(globalVariable.intervalCheckLock);
	if(0 != globalVariable.prevTime && (currentSec - globalVariable.prevTime) <= 20) {
		apr_thread_mutex_unlock(globalVariable.intervalCheckLock);
		return;
	}
	globalVariable.prevTime = currentSec;
	apr_thread_mutex_unlock(globalVariable.intervalCheckLock);

	//socket updator_check
	Buffer *data = getData(req_pool, UPDATOR_CHECK, NULL, 0);
	if(SC_IS_EMPTY_BUFFER(data)) {
		return;
	}
	long newVsTime = atol(data->ptr);

	if(IS_LOG_ENABLED(LOG_VERSION_UPDATE)) {
		sc_log_debug(LOG_VERSION_UPDATE, "version time equals local=[%ld] vs [%ld]", globalVariable.upateTime, newVsTime);
	}

	if(globalVariable.upateTime == newVsTime) {
		return;
	}
	/**
	 * 创建一个新的内存池来创建一个hashtable，用于存放所有的k,v。
	 * 并且将老的内存池和hashtable释放掉。
	 */
	sc_pool_t *newPool = NULL;
	apr_pool_create(&newPool, server_pool);
	if(NULL == newPool) {
		return;
	}
	globalVariable.newPool = newPool;
	apr_hash_t *newHtable  = apr_hash_make(newPool);
	globalVariable.styleVersionTable = newHtable;

	if(NULL != globalVariable.oldPool) {
		apr_pool_destroy(globalVariable.oldPool);
	}
	globalVariable.oldPool    = newPool;
	globalVariable.upateTime  = newVsTime;
	return;
}

static Buffer *getAndPut(Buffer *styleUri, GlobalVariable *globalVariable) {
	if(NULL == globalVariable.styleVersionTable) {
		sc_log_error("styleVersionTable is NULL or not Ready!");
		return NULL;
	}
	//先在当前的hash表里查询，查到了直接返回 。 没有查到再从网络获取，获取到后写入hash表中
	Buffer *buf = (Buffer *) apr_hash_get(globalVariable.styleVersionTable, styleUri->ptr, styleUri->used);
	if(NULL != buf) {
		return buf;
	}

	//写数据时锁住hash列表，避免多线程安全
	apr_thread_mutex_lock(globalVariable.getDataLock);
	buf = (Buffer *) apr_hash_get(globalVariable.styleVersionTable, styleUri->ptr, styleUri->used);
	if(NULL != buf) {
		apr_thread_mutex_unlock(globalVariable.getDataLock);
		return buf;
	}
	Buffer *data = getData(globalVariable.newPool, VERSION_GET, styleUri->ptr, styleUri->used);
	if(!SC_IS_EMPTY_BUFFER(data)) {
		char *key = apr_pstrmemdup(globalVariable.newPool, styleUri->ptr, styleUri->used);
		apr_hash_set(globalVariable.styleVersionTable, key, styleUri->used, data);
	}
	if(IS_LOG_ENABLED(LOG_GET_VERSION)) {
		sc_log_debug(LOG_GET_VERSION, "pid=%d get version URL [%s][%ld] vs[%s]", getpid(), styleUri->ptr, styleUri->used, ((NULL == data) ? "" : data->ptr));
	}
	apr_thread_mutex_unlock(globalVariable.getDataLock);
	return data;
}

Buffer *getStrVersion(sc_pool_t *pool, char *uri, Buffer *styleUri, GlobalVariable *globalVariable) {
	Buffer *versionBuf = getAndPut(styleUri, globalVariable);
	if(SC_IS_EMPTY_BUFFER(versionBuf) || 1 == versionBuf->used) {
		sc_log_error("pid=%d styleCombine=can't getVersion:ReqURI:[%s]==>StyleURI:[%s]", getpid(), uri, styleUri->ptr);
		time_t currentSec;
		time(&currentSec);
		versionBuf     = buffer_init_size(pool, 64);
		//build a dynic version in 6 minutes
		apr_snprintf(versionBuf->ptr, versionBuf->size, "%ld", (currentSec / 300));
		versionBuf->used = strlen(versionBuf->ptr);
	}
	return versionBuf;
}

void makeVersion(sc_pool_t *pool, Buffer *buf, Buffer *versionBuf) {
	string_append(pool, buf, "?_v=", 4);
	if(!SC_IS_EMPTY_BUFFER(versionBuf)) {
		if(versionBuf->used > 32) {
			char md5[3];
			unsigned char digest[16];
			apr_md5(digest, (const void *)versionBuf->ptr, versionBuf->used);
			SC_BUFFER_CLEAN(versionBuf);
			int i = 0;
			for(i = 0; i < 16; i++) {
				apr_snprintf(md5, 3, "%02x", digest[i]);
				string_append(pool, versionBuf, md5, 2);
			}
		}
		SC_STRING_APPEND_BUFFER(pool, buf, versionBuf);
	}
}
