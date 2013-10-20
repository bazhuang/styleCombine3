/*
 * sc_config.c
 *
 *  Created on: Oct 20, 2013
 *      Author: zhiwenmizw
 */

#include "sc_config.h"

void global_variable_init(sc_pool_t *pool, CombineConfig *pConfig,  GlobalVariable *globalVariable) {
	globalVariable->styleVersionTable = NULL;
	globalVariable->newPool           = NULL;
	globalVariable->oldPool           = NULL;
	globalVariable->prevTime          = 0;
	globalVariable->upateTime         = 0;
	globalVariable->modRunMode        = NULL;
	globalVariable->pConfig           = pConfig;
	//apr_thread_mutex_create(&globalVariable.getDataLock, APR_THREAD_MUTEX_DEFAULT, pool);
	//apr_thread_mutex_create(&globalVariable.intervalCheckLock, APR_THREAD_MUTEX_DEFAULT, pool);
}

void combine_config_init(sc_pool_t *pool, CombineConfig *pConfig) {
	pConfig->enabled       = 1;
	pConfig->printLog      = 0;
	pConfig->filterCntType = "text/htm;text/html;";
	pConfig->appName       = NULL;
	int i = 0;
	for(i = 0; i < DOMAINS_COUNT; i++) {
		pConfig->oldDomains[i] = NULL;
		pConfig->newDomains[i] = NULL;
	}

	char variableNames[]    = "styleDomain0;styleDomain1;";
	string_split(pool, pConfig->asyncVariableNames, DOMAINS_COUNT, variableNames, ";");

	pConfig->blackList     = linked_list_create(pool);
	pConfig->whiteList     = linked_list_create(pool);
	/**
	 * see http://support.microsoft.com/kb/208427/EN-US
	 * default len for ie 2083 char
	 */
	pConfig->maxUrlLen     = 1500;
}

void *style_tag_init(sc_pool_t *pool, StyleParserTag *styleParserTags[2]) {

	StyleParserTag *cssPtag = sc_palloc(pool, sizeof(StyleParserTag));
	StyleParserTag *jsPtag  = sc_palloc(pool, sizeof(StyleParserTag));
	styleParserTags[SC_TYPE_CSS] = cssPtag;
	styleParserTags[SC_TYPE_JS]  = jsPtag;

	if(NULL == cssPtag || NULL == jsPtag) {
		return NULL;
	}
	//初始化css标签配置
	long size = sizeof(Buffer);
	Buffer *cssPrefix   = sc_palloc(pool, size);
	if(!putValueToBuffer(cssPrefix, "<link")) {
		return NULL;
	}
	Buffer *cssRefTag    = sc_palloc(pool, sizeof(Buffer));
	if(!putValueToBuffer(cssRefTag, " href=")) {
		return NULL;
	}
	Buffer *cssCloseTag  = sc_palloc(pool, sizeof(Buffer));
	if(!putValueToBuffer(cssCloseTag, ">")) {
		return NULL;
	}
	Buffer *cssMark      = sc_palloc(pool, sizeof(Buffer));
	if(!putValueToBuffer(cssMark, "stylesheet")) {
		return NULL;
	}
	cssPtag->prefix      = cssPrefix;
	cssPtag->mark        = cssMark;
	cssPtag->refTag      = cssRefTag;
	cssPtag->suffix      = '>';
	cssPtag->closeTag    = cssCloseTag;
	cssPtag->styleType   = SC_TYPE_CSS;

	// 初始化js标签配置
	Buffer *jsPrefix       = sc_palloc(pool, sizeof(Buffer));
	if(!putValueToBuffer(jsPrefix, "<script")) {
		return NULL;
	}
	Buffer *jsCloseTag     = sc_palloc(pool, sizeof(Buffer));
	if(!putValueToBuffer(jsCloseTag, "</script>")) {
		return NULL;
	}
	Buffer *jsMark         = sc_palloc(pool, sizeof(Buffer));
	if(!putValueToBuffer(jsMark, "src")) {
		return NULL;
	}
	Buffer *jsRefTag       = sc_palloc(pool, sizeof(Buffer));
	if(!putValueToBuffer(jsRefTag, " src=")) {
		return NULL;
	}
	jsPtag->prefix         = jsPrefix;
	jsPtag->mark           = jsMark;
	jsPtag->refTag         = jsRefTag;
	jsPtag->suffix         = '>';
	jsPtag->closeTag       = jsCloseTag;
	jsPtag->styleType      = SC_TYPE_JS;

	return pool;
}
