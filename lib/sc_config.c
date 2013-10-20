/*
 * sc_config.c
 *
 *  Created on: Oct 20, 2013
 *      Author: zhiwenmizw
 */

#include "sc_common.h"
#include "sc_config.h"
#include "sc_linked_list.h"
#include "sc_string.h"

struct StyleParserTag {
	Buffer            *prefix;
	Buffer            *mark;
	Buffer            *refTag;
	Buffer            *closeTag;
	int                suffix;
	enum StyleType     styleType;
};

struct CombineConfig {
	short              enabled;
	int                maxUrlLen;
	int                printLog;
	char              *filterCntType;
	Buffer            *appName;
	Buffer            *oldDomains[DOMAINS_COUNT];
	Buffer            *newDomains[DOMAINS_COUNT];
	Buffer            *asyncVariableNames[DOMAINS_COUNT];
	LinkedList        *blackList;
	LinkedList        *whiteList;
};

struct StyleField {
	short                 async;
	enum StyleType        styleType;
	short                 domainIndex;
	Buffer               *styleUri;
	Buffer               *group;
	Buffer               *media;
	Buffer               *version;
	enum PositionEnum     position;
};

struct ParamConfig {
	StyleField          *styleField;
	Buffer              *domain;
	short                isNewLine;
	short                needExt;
	short                debugMode;
	int                  styleCount;
	CombineConfig       *pConfig;
	StyleParserTag      *styleParserTags;
	sc_pool_t           *pool;
};

struct StyleList {
	short                domainIndex;
	Buffer              *group;
	LinkedList          *list[2];
};

struct ContentBlock {
	int                  bIndex;
	int                  eIndex;
	//用于存放，那些没有合并的style；有内容时 bIndex和eIndex都视无效
	Buffer              *cntBlock;
	//当前对象的类型如是：<head>,</head>, </body>等
	enum TagNameEnum     tagNameEnum;
};

struct GlobalVariable {
	sc_thread_mutex_t   *getDataLock, *intervalCheckLock;
	time_t               prevTime;
	time_t               upateTime;
	sc_pool_t           *newPool, *oldPool;
	sc_hash_t          *styleVersionTable;
	CombineConfig       *pConfig;
	char                *modRunMode;
};

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

	StyleParserTag *cssPtag = styleParserTags[SC_TYPE_CSS] = sc_palloc(pool, sizeof(StyleParserTag));
	StyleParserTag *jsPtag = styleParserTags[SC_TYPE_JS]   = sc_palloc(pool, sizeof(StyleParserTag));
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
