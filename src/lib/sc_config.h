/*
 * sc_config.h
 *
 *  Created on: Oct 19, 2013
 *      Author: zhiwenmizw
 */

#ifndef SC_CONFIG_H_
#define SC_CONFIG_H_

#include "sc_common.h"
#include "sc_linked_list.h"
#include "sc_string.h"
#include "sc_hash.h"

#define EXT_JS_WITH_LEN                           ".js", 3
#define EXT_CSS_WITH_LEN                          ".css", 4

#define POSITION_TOP_WITH_LEN                     "top", 3
#define POSITION_HEAD_WITH_LEN                    "head", 4
#define POSITION_FOOTER_WITH_LEN                  "footer", 6

#define DEBUG_MODE                                "_debugMode_="
#define RUN_MODE_STATUS_WITH_LEN                  "dis", 3

#define JAVASCRIPT_PREFIX_STR_WITH_LEN            "<script type=\"text/javascript\" src=\"", 36
#define JAVASCRIPT_SUFFIX_STR_WITH_LEN            "\"></script>", 11
#define CSS_PREFIX_STR_WITH_LEN                   "<link rel=\"stylesheet\" href=\"", 29
#define CSS_SUFFIX_STR_WITH_LEN                   "\" />", 4
#define URI_SEPARATOR_WITH_LEN                    ",", 1
#define URL_URI_SPLIT_WITH_LEN                    "??", 2


enum StyleType                   { SC_TYPE_CSS, SC_TYPE_JS };
/*position char */
enum PositionEnum                { SC_TOP, SC_HEAD, SC_FOOTER, SC_NONE };

/*tag field*/
enum TagNameEnum                 { SC_BHEAD, SC_EHEAD, SC_EBODY, SC_LINK, SC_SCRIPT, SC_TEXTAREA, SC_COMMENT_EXPRESSION, SC_TN_NONE };

typedef struct {
	Buffer            *prefix;
	Buffer            *mark;
	Buffer            *refTag;
	Buffer            *closeTag;
	int                suffix;
	enum StyleType     styleType;
} StyleParserTag;

typedef struct {
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
} CombineConfig;

typedef struct StyleField {
	short                 async;
	enum StyleType        styleType;
	short                 domainIndex;
	Buffer               *styleUri;
	Buffer               *group;
	Buffer               *media;
	Buffer               *version;
	enum PositionEnum     position;
} StyleField;

typedef struct {
	short                domainIndex;
	Buffer              *group;
	LinkedList          *list[2];
} StyleList;

typedef struct {
	int                  bIndex;
	int                  eIndex;
	//用于存放，那些没有合并的style；有内容时 bIndex和eIndex都视无效
	Buffer              *cntBlock;
	//当前对象的类型如是：<head>,</head>, </body>等
	enum TagNameEnum     tagNameEnum;
} ContentBlock;

typedef struct  {
#ifndef SC_NGINX_PLATFORM
	sc_thread_mutex_t   *getDataLock, *intervalCheckLock;
#endif
	time_t               prevTime;
	time_t               upateTime;
	sc_pool_t           *newPool, *oldPool;
	sc_hash_t           *styleVersionTable;
	CombineConfig       *pConfig;
	char                *modRunMode;
} GlobalVariable;

typedef struct {
	StyleField          *styleField;
	Buffer              *domain;
	short                isNewLine;
	short                needExt;
	short                debugMode;
	int                  styleCount;
	CombineConfig       *pConfig;
	StyleParserTag     **styleParserTags;
	GlobalVariable      *globalVariable;
	sc_pool_t           *pool;
} ParamConfig;

void global_variable_init(sc_pool_t *pool, CombineConfig *pConfig, GlobalVariable *globalVariable);

void combine_config_init(sc_pool_t *pool, CombineConfig *pConfig);

void *style_tag_init(sc_pool_t *pool, StyleParserTag *styleParserTags[2]);

#endif /* SC_CONFIG_H_ */
