/*
 * sc_config.h
 *
 *  Created on: Oct 19, 2013
 *      Author: zhiwenmizw
 */

#ifndef SC_CONFIG_H_
#define SC_CONFIG_H_

#include "sc_common.h"
#include "sc_config.h"

#define STYLE_COMBINE_NAME                        "styleCombine"
#define MODULE_BRAND                               STYLE_COMBINE_NAME"/2.1.0"

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

#define DEFAULT_CONTENT_LEN                       262144 //1024 << 8
#define DOMAINS_COUNT                             2

enum StyleType                   { SC_TYPE_CSS, SC_TYPE_JS };
/*position char */
enum PositionEnum                { SC_TOP, SC_HEAD, SC_FOOTER, SC_NONE };
/*tag field*/
enum TagNameEnum                 { SC_BHEAD, SC_EHEAD, SC_EBODY, SC_LINK, SC_SCRIPT, SC_TEXTAREA, SC_COMMENT_EXPRESSION, SC_TN_NONE };
char *tagPatterns[7]    =        { "head", "/head", "/body", "link", "script", "textarea", "!--" };
short tagPatternsLen[7] =        { 4, 5, 5, 4, 6, 8, 3 };

typedef struct StyleParserTag StyleParserTag;
typedef struct CombineConfig  CombineConfig;
typedef struct StyleField     StyleField;
typedef struct StyleList      StyleList;
typedef struct ContentBlock   ContentBlock;
typedef struct ParamConfig    ParamConfig;
typedef struct GlobalVariable GlobalVariable;

void global_variable_init(sc_pool_t *pool, CombineConfig *pConfig, GlobalVariable *globalVariable);

void combine_config_init(sc_pool_t *pool, CombineConfig *pConfig);

void *style_tag_init(sc_pool_t *pool, StyleParserTag *styleParserTags[2]);

#endif /* SC_CONFIG_H_ */
