/*
 * sc_combine.c
 *
 *  Created on: Oct 19, 2013
 *      Author: zhiwenmizw
 */

#include "sc_combine.h"
#include "sc_config.h"

int addExtStyle(Buffer *destBuf, ParamConfig *paramConfig) {

	if(NULL == destBuf ||NULL == paramConfig || NULL == paramConfig->styleField) {
		return 0;
	}
	StyleField *styleField = paramConfig->styleField;
	if (paramConfig->isNewLine) {
		string_append(paramConfig->pool, destBuf, "\n", 1);
	}
	if (SC_TYPE_JS == styleField->styleType) {
		string_append(paramConfig->pool, destBuf, JAVASCRIPT_PREFIX_STR_WITH_LEN);
	} else {
		string_append(paramConfig->pool, destBuf, CSS_PREFIX_STR_WITH_LEN);
	}
	SC_STRING_APPEND_BUFFER(paramConfig->pool, destBuf, paramConfig->domain);
	//超过于2个的style才使用 ?? xx.js,xx.js,否则按标准的URL生成
	if(paramConfig->styleCount > 1) {
		string_append(paramConfig->pool, destBuf, URL_URI_SPLIT_WITH_LEN);
	}
	SC_STRING_APPEND_BUFFER(paramConfig->pool, destBuf, paramConfig->styleField->styleUri);
	//append version
	make_md5_version(paramConfig->pool, destBuf, paramConfig->styleField->version);
	//append the version ext
	if (SC_TYPE_JS == styleField->styleType) {
		string_append(paramConfig->pool, destBuf, EXT_JS_WITH_LEN);
	} else {
		string_append(paramConfig->pool, destBuf, EXT_CSS_WITH_LEN);
	}
	if(2 == paramConfig->debugMode) {
		if(styleField->group) {
			string_append(paramConfig->pool, destBuf, "\" data-sc-group=\"", 17);
			SC_STRING_APPEND_BUFFER(paramConfig->pool, destBuf, styleField->group);
		}
	}
	//扩充media属性
	if(NULL != styleField->media) {
		string_append(paramConfig->pool, destBuf, "\" media=\"", 9);
		SC_STRING_APPEND_BUFFER(paramConfig->pool, destBuf, styleField->media);
	}
	if (SC_TYPE_JS == styleField->styleType) {
		string_append(paramConfig->pool, destBuf, JAVASCRIPT_SUFFIX_STR_WITH_LEN);
	} else {
		string_append(paramConfig->pool, destBuf, CSS_SUFFIX_STR_WITH_LEN);
	}
	return 1;
}

/**
 * 将js/css列表合并成一个url,并放到相应的位置上去
 */
void combineStyles(ParamConfig *paramConfig, LinkedList *styleList, Buffer *combinedStyleBuf[], Buffer *tmpUriBuf, Buffer *versionBuf) {
	if(NULL == styleList) {
		return;
	}
	StyleField *styleField = NULL;
	ListNode *node         = styleList->first;
	if(NULL == node || NULL == (styleField = (StyleField *)node->value)) {
		return;
	}
	CombineConfig *pConfig = paramConfig->pConfig;
	short flag             = 0;
	Buffer *combinedBuf = combinedStyleBuf[styleField->position];
	if(NULL == combinedBuf) {
		combinedStyleBuf[styleField->position] = combinedBuf = buffer_init_size(paramConfig->pool, pConfig->maxUrlLen);
	}
	paramConfig->styleField = styleField;
	paramConfig->domain     = pConfig->newDomains[styleField->domainIndex];
	paramConfig->isNewLine  = 1;
	paramConfig->styleCount = 0;
	for(; NULL != node; node = node->next) {
		styleField        = (StyleField *) node->value;
		if (flag) {
			string_append(paramConfig->pool, tmpUriBuf, URI_SEPARATOR_WITH_LEN);
		} else {
			flag          = 1;
		}
		//url拼接在一起的长度超过配置的长度，则需要分成多个请求来处理。(域名+uri+下一个uri +版本长度 + 参数名称长度[版本长度36 + 参数名称长度4])
		int urlLen = (paramConfig->domain->used + tmpUriBuf->used + styleField->styleUri->used);
		if (urlLen + 40  >= pConfig->maxUrlLen) {
			tmpUriBuf->ptr[--tmpUriBuf->used] = ZERO_END;  //将合并的url最后一个,字符去除
			//借用一个变量传递参数值，不好的写法
			paramConfig->styleField->styleUri = tmpUriBuf;
			paramConfig->styleField->version  = versionBuf;
			addExtStyle(combinedBuf, paramConfig);

			paramConfig->styleCount           = 0;
			SC_BUFFER_CLEAN(versionBuf); SC_BUFFER_CLEAN(tmpUriBuf);
		}
		//为了合并后减少一个反斜杠 '/' 如：(/app/a.js ==> app/a.js)
		SC_STRING_APPEND_BUFFER(paramConfig->pool, tmpUriBuf, styleField->styleUri);
		SC_STRING_APPEND_BUFFER(paramConfig->pool, versionBuf, styleField->version);
		paramConfig->styleCount++;
	}
	paramConfig->styleField->styleUri = tmpUriBuf;
	paramConfig->styleField->version  = versionBuf;
	addExtStyle(combinedBuf, paramConfig);
	return;
}

static void addAsyncStyle(sc_pool_t *pool, Buffer *buf, Buffer *versionBuf, enum StyleType styleType) {
	make_md5_version(pool, buf, versionBuf);
	if (SC_TYPE_JS == styleType) {
		string_append(pool, buf, EXT_JS_WITH_LEN);
	} else {
		string_append(pool, buf, EXT_CSS_WITH_LEN);
	}
}

//var tt="{"group1":{"css":["http://xx/a1.css"],"js":["http://xx/a1.js"]},"group2":{"css":[],"js":["http://xx/a2.js"]}}"
void combineStylesAsync(ParamConfig *paramConfig, StyleList *styleList, Buffer *headBuf, Buffer *tmpUriBuf, Buffer *versionBuf) {

	if(NULL == styleList || NULL == headBuf) {
		return;
	}
	sc_pool_t      *pool   = paramConfig->pool;
	CombineConfig *pConfig = paramConfig->pConfig;
	headBuf->ptr[headBuf->used++] = '"';
	string_append(pool, headBuf, styleList->group->ptr, styleList->group->used - 1);
	string_append(pool, headBuf, "\":{\"css\"", 8);
	unsigned int i = 0, count = 0;
	for(i = 0; i < 2; i++) {
		LinkedList *list = styleList->list[i];
		if(NULL == list || !list->size) {
			if(i) {
				string_append(pool, headBuf, "\"js\":[]", 7); // "js":[]
			} else {
				string_append(pool, headBuf, ":[],", 4); // "css":[],
			}
			continue;
		}
		if(i) {
			string_append(pool, headBuf, "\"js\"", 4);
		}
		SC_BUFFER_CLEAN(tmpUriBuf); SC_BUFFER_CLEAN(versionBuf);

		string_append(pool, headBuf, ":[", 2);
		ListNode *node         = list->first;
		StyleField *styleField = (StyleField *) node->value;
		Buffer *domain         = pConfig->newDomains[styleField->domainIndex];
		SC_STRING_APPEND_BUFFER(pool, tmpUriBuf, domain);

		if(list->size > 1) {
			string_append(pool, tmpUriBuf, URL_URI_SPLIT_WITH_LEN);
		}

		for(count = 0; NULL != node; count++) {
			styleField = (StyleField *) node->value;
			if(count) {
				string_append(pool, tmpUriBuf, URI_SEPARATOR_WITH_LEN);
			}
			//url拼接在一起的长度超过配置的长度，则需要分成多个请求来处理。(域名+uri+下一个uri +版本长度 + 参数名称长度[版本长度36 + 参数名称长度4])
			int urlLen = (domain->used + tmpUriBuf->used + styleField->styleUri->used);
			if (urlLen + 40  >= pConfig->maxUrlLen) {
				//将合并的url最后一个,字符去除
				tmpUriBuf->ptr[--tmpUriBuf->used] = ZERO_END;
				addAsyncStyle(pool, tmpUriBuf, versionBuf, i);
				//copy to head
				string_append(pool, headBuf, "\"", 1);
				SC_STRING_APPEND_BUFFER(pool, headBuf, tmpUriBuf);
				SC_BUFFER_CLEAN(tmpUriBuf);
				SC_BUFFER_CLEAN(versionBuf);
				//if not the end
				if(list->size >= count + 1) {
					string_append(pool, headBuf, "\",", 2);
					SC_STRING_APPEND_BUFFER(pool, tmpUriBuf, domain);
					if(list->size >= count + 2) {
						string_append(pool, tmpUriBuf, URL_URI_SPLIT_WITH_LEN);
					}
				}
			}
			SC_STRING_APPEND_BUFFER(pool, tmpUriBuf, styleField->styleUri);
			SC_STRING_APPEND_BUFFER(pool, versionBuf, styleField->version);
			node = node->next;
		}
		if(tmpUriBuf->used) {
			string_append(pool, headBuf, "\"", 1);
			addAsyncStyle(pool, tmpUriBuf, versionBuf, i);
		}
		SC_STRING_APPEND_BUFFER(pool, headBuf, tmpUriBuf);
		if (i) {
			string_append(pool, headBuf, "\"]", 2);
		} else {
			string_append(pool, headBuf, "\"],", 3);
		}
	}
	string_append(pool, headBuf, "},", 2);
}

/**
 * 用于开发时，打开调试模块调用。将js/css的位置做移动，但不做合并
 */
void combineStylesDebug(ParamConfig *paramConfig, LinkedList *fullStyleList, Buffer *combinedStyleBuf[]) {

	ListNode *styleNode = NULL;
	if(NULL == fullStyleList || NULL == (styleNode = fullStyleList->first)) {
		return;
	}
	Buffer *combinedBuf = NULL;
	int i = 0;
	for(; NULL != styleNode; styleNode = styleNode->next) {
		StyleList *styleList = (StyleList *) styleNode->value;
		for(i = 0; i < 2; i++) {
			ListNode *node   = NULL;
			LinkedList *list = styleList->list[i];
			if(NULL == list || NULL == (node = list->first)) {
				continue;
			}
			StyleField *styleField = (StyleField *)node->value;
			if(NULL == styleField) {
				continue;
			}
			if(SC_NONE == styleField->position || styleField->async) {
				combinedBuf = combinedStyleBuf[SC_FOOTER];
				if(NULL == combinedBuf) {
					combinedStyleBuf[SC_FOOTER] = combinedBuf = buffer_init_size(paramConfig->pool, 1024);
				}
			} else {
				combinedBuf = combinedStyleBuf[styleField->position];
				if(NULL == combinedBuf) {
					combinedStyleBuf[styleField->position] = combinedBuf = buffer_init_size(paramConfig->pool, 1024);
				}
			}
			paramConfig->styleField = styleField;
			paramConfig->domain     = paramConfig->pConfig->newDomains[styleField->domainIndex];
			paramConfig->isNewLine  = 1;
			for(; NULL != node; node = node->next) {
				styleField            = (StyleField *) node->value;
				paramConfig->styleField = styleField;
				addExtStyle(combinedBuf, paramConfig);
			}
		}
	}
	return;
}
