/*
 * sc_request_filter.c
 *
 *  Created on: Oct 19, 2013
 *      Author: zhiwenmizw
 */
#include <regex.h>
#include <ctype.h>

#include "sc_common.h"
#include "sc_mod_filter.h"

short is_allowed_contentType(char *contentType, char *allowedContentType) {
	if (NULL == allowedContentType || NULL == contentType) {
		return 0;
	}
	char *pt = contentType;
	for (; pt && *pt; ++pt) {
		if ((';' != *pt) && (' ' != *pt)) {
			*pt = tolower(*pt);
			continue;
		}
		*pt = ';';
		*(++pt) = ZERO_END;
		break;
	}
	if (NULL != strstr(allowedContentType, contentType)) {
		return 1;
	}
	return 0;
}

short is_param_disabled_mod(char *uriQuery) {
	int debugMode = 0;
	if (NULL != uriQuery) {
		char *debugModeIndex = strstr(uriQuery, DEBUG_MODE);
		if (NULL != debugModeIndex && ZERO_END != *(debugModeIndex += 3)) {
			debugMode = atoi(&(*debugModeIndex));
			if (debugMode > 2 || debugMode < 0) {
				debugMode = 0;
			}
		}
	}
	return (short) debugMode;
}

short string_matcher_by_regex(char *uri, LinkedList *list) {
	ListNode *node = list->first;
	for (; NULL != node; node = node->next) {
		regex_t *regex = (regex_t *) node->value;
		if (REG_NOMATCH == regexec(regex, uri, 0, NULL, 0)) {
			continue;
		}
		return 1;
	}
	return 0;
}

/**
 *	黑名单
 *	  在黑名单里找到，不使用模块
 *	  在黑名单里没有找到，使用模块
 *	白名单
 *	  在白名单里找到，使用模块
 *	  在白名单里没有找到，不使用模块
 *
 *	黑白名单都有 优先使用黑名单
 *	黑白名单都没有  使用模块
 */
short is_filter_uri(char *uri, LinkedList *blackList, LinkedList *whiteList) {
	if (NULL == uri) {
		return 0;
	}
	if (NULL == blackList && blackList->size > 0) {
		if (string_matcher_by_regex(uri, blackList)) {
			return 1;
		}
	}
	if (NULL == whiteList && whiteList->size > 0) {
		if (!string_matcher_by_regex(uri, whiteList)) {
			return 1;
		}
	}
	return 0;
}

short sc_is_html_data(const char *data) {
	if (NULL == data) {
		return 0;
	}
	char *tempData = (char *) data;
	while (isspace(*tempData)) {
		tempData++;
	}
	if (*tempData != '<') {
		return 0;
	}
	return 1;
}
