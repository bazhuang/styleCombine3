/*
 * sc_string.h
 *
 *  Created on: Oct 19, 2013
 *      Author: zhiwenmizw
 */

#ifndef SC_STRING_H_
#define SC_STRING_H_

#include <ctype.h>

#include "sc_common.h"
#include "sc_buffer.h"

/**
 * 拿当前字符串与模式字符串先比较两人最后的字符是否相等，如果相等再比较全部。
 */
int compare(char *input, char *pattern, int patternLen, short ignorecase) {
	if(NULL == input || NULL == pattern) {
		return -1;
	}
	++input;
	++pattern; --patternLen;
	char *endChar = input + patternLen - 1;
	if(*endChar == ZERO_END || tolower(*endChar) != *(pattern + patternLen - 1)) {
		return -1;
	}
	if(ignorecase) {
		return strncasecmp(input, pattern, patternLen);
	}
	return memcmp(input, pattern, patternLen);
}

/**
 * 字符串分割
 */
void string_split(sc_pool_t *pool, Buffer *arrays[], int arrayLen,
		char *string, char *seperator) {
	char *item = NULL;
	int len = 0, i = 0;
	while (i < arrayLen && (item = strsep(&string, seperator))) {
		len = strlen(item);
		if(0 == len) {
			continue;
		}
		Buffer *buf = buffer_init_size(pool, len + 1);
		string_append(pool, buf, item, len);
		arrays[i++] = buf;
	}
}

int parseargline(char *str, char **pattern) {
	char quote;
	while (isspace(*str)) {
		++str;
	}
	/*
	 * determine first argument
	 */
	quote = (*str == '"' || *str == '\'') ? *str++ : '\0';
	*pattern = str;
	for (; *str; ++str) {
		if ((isspace(*str) && !quote) || (*str == quote)) {
			break;
		}
		if (*str == '\\' && isspace(str[1])) {
			++str;
			continue;
		}
	}
	if (!*str) {
		return 1;
	}
	*str++ = '\0';
	return 0;
}

char *sc_pstrmemdup(sc_pool_t *pool, const char *s, size_t n) {
    char *res;
    if (s == NULL) {
        return NULL;
    }
    res = sc_palloc(pool, n + 1);
    memcpy(res, s, n);
    res[n] = '\0';
    return res;
}

#endif /* SC_STRING_H_ */
