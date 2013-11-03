/*
 * sc_string.h
 *
 *  Created on: Oct 19, 2013
 *      Author: zhiwenmizw
 */

#ifndef SC_STRING_H_
#define SC_STRING_H_

#include <ctype.h>
#include <regex.h>

#include "sc_common.h"
#include "sc_buffer.h"

/**
 * 拿当前字符串与模式字符串先比较两人最后的字符是否相等，如果相等再比较全部。
 */
int compare(char *input, char *pattern, int patternLen, short ignorecase);

/**
 * 字符串分割
 */
void string_split(sc_pool_t *pool, Buffer *arrays[], int arrayLen, char *string,
		char *seperator);

short parseargline(char *str, char **pattern);

char *sc_pstrmemdup(sc_pool_t *pool, const char *s, size_t n);

char *sc_pstrdup(sc_pool_t *a, const char *s);

regex_t *pattern_validate_compile(sc_pool_t *pool, const char *string);

#endif /* SC_STRING_H_ */
