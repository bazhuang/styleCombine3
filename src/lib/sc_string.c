/*
 * sc_string.c
 *
 *  Created on: Oct 24, 2013
 *      Author: zhiwenmizw
 */

#include "sc_string.h"

/**
 * 拿当前字符串与模式字符串先比较两人最后的字符是否相等，如果相等再比较全部。
 */
int compare(char *input, char *pattern, int patternLen, short ignorecase) {
	if (NULL == input || NULL == pattern) {
		return -1;
	}
	++input;
	++pattern;
	--patternLen;
	char *endChar = input + patternLen - 1;
	if (*endChar == ZERO_END
			|| tolower(*endChar) != *(pattern + patternLen - 1)) {
		return -1;
	}
	if (ignorecase) {
		return strncasecmp(input, pattern, patternLen);
	}
	return memcmp(input, pattern, patternLen);
}

/**
 * 字符串分割
 */
void string_split(sc_pool_t *pool, Buffer *arrays[], int arrayLen, char *string,
		char *seperator) {
	char *item = NULL;
	int len = 0, i = 0;
	while (i < arrayLen && (item = strsep(&string, seperator))) {
		len = strlen(item);
		if (0 == len) {
			continue;
		}
		Buffer *buf = buffer_init_size(pool, len + 1);
		string_append(pool, buf, item, len);
		arrays[i++] = buf;
	}
}

short parseargline(char *str, char **pattern) {
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

char * sc_pstrdup(sc_pool_t *a, const char *s) {
	char *res;
	size_t len;
	if (s == NULL) {
		return NULL;
	}
	len = strlen(s) + 1;
	res = sc_palloc(a, len);
	memcpy(res, s, len);
	return res;
}

regex_t * pattern_validate_compile(sc_pool_t *pool, const char *string) {
	if (NULL == string) {
		return NULL;
	}
	char *pt_str = sc_pstrdup(pool, string);

#ifdef SC_HTTPD_PLATFORM
	regex_t *regexp = sc_palloc(pool, sizeof(regex_t));

#elif SC_NGINX_PLATFORM
#include <ngx_config.h>
#include <ngx_core.h>  
    ngx_pool_cleanup_t  *cln;

    cln = ngx_pool_cleanup_add(pool, sizeof(regex_t));
    if (cln == NULL) {                    
            return NULL;                 
    }                                     
    regex_t *regexp = cln->data;                                         
    cln->handler = (ngx_pool_cleanup_pt)regfree;

#endif 
	char *pattern = NULL;
	parseargline(pt_str, &pattern);
	int rc = regcomp(regexp, pattern, REG_EXTENDED | REG_NOSUB | REG_ICASE);
	if (0 != rc) {
		return NULL;
	}
	return regexp;
}
