/*
 * sc_mod_filter.h
 *
 *  Created on: Oct 19, 2013
 *      Author: zhiwenmizw
 */

#ifndef SC_MOD_FILTER_H_
#define SC_MOD_FILTER_H_

#include <ctype.h>
#include <stdlib.h>

#include "sc_common.h"
#include "sc_linked_list.h"
#include "sc_config.h"

short is_allowed_contentType(char *contentType, char *allowedContentType);

short is_param_disabled_mod(char *uriQuery);

short string_matcher_by_regex(char *uri, LinkedList *list);

short is_filter_uri(char *uri, LinkedList *blackList, LinkedList *whiteList);

short sc_is_html_data(const char *data);

#endif /* SC_MOD_FILTER_H_ */
