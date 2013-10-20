/*
 * sc_html_parser.h
 *
 *  Created on: Oct 19, 2013
 *      Author: zhiwenmizw
 */

#ifndef SC_HTML_PARSER_H_
#define SC_HTML_PARSER_H_

#include "sc_config.h"

char *tagPatterns[7]    =        { "head", "/head", "/body", "link", "script", "textarea", "!--" };
short tagPatternsLen[7] =        { 4, 5, 5, 4, 6, 8, 3 };

int html_parser(ParamConfig *paramConfig, Buffer *sourceCnt, Buffer *combinedStyleBuf[3], LinkedList *blockList, char *unparsed_uri);

#endif /* SC_HTML_PARSER_H_ */
