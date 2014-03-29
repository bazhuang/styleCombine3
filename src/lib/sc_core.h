/*
 * sc_core.h
 *
 *  Created on: Oct 19, 2013
 *      Author: zhiwenmizw
 */

#ifndef SC_HTML_PARSER_H_
#define SC_HTML_PARSER_H_

#include "sc_config.h"

int sc_core(ParamConfig *paramConfig, Buffer *sourceCnt, Buffer *combinedStyleBuf[3], LinkedList *blockList);

#endif /* SC_HTML_PARSER_H_ */
