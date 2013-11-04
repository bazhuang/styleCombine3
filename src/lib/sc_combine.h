/*
 * sc_combine.h
 *
 *  Created on: Oct 19, 2013
 *      Author: zhiwenmizw
 */

#ifndef SC_COMBINE_H_
#define SC_COMBINE_H_

#include "sc_common.h"
#include "sc_config.h"
#include "sc_version.h"
#include "sc_linked_list.h"

int addExtStyle(Buffer *destBuf, ParamConfig *paramConfig);

void combineStyles(ParamConfig *paramConfig, LinkedList *styleList, Buffer *combinedStyleBuf[], Buffer *tmpUriBuf, Buffer *versionBuf);

void combineStylesAsync(ParamConfig *paramConfig, StyleList *styleList, Buffer *headBuf, Buffer *tmpUriBuf, Buffer *versionBuf);

void combineStylesDebug(ParamConfig *paramConfig, LinkedList *fullStyleList, Buffer *combinedStyleBuf[]);

#endif /* SC_COMBINE_H_ */
