/*
 * sc_version.h
 *
 *  Created on: Oct 19, 2013
 *      Author: zhiwenmizw
 */

#ifndef SC_VERSION_H_
#define SC_VERSION_H_

#include "sc_common.h"

void checkVersionUpdate(sc_pool_t *server_pool, sc_pool_t *req_pool, GlobalVariable *globalVariable);

Buffer *getStrVersion(sc_pool_t *pool, char *uri, Buffer *styleUri, GlobalVariable *globalVariable);

void makeVersion(sc_pool_t *pool, Buffer *buf, Buffer *versionBuf);

#endif /* SC_VERSION_H_ */
