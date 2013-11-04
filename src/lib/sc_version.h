/*
 * sc_version.h
 *
 *  Created on: Oct 19, 2013
 *      Author: zhiwenmizw
 */

#ifndef SC_VERSION_H_
#define SC_VERSION_H_

#include "sc_common.h"
#include "sc_config.h"

void check_version_update(sc_pool_t *server_pool, sc_pool_t *req_pool, GlobalVariable *globalVariable);

Buffer *get_string_version(sc_pool_t *pool, char *uri, Buffer *styleUri, GlobalVariable *globalVariable);

void make_md5_version(sc_pool_t *pool, Buffer *buf, Buffer *versionBuf);

#endif /* SC_VERSION_H_ */
