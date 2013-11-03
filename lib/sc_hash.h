/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * sc_hash.h
 *
 *  Created on: Nov 3, 2013
 *      Author: zhiwenmizw
 */

#ifndef SC_HASH_H_
#define SC_HASH_H_

#include "sc_common.h"

typedef struct sc_hash_t sc_hash_t;

typedef struct sc_hash_index_t sc_hash_index_t;

typedef unsigned int (*sc_hashfunc_t)(const char *key, size_t *klen);

sc_hash_t * sc_hash_make(sc_pool_t *pool);

void sc_hash_set(sc_hash_t *ht, const void *key, size_t klen, const void *val);

void * sc_hash_get(sc_hash_t *ht, const void *key, size_t klen);

#endif /* SC_HASH_H_ */
