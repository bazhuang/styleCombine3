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
 * sc_hash.c
 *
 *  Created on: Nov 3, 2013
 *      Author: zhiwenmizw
 *      copy by Apache
 */

#include "sc_hash.h"

typedef struct sc_hash_entry_t sc_hash_entry_t;

struct sc_hash_entry_t {
	sc_hash_entry_t *next;
	unsigned int hash;
	const void *key;
	size_t klen;
	const void *val;
};

struct sc_hash_index_t {
	sc_hash_t *ht;
	sc_hash_entry_t *this, *next;
	unsigned int index;
};

struct sc_hash_t {
	sc_pool_t *pool;
	sc_hash_entry_t **array;
	sc_hash_index_t iterator; /* For sc_hash_first(NULL, ...) */
	unsigned int count, max;
	sc_hashfunc_t hash_func;
	sc_hash_entry_t *free; /* List of recycled entries */
};

unsigned int sc_hashfunc_default(const char *char_key, size_t *klen) {
	unsigned int hash = 0;
	const unsigned char *key = (const unsigned char *) char_key;
	const unsigned char *p;
	size_t i;

	if (*klen == (size_t) -1) {
		for (p = key; *p; p++) {
			hash = hash * 33 + *p;
		}
		*klen = p - key;
	} else {
		for (p = key, i = *klen; i; i--, p++) {
			hash = hash * 33 + *p;
		}
	}
	return hash;
}

static sc_hash_entry_t **alloc_array(sc_hash_t *ht, unsigned int max) {
	return sc_pcalloc(ht->pool, sizeof(*ht->array) * (max + 1));
}

sc_hash_t * sc_hash_make(sc_pool_t *pool) {
	sc_hash_t *ht;
	ht = sc_palloc(pool, sizeof(sc_hash_t));
	ht->pool = pool;
	ht->free = NULL;
	ht->count = 0;
	ht->max = 15;
	ht->array = alloc_array(ht, ht->max);
	ht->hash_func = sc_hashfunc_default;
	return ht;
}

static sc_hash_entry_t **find_entry(sc_hash_t *ht, const void *key, size_t klen,
		const void *val) {
	sc_hash_entry_t **hep, *he;
	unsigned int hash;

	hash = ht->hash_func(key, &klen);

	/* scan linked list */
	for (hep = &ht->array[hash & ht->max], he = *hep; he; hep = &he->next, he =
			*hep) {
		if (he->hash == hash && he->klen == klen
				&& memcmp(he->key, key, klen) == 0) {
			break;
		}
	}
	if (he || !val) {
		return hep;
	}

	/* add a new entry for non-NULL values */
	if ((he = ht->free) != NULL) {
		ht->free = he->next;
	} else {
		he = sc_palloc(ht->pool, sizeof(*he));
	}
	he->next = NULL;
	he->hash = hash;
	he->key = key;
	he->klen = klen;
	he->val = val;
	*hep = he;
	ht->count++;
	return hep;
}

sc_hash_index_t * sc_hash_next(sc_hash_index_t *hi) {
	hi->this = hi->next;
	while (!hi->this) {
		if (hi->index > hi->ht->max)
			return NULL;

		hi->this = hi->ht->array[hi->index++];
	}
	hi->next = hi->this->next;
	return hi;
}

sc_hash_index_t * sc_hash_first(sc_pool_t *p, sc_hash_t *ht) {
	sc_hash_index_t *hi;
	if (p)
		hi = sc_palloc(p, sizeof(*hi));
	else
		hi = &ht->iterator;

	hi->ht = ht;
	hi->index = 0;
	hi->this = NULL;
	hi->next = NULL;
	return sc_hash_next(hi);
}

static void expand_array(sc_hash_t *ht) {
	sc_hash_index_t *hi;
	sc_hash_entry_t **new_array;
	unsigned int new_max;

	new_max = ht->max * 2 + 1;
	new_array = alloc_array(ht, new_max);
	for (hi = sc_hash_first(NULL, ht); hi; hi = sc_hash_next(hi)) {
		unsigned int i = hi->this->hash & new_max;
		hi->this->next = new_array[i];
		new_array[i] = hi->this;
	}
	ht->array = new_array;
	ht->max = new_max;
}

void * sc_hash_get(sc_hash_t *ht, const void *key, size_t klen) {
	sc_hash_entry_t *he;
	he = *find_entry(ht, key, klen, NULL);
	if (he)
		return (void *) he->val;
	else
		return NULL;
}

void sc_hash_set(sc_hash_t *ht, const void *key, size_t klen, const void *val) {
	sc_hash_entry_t **hep;
	hep = find_entry(ht, key, klen, val);
	if (*hep) {
		if (!val) {
			/* delete entry */
			sc_hash_entry_t *old = *hep;
			*hep = (*hep)->next;
			old->next = ht->free;
			ht->free = old;
			--ht->count;
		} else {
			/* replace entry */
			(*hep)->val = val;
			/* check that the collision rate isn't too high */
			if (ht->count > ht->max) {
				expand_array(ht);
			}
		}
	}
}
