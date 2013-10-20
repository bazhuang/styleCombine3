/*
 * sc_linked_list.h
 *
 *  Created on: Oct 19, 2013
 *      Author: zhiwenmizw
 */

#ifndef SC_LINKED_LIST_H_
#define SC_LINKED_LIST_H_

#include "sc_common.h"

typedef struct ListNode ListNode;
struct ListNode {
	ListNode   *next;
	const void *value;
};

typedef struct {
	int        size;
	ListNode  *first;
	ListNode  *head;
} LinkedList;

/**
 * 列表的操作
 */
LinkedList *linked_list_create(apr_pool_t *pool);

int add(apr_pool_t *pool, LinkedList *list, void *item);

#endif /* SC_LINKED_LIST_H_ */
