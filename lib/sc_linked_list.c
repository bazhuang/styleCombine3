/*
 * sc_linked_list.c
 *
 *  Created on: Oct 19, 2013
 *      Author: zhiwenmizw
 */

#include "sc_linked_list.h"

/**
 * 列表的操作
 */
LinkedList *linked_list_create(sc_pool_t *pool) {
	LinkedList *list = (LinkedList *) sc_palloc(pool, sizeof(LinkedList));
	if (NULL == list) {
		return NULL;
	}
	list->first = NULL, list->head = NULL, list->size = 0;
	return list;
}

int add(sc_pool_t *pool, LinkedList *list, void *item) {
	if (NULL == list || NULL == item) {
		return 0;
	}
	ListNode *node = (ListNode *) sc_palloc(pool, sizeof(ListNode));
	if (NULL == node) {
		return 0;
	}
	node->next = NULL;
	node->value = item;
	if (NULL == list->first) {
		list->first = node;
		list->size = 0;
	} else {
		list->head->next = node;
	}
	++list->size;
	list->head = node;
	return 1;
}
