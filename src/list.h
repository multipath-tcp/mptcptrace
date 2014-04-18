/*
 * list.h
 *
 *  Created on: Dec 24, 2013
 *      Author: Benjamin Hesmans
 */

#ifndef LIST_H_
#define LIST_H_

typedef struct List List;
typedef struct Node Node;
typedef struct OrderedList OrderedList;

struct Node{
	void* element;
	Node* next;
	Node* previous;
};

struct List{
	Node* head;
	Node* tail;
	int size;
	void (*destroyElement)(void* element);
};

struct OrderedList{
	List* l;
	/* java like compareTo function */
	int (*compare)(void* e1,void* e2);
};
void* exitMalloc(int size);
/*
 * Add node head, tail
 * destroy the list
 * del head, tail
 * apply (with args, constant accumulator)
 * search for (with the search fun and the args)
 */

List* newList(void (*destroyElement)(void* element));
OrderedList* newOrderedList(void (*destroyElement)(void* element), int (*compare)(void* e1,void* e2));
Node* addElementHead(void* element, List* l);
Node* addElementTail(void* element, List* l);
/*
 * Create a new node, and insert it after x, if x is null, add the new element at the head of the list.
 */
Node* addElementAfterX(Node* x,void* element, List* l);
/*
 * Free each node and apply the destroy element function for each element of the list
 */
void destroyList(List* l);
/*
 * apply a given function fun to each element of the list. Fix arg supposed to stay fix...while acc could be used to accumulate information
 */
void apply(List* l, void (*fun)(void* element,int pos,void* fix, void* acc), void* fix, void* acc);
void applyReverse(List* l, void (*fun)(void* element,int pos,void* fix, void* acc), void* fix, void* acc);
/*
 * search for arg in l by mean of search fun.
 */
void* search(List* l, int (*search)(void* element,int pos, void* arg, void* acc), void* arg, void* acc);

Node* addElementOrdered(void* element, OrderedList *ol);
Node* addElementOrderedReverse(void* element, OrderedList *ol);

void destroyOrderedList(OrderedList* ol);
void removeHead(List *l);
void removeHeadFree(List *l);
Node* addElementOrderedUnique(void* element, OrderedList *ol, int *added);
Node* addElementOrderedReverseUnique(void* element, OrderedList *ol, int *added);
#endif /* LIST_H_ */
