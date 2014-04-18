/*
 * list.c
 *
 *  Created on: Dec 24, 2013
 *      Author: Benjamin Hesmans
 */


#include <stdlib.h>
#include <stdio.h>
#include "list.h"

void* exitMalloc(int size){
	void* s = malloc(size);
	if(!s){
		printf("Memory allocation fails...\n");
		exit(1);
	}
	return s;
}


int dontStop(void* element,int pos,void* fix, void* acc){
	return 0;
}

void doNothing(void* element,int pos,void* fix, void* acc){
	return;
}

Node* newNode(void *element){
	Node* n = (Node*) exitMalloc(sizeof(Node));
	n->element = element;
	n->next = NULL;
	n->previous = NULL;
	return n;
}

List* newList(void (*destroyElement)(void* element)){
	List* l = (List*) exitMalloc(sizeof(List));
	l->head=NULL;
	l->size=0;
	l->destroyElement = destroyElement;
	l->tail = NULL;
	return l;
}



OrderedList* newOrderedList(void (*destroyElement)(void* element), int (*compare)(void* e1,void* e2)){
	OrderedList *ol = (OrderedList*) exitMalloc(sizeof(OrderedList));
	ol->l = newList(destroyElement);
	ol->compare = compare;
	return ol;
}

Node* addElementAfterX(Node* x,void* element, List* l){
	if(x==NULL)
		return addElementHead(element,l);
	else{
		Node *n = newNode(element);
		n->next = x->next;
		n->previous = x;
		x->next = n;
		l->size++;
		if(x==l->tail)
			l->tail = n;
		else
			n->next->previous = n;
		return n;
	}
}

Node* addElementBeforeX(Node* x,void* element, List *l){
	if(x==NULL)
		return addElementTail(element,l);
	else
		return addElementAfterX(x->previous,element,l);
}

Node* addElementHead(void* element, List* l){
	Node *n = newNode(element);
	if(l->size==0)
		l->tail = n;
	else
		l->head->previous=n;
	n->next = l->head;
	n->previous = NULL;
	l->head = n;
	l->size++;
	return n;
}

Node* addElementTail(void* element, List* l){
	return addElementAfterX(l->tail,element,l);
}

void removeHead(List *l){
	if(l->size==1){
		l->head = NULL;
		l->tail = NULL;
	}
	else{
		l->head = l->head->next;
		l->head->previous = NULL;
	}
	l->size--;
}
void removeHeadFree(List *l){
	if(l->size!=0){
		Node* tmp=l->head;
		removeHead(l);
		free(tmp);
	}
}
Node* applyUntilNode(List* l, void (*fun)(void* element,int pos,void* fix, void* acc),int (*stop)(void* element,int pos,void* fix, void* acc), void* fix, void* acc){
	int i=0;
	Node* n = l->head;
	for(i=0 ; i < l->size;i++){
		fun(n->element,i,fix,acc);
		if(stop(n->element,i,fix,acc))
			return n;
		n=n->next;
	}
	return NULL;
}

Node* applyUntilNodeReverse(List* l, void (*fun)(void* element,int pos,void* fix, void* acc),int (*stop)(void* element,int pos,void* fix, void* acc), void* fix, void* acc){
	int i=0;
	Node* n = l->tail;
	for(i=l->size-1 ; i >= 0 ;i--){
		fun(n->element,i,fix,acc);
		if(stop(n->element,i,fix,acc))
			return n;
		n=n->previous;
	}
	return NULL;
}

void* applyUntil(List* l, void (*fun)(void* element,int pos,void* fix, void* acc),int (*stop)(void* element,int pos,void* fix, void* acc), void* fix, void* acc){

	Node* n = applyUntilNode(l,fun,stop,fix,acc);
	return n ? n->element : NULL;
}

void* applyUntilReverse(List* l, void (*fun)(void* element,int pos,void* fix, void* acc),int (*stop)(void* element,int pos,void* fix, void* acc), void* fix, void* acc){
	Node* n = applyUntilNodeReverse(l,fun,stop,fix,acc);
	return n ? n->element : NULL;
}

void apply(List* l, void (*fun)(void* element,int pos,void* fix, void* acc), void* fix, void* acc){
	applyUntil(l,fun,dontStop,fix,acc);
}

void applyReverse(List* l, void (*fun)(void* element,int pos,void* fix, void* acc), void* fix, void* acc){
	applyUntilReverse(l,fun,dontStop,fix,acc);
}

Node* searchNode(List* l, int (*search)(void* element,int pos, void* arg, void* acc), void* arg, void* acc){
	return applyUntilNode(l,doNothing,search,arg,acc);
}

void* search(List* l, int (*search)(void* element,int pos, void* arg, void* acc), void* arg, void* acc){
	return applyUntil(l,doNothing,search,arg,acc);
}

int compareWrapper(void* element,int pos,void* fix, void* acc){
	int (*compare)(void *e1,void *e2) = (int (*)(void*,void*)) fix;
	return compare(acc,element) < 0 ? 1 : 0;
}

int compareWrapperReverse(void* element,int pos,void* fix, void* acc){
	return !compareWrapper(element,pos,fix,acc);
}


Node* addElementOrdered(void* element, OrderedList *ol){
	Node *n = applyUntilNode(ol->l,doNothing,compareWrapper,ol->compare,element);
	return addElementBeforeX(n,element,ol->l);
}

Node* addElementOrderedUnique(void* element, OrderedList *ol, int *added){
	Node *n = applyUntilNode(ol->l,doNothing,compareWrapper,ol->compare,element);
	*added=0;
	if(n==NULL && ol->l->size>0 && ol->compare(ol->l->tail->element,element) == 0)
		return ol->l->tail;
	if(n!=NULL && ol->compare(n->previous->element,element) == 0)
		return n->previous;
	*added=1;
	return addElementBeforeX(n,element,ol->l);
}

void destroyElement(void* element, int pos, void* fix, void* acc){
	void (*destroyElement)(void* element) = (void (*)(void*)) fix;
	destroyElement(element);
}
Node* addElementOrderedReverse(void* element, OrderedList *ol){
	Node *n = applyUntilNodeReverse(ol->l,doNothing,compareWrapperReverse,ol->compare,element);
	return addElementAfterX(n,element,ol->l);
}
Node* addElementOrderedReverseUnique(void* element, OrderedList *ol, int *added){
	Node *n = applyUntilNodeReverse(ol->l,doNothing,compareWrapperReverse,ol->compare,element);
	*added=0;
	if(n==NULL && ol->l->size>0 && ol->compare(ol->l->head->element,element) == 0)
		return ol->l->head;
	if(n!=NULL && ol->compare(n->element,element) == 0)
		return n;
	*added=1;
	return addElementAfterX(n,element,ol->l);
}

void destroyList(List* l){
	apply(l,destroyElement,l->destroyElement,NULL);
	int i=0;
	Node *n = l->head, *tmp;
	for(i=0 ; i < l->size;i++){
		tmp=n;
		n=n->next;
		free(tmp);
	}
	free(l);
}

void destroyOrderedList(OrderedList* ol){
	destroyList(ol->l);
	free(ol);
}

