/*
 * t1.c
 *
 *  Created on: Dec 24, 2013
 *      Author: Benjamin Hesmans
 */
#include <stdio.h>
#include <stdlib.h>
#include <check.h>
#include "../src/list.h"

int searchInt(void* element,int pos, void* arg, void* acc){
	return (*((int*)element)) == *((int*) arg);
}
int searchNth(void* element,int pos, void* arg, void* acc){
	return pos == *((int*) arg);
}

int compareInt(void* e1, void *e2){
	if ( *((int*)e1) < *((int*)e2) ) return -1;
	return ( *((int*)e1) > *((int*)e2) ) ? 1 : 0;
}

void printInt(void* element, int pos, void *arg, void *acc){
	printf("%d\t%d\n",pos,*((int*)element));
}

void dontfree(void* element){
	return;
}
START_TEST (test_list_create_and_destroy)
{
	int *un, *deux, *trois;
	un = (int*) malloc(sizeof(int));
	deux = (int*) malloc(sizeof(int));
	trois = (int*) malloc(sizeof(int));
	*un = 1;
	*deux = 2;
	*trois = 3;

	List *l = newList(free);

	addElementHead(un,l);
	ck_assert_ptr_eq( (search(l,searchInt,deux,NULL)),NULL);

	addElementHead(deux,l);
	ck_assert_ptr_ne( (search(l,searchInt,deux,NULL)),NULL);

	addElementHead(trois,l);
	ck_assert_int_eq(l->size, 3);
	ck_assert_int_eq( *((int*)(search(l,searchInt,deux,NULL))),2);

	ck_assert_int_eq( *((int*)(search(l,searchNth,un,NULL))),2);

	destroyList(l);
}
END_TEST

START_TEST (test_olist_create_and_destroy)
{
	int zero, un, deux, trois, quatre;
	un = 1;
	deux = 2;
	trois = 3;
	zero = 0;
	quatre = 4;

	OrderedList *ol = newOrderedList(dontfree,compareInt);
	addElementOrdered(&un,ol);
	addElementOrdered(&deux,ol);
	addElementOrdered(&trois,ol);
	addElementOrdered(&deux,ol);
	addElementOrdered(&deux,ol);
	addElementOrdered(&trois,ol);
	addElementOrdered(&un,ol);
	//apply(ol->l,printInt,NULL,NULL);
	//applyReverse(ol->l,printInt,NULL,NULL);
	addElementOrderedReverse(&un,ol);
	addElementOrderedReverse(&deux,ol);
	addElementOrderedReverse(&trois,ol);
	addElementOrderedReverse(&quatre,ol);
	addElementOrderedReverse(&zero,ol);
	applyReverse(ol->l,printInt,NULL,NULL);
	apply(ol->l,printInt,NULL,NULL);

	//ck_assert_int_eq(ol->l->size,12);
	//ck_assert_int_eq( *((int*)(search(ol->l,searchNth,&trois,NULL))),1);

	destroyOrderedList(ol);
}
END_TEST

START_TEST (test_olist_create_and_destroy_unique)
{
	int zero, un, deux, trois, quatre, added;
	un = 1;
	deux = 2;
	trois = 3;
	zero = 0;
	quatre = 4;
	printf("reioazjoeirjezajreojaioer\n");
	OrderedList *ol = newOrderedList(dontfree,compareInt);
	addElementOrderedUnique(&un,ol,&added);
	addElementOrderedUnique(&deux,ol,&added);
	addElementOrderedUnique(&trois,ol,&added);
	addElementOrderedUnique(&deux,ol,&added);
	addElementOrderedUnique(&deux,ol,&added);
	addElementOrderedUnique(&trois,ol,&added);
	addElementOrderedUnique(&un,ol,&added);
	//apply(ol->l,printInt,NULL,NULL);
	//applyReverse(ol->l,printInt,NULL,NULL);
	addElementOrderedReverseUnique(&un,ol,&added);
	addElementOrderedReverseUnique(&deux,ol,&added);
	addElementOrderedReverseUnique(&trois,ol,&added);
	addElementOrderedReverseUnique(&quatre,ol,&added);
	addElementOrderedReverseUnique(&zero,ol,&added);
	applyReverse(ol->l,printInt,NULL,NULL);
	apply(ol->l,printInt,NULL,NULL);

	//ck_assert_int_eq(ol->l->size,12);
	//ck_assert_int_eq( *((int*)(search(ol->l,searchNth,&trois,NULL))),1);

	destroyOrderedList(ol);
}
END_TEST

Suite *
money_suite (void)
{
  Suite *s = suite_create ("SimpleList");
  /* Core test case */
  TCase *tc_core = tcase_create ("Core");
  tcase_add_test (tc_core, test_list_create_and_destroy);
  tcase_add_test (tc_core, test_olist_create_and_destroy);
  tcase_add_test (tc_core, test_olist_create_and_destroy_unique);
  suite_add_tcase (s, tc_core);

  return s;
}

int
main (void)
{
  int number_failed;
  Suite *s = money_suite ();
  SRunner *sr = srunner_create (s);
  srunner_run_all (sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed (sr);
  srunner_free (sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
