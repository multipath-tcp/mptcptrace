AUTOMAKE_OPTIONS = subdir-objects
TESTS = check_t1
check_PROGRAMS = check_t1
check_t1_SOURCES = check_t1.c ../src/list.h ../src/list.c
check_t1_CFLAGS = @CHECK_CFLAGS@
check_t1_LDADD = @CHECK_LIBS@ -lm -lpthread -lrt
