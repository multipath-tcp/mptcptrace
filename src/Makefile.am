
bin_PROGRAMS = mptcptrace
mptcptrace_SOURCES = mptcptrace.c TCPOptions.c allocations.c MPTCPList.c list.c graph.c timingTools.c traceInfo.c

mptcptrace_LDADD =  -lpcap @CRYPTO_LIBS@
mptcptrace_LDFLAGS = $(AM_LDFLAGS) -ggdb -gdwarf-2 -g3
mptcptrace_CFLAGS = $(AM_CFLAGS) @CRYPTO_CFLAGS@
