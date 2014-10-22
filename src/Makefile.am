
bin_PROGRAMS = mptcptrace
mptcptrace_SOURCES = mptcptrace.c TCPOptions.c allocations.c MPTCPList.c list.c graph.c timingTools.c

GIT_VERSION = `git describe --abbrev=0 --dirty --always`

mptcptrace_LDADD =  -lpcap @CRYPTO_LIBS@
mptcptrace_LDFLAGS = -ggdb
mptcptrace_CFLAGS = -DVERSION=\"$(GIT_VERSION)\" @CRYPTO_CFLAGS@
