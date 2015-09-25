/*
 * traceInfo.h
 *
 *  Created on: Nov 24, 2014
 *      Author: bhesmans
 */

#ifndef TRACEINFO_H_
#define TRACEINFO_H_

#include <stdlib.h>
#include <stdio.h>

#include "mptcptrace.h"

enum{
	CONNECTION_COUNTER,
	SUBFLOW_COUNTER,
	FAST_CLOSE_COUNTER,
	FINISHED_COUNTER,
	JOIN_FAILED_COUNTER,
	FAST_CLOSE_SEEN_COUNTER,
	JOIN_WRONG_HMAC_COUNTER,
	SYNACK_DIFFKEY_COUNTER,
	CONN_TIMEOUT_COUNTER,
	CAPABLE_AFTER_JOIN_REUSE_PORT,
	MAX_COUNTER
};

typedef struct traceCounter traceCounter;
typedef struct logLevel logLevel;

struct traceCounter{
	int id;
	int val[WAYS];
	char *name;
};

struct logLevel{
	int id;
	char *desc;
};

void printLogHelp();
void incCounter(int counterID, int way);
void destroyTraceInfo();
void mplog(int level, char* fmt, ...);
void mplogmsf(int level, mptcp_sf *msf, char* fmt, ...);

enum{
	BUG		= 1,
	WARN	= 2,
	INFO	= 4,
	CONNINFO = 8,
	LOGALL	= 16,
};

#endif /* TRACEINFO_H_ */
