#include "traceInfo.h"
#include <stdio.h>
#include <stdarg.h>

FILE *logFile=NULL;
FILE *statFile=NULL;

traceCounter counters[] = {
		{
				CONNECTION_COUNTER,
				{0,0},
				"nbConnections"
		},
		{
				SUBFLOW_COUNTER,
				{0,0},
				"sfConnections"
		},
		{
				FAST_CLOSE_COUNTER,
				{0,0},
				"nbFastClose"
		},
		{
				FINISHED_COUNTER,
				{0,0},
				"finishedConnections"
		},
		{
				JOIN_FAILED_COUNTER,
				{0,0},
				"joinFailed"
		},
		{
				FAST_CLOSE_SEEN_COUNTER,
				{0,0},
				"nbFastCloseSeen"
		},
		{
				JOIN_WRONG_HMAC_COUNTER,
				{0,0},
				"JoinWrongHMAC"
		},
		{
				SYNACK_DIFFKEY_COUNTER,
				{0,0},
				"DiffKeyInSynack"
		},
		{
				CONN_TIMEOUT_COUNTER,
				{0,0},
				"connTimeOut"
		},
		{
				CAPABLE_AFTER_JOIN_REUSE_PORT,
				{0,0},
				"capaToJoinReuse"
		},
		{
				SUSPECT_JOIN_REJECTED,
				{0,0},
				"suspectJoinRejected"
		},
		{
			THIRD_ACK_KEYDIFF,
			{0,0},
			"thirdAckKeyDiff"
		},

};

logLevel logs[] = {
		{
				BUG,
				"Everything considered to be bug"
		},
		{
				WARN,
				"Everything considered to be a warning"
		},
		{
				CONNINFO,
				"Print connection informations when we remove it"
		},
		{
				LOGALL,
				"Unclassified ..."
		}
};

void printLogHelp(){
	int i;
	logLevel l;
	printf("\t -l X option let you chose what should be logged by mptcptrace...\n");
	for(i = 0 ; i < sizeof(logs)/sizeof(logLevel); i++){
		l = logs[i];
		printf("\t\tLog level %d : %s\n", l.id, l.desc);
	}
	printf("\t   Options may be combined.\n");
}

void mplog(int level, char* fmt, ...){
    if (level & paramLevel) {
            va_list args;
            va_start(args, fmt);
            vfprintf(logFile,fmt, args);
            va_end(args);
    }
}
void mplogmsf(int level, mptcp_sf *msf, char* fmt, ...){
    if (level & paramLevel) {
            va_list args;
            va_start(args, fmt);
            vfprintf(logFile,fmt, args);
            va_end(args);
            printMPTCPSubflow(msf,0,logFile,NULL);
    }
}

//void mplogWithMsf(mptcp_sf*, int level, char* fmt, ...)

void initTraceInfo(){
	 logFile = fopen("mptcptrace.log","w");
	 statFile = fopen("file_stats.csv","w");
}

void writeCounters(){
	int i;
	for(i=0; i<MAX_COUNTER;i++){
		fprintf(statFile,"%s,%i,%i\n",counters[i].name, counters[i].val[C2S],counters[i].val[S2C]);
	}
}

void destroyTraceInfo(){
	writeCounters();
	fflush(logFile);
	fflush(statFile);
	fclose(logFile);
	fclose(statFile);
}

void incCounter(int counterID, int way){
	counters[counterID].val[way]++;
}

