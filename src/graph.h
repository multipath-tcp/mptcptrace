/*
 * graph.h
 *
 *  Created on: Jan 9, 2014
 *      Author: Benjamin Hesmans
 */

#ifndef GRAPH_H_
#define GRAPH_H_

#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include "mptcptrace.h"

#define TIMEVAL		"timeval"
#define DOUBLE		"double"

#define LABELSEQ		"Sequence number"
#define LABELTIME		"Time"

#define ACTIVE_MODULE	1
#define UNACTIVE_MODULE	0
#define GP_INTERV		50

#define	XPLOT_WRITER	0
#define GOOGLE_WRITER	1
#define CSV_WRITER		2

#define RTT_ARRIVAL		1
#define RTT_SEQ_DEP		2
#define RTT_SEQ_NUM		4


#define RTT_ARRIVAL_GRAPH	0
#define RTT_SEQ_DEP_GRAPH	1
#define RTT_SEQ_NUM_GRAPH	2
#define RTT_GRAPHS		3

#define WINDOW_CLOSE_TO_FS	10000

#define MAX_SF			32

typedef struct graphModule graphModule;
typedef struct tcpGraphModule tcpGraphModule;
typedef struct Writer Writer;

typedef struct seqData seqData;
typedef struct bwData bwData;
typedef struct winFlightData winFlightData;
typedef struct tcpWinFlightData tcpWinFlightData;
typedef struct wFSData wFSData;
typedef struct rTTData rTTData;
typedef struct asData asData;
typedef struct seriesData seriesData;
/******
 * xplot writer
 */

void xpl_verticalLine(FILE* f, unsigned int x, unsigned int y, unsigned long h, int color);
void xpl_verticalLineTime(FILE* f, struct timeval tsx, unsigned int y, unsigned int h, int color);
void xpl_diamondTime(FILE *f, struct timeval tsx, unsigned int y, int color);
void xpl_diamondTimeDouble(FILE *f, struct timeval tsx, double y, int color);
void xpl_textTime(FILE *f, struct timeval tsx, unsigned int y, char* text, int color);
void xpl_writeHeader(FILE *f,char *way, char* title, char *xtype, char *ytype, char * xlabel, char *ylabel);
void xpl_writeFooter(FILE *f,char *way, char* title, char *xtype, char *ytype, char * xlabel, char *ylabel);
FILE* xpl_openGraphFile(char *name, int id, int way);
void xpl_writeSeries(FILE *f, char *type, char *name);

void gg_verticalLine(FILE* f, unsigned int x, unsigned int y, unsigned long h, int color);
void gg_verticalLineTime(FILE* f, struct timeval tsx, unsigned int y, unsigned int h, int color);
void gg_diamondTime(FILE *f, struct timeval tsx, unsigned int y, int color);
void gg_diamondTimeDouble(FILE *f, struct timeval tsx, double y, int color);
void gg_textTime(FILE *f, struct timeval tsx, unsigned int y, char* text, int color);
void gg_writeHeader(FILE *f,char *way, char* title, char *xtype, char *ytype, char * xlabel, char *ylabel);
void gg_writeFooter(FILE *f,char *way, char* title, char *xtype, char *ytype, char * xlabel, char *ylabel);
FILE* gg_openGraphFile(char *name, int id, int way);
void gg_writeSeries(FILE *f, char *type, char *name);

void csv_verticalLine(FILE* f, unsigned int x, unsigned int y, unsigned long h, int color);
void csv_verticalLineTime(FILE* f, struct timeval tsx, unsigned int y, unsigned int h, int color);
void csv_diamondTime(FILE *f, struct timeval tsx, unsigned int y, int color);
void csv_diamondTimeDouble(FILE *f, struct timeval tsx, double y, int color);
void csv_textTime(FILE *f, struct timeval tsx, unsigned int y, char* text, int color);
void csv_writeHeader(FILE *f,char *way, char* title, char *xtype, char *ytype, char * xlabel, char *ylabel);
void csv_writeFooter(FILE *f,char *way, char* title, char *xtype, char *ytype, char * xlabel, char *ylabel);
FILE* csv_openGraphFile(char *name, int id, int way);
void csv_writeSeries(FILE *f, char *type, char *name);

void initSeq(void** graphData, MPTCPConnInfo *mci);
void seqGrahSeq(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_map *seq,  void* graphData, MPTCPConnInfo *mi, int way);
void seqGrahAck(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_ack *ack,  void* graphData, MPTCPConnInfo *mi, int way);
void destroySeq(void** graphData, MPTCPConnInfo *mci);
void handleNewSFSeq(mptcp_sf *msf, void* graphData, MPTCPConnInfo *mi);

void initAS(void** graphData, MPTCPConnInfo *mci);
void asGrahSeq(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_map *seq,  void* graphData, MPTCPConnInfo *mi, int way);
void asGrahAck(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_ack *ack,  void* graphData, MPTCPConnInfo *mi, int way);
void destroyAS(void** graphData, MPTCPConnInfo *mci);

void initCI(void** graphData, MPTCPConnInfo *mci);
void CISeq(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_map *seq,  void* graphData, MPTCPConnInfo *mi, int way);
void CIAck(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_ack *ack,  void* graphData, MPTCPConnInfo *mi, int way);
void destroyCI(void** graphData, MPTCPConnInfo *mci);

void initWinFlight(void** graphData, MPTCPConnInfo *mci);
void winFlightSeq(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_map *seq,  void* graphData, MPTCPConnInfo *mi, int way);
void winFlightAck(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_ack *ack,  void* graphData, MPTCPConnInfo *mi, int way);
void destroyWinFlight(void** graphData, MPTCPConnInfo *mci);

void initTcpWinFlight(void** graphData, MPTCPConnInfo *mci);
void tcpWinFlight(struct sniff_ip *rawIP,struct sniff_tcp *rawTCP, mptcp_sf *msf, void* graphData, MPTCPConnInfo *mi, int way);
void destroyTcpWinFlight(void** graphData, MPTCPConnInfo *mci);

void initBW(void** graphData, MPTCPConnInfo *mci);
void bWSeq(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_map *seq,  void* graphData, MPTCPConnInfo *mi, int way);
void bWAck(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_ack *ack,  void* graphData, MPTCPConnInfo *mi, int way);
void destroyBW(void** graphData, MPTCPConnInfo *mci);

void initWFS(void** graphData, MPTCPConnInfo *mci);
void wFSSeq(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_map *seq,  void* graphData, MPTCPConnInfo *mi, int way);
void wFSAck(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_ack *ack,  void* graphData, MPTCPConnInfo *mi, int way);
void destroyWFS(void** graphData, MPTCPConnInfo *mci);

void initSeries(void** graphData, MPTCPConnInfo *mci);
void seriesSeq(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_map *seq,  void* graphData, MPTCPConnInfo *mi, int way);
void seriesAck(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_ack *ack,  void* graphData, MPTCPConnInfo *mi, int way);
void destroySeries(void** graphData, MPTCPConnInfo *mci);
void handleNewSFSeries(mptcp_sf *msf, void* graphData, MPTCPConnInfo *mi);


void initRTT(void** graphData, MPTCPConnInfo *mci);
void rTTSeq(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_map *seq,  void* graphData, MPTCPConnInfo *mi, int way);
void rTTAck(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_ack *ack,  void* graphData, MPTCPConnInfo *mi, int way);
void destroyRTT(void** graphData, MPTCPConnInfo *mci);

struct bwData{
	FILE *graph[WAYS];
	mptcp_ack *mpa[WAYS];
	unsigned long int ackedData[WAYS];
	int bucket[WAYS];
	mptcp_ack *fmpa[WAYS];
	mptcp_ack **lastNacks[WAYS];
	int movingAvg[WAYS];
	int movingAvgFull[WAYS];
	//we may need other data to calculate the bandwidth
};

struct seqData{
	FILE *graph[WAYS];
	OrderedList *seq[WAYS];
	unsigned int reinject[WAYS];
	unsigned int reinjectNTimes[WAYS][MAX_SF];
};

struct asData{
	FILE *graph[WAYS];
};

struct seriesData{
	FILE *graph[WAYS];
};

struct wFSData{
	FILE *f;
	unsigned int *n[WAYS];
	unsigned int *nWighted[WAYS];
};

struct rTTData{
	FILE *graph[RTT_GRAPHS][WAYS];
	float rttMin[WAYS];
	float rttMax[WAYS];
	//avg std...
};

struct winFlightData{
	FILE *graph[WAYS];
	FILE *graphRE[WAYS];
	FILE *graph2[WAYS]; /* per flow usage,  use flight size */
	unsigned int rightEdge[WAYS];
	unsigned int *mpFlightSize[WAYS];
	unsigned int *mpWindow[WAYS];
	unsigned int *tcpSumFlightSize[WAYS];
};

struct tcpWinFlightData{

};

struct graphModule{
	int activated;
	char *name;
	void (*initModule)(void** graphData, MPTCPConnInfo *mci);
	//maybe pass the raw tcp packet.
	void (*handleMPTCPSeq)(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_map *seq, void* graphData, MPTCPConnInfo *mi, int way);
	void (*handleMPTCPAck)(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_ack *ack, void* graphData, MPTCPConnInfo *mi, int way);
	void (*destroyModule)(void** graphData, MPTCPConnInfo *mci);
	void (*handleNewSF)(mptcp_sf *msf, void* graphData, MPTCPConnInfo *mi);
};

struct tcpGraphModule{
	int activated;
	char *name;
	void (*initModule)(void** graphData, MPTCPConnInfo *mci);
	//maybe pass the raw tcp packet.
	void (*handleTCP)(struct sniff_ip *rawIP,struct sniff_tcp *rawTCP, mptcp_sf *msf, void* graphData, MPTCPConnInfo *mi, int way);
	void (*destroyModule)(void** graphData, MPTCPConnInfo *mci);
};

struct Writer{
	FILE * (*openFile) (char *name, int id, int way);
	void (*writeHeader)(FILE *f,char *way, char* title, char *xtype, char *ytype, char * xlabel, char *ylabel);
	void (*writeTimeDot)(FILE *f, struct timeval tsx, unsigned int y, int color);
	void (*writeTimeDotDouble)(FILE *f, struct timeval tsx, double y, int color);
	void (*writeTimeVerticalLine) (FILE* f, struct timeval tsx, unsigned int y, unsigned int h, int color);
	void (*writeTimeVerticalLineDouble) (FILE* f, struct timeval tsx, unsigned int y, double h, int color);
	void (*writeTextTime) (FILE *f, struct timeval tsx, unsigned int y, char* text, int color);
	void (*writeFooter)(FILE *f,char *way, char* title, char *xtype, char *ytype, char * xlabel, char *ylabel);
	void (*writeSeries)(FILE *f, char *type, char *name);
};

extern graphModule modules[];
extern Writer Boris[];
extern int Vian;
extern tcpGraphModule tcpModules[];
extern int gpInterv;
extern int flight_select;
extern int rtt_select;

#define FLIGHT_REG		1
#define FLIGHT_PER_FLOW	2
#define FLIGHT_RE		4



#endif /* GRAPH_H_ */
