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

#define WINDOW_CLOSE_TO_FS	10000

typedef struct graphModule graphModule;
typedef struct tcpGraphModule tcpGraphModule;
typedef struct Writer Writer;

typedef struct seqData seqData;
typedef struct bwData bwData;
typedef struct winFlightData winFlightData;
typedef struct tcpWinFlightData tcpWinFlightData;
typedef struct wFSData wFSData;

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

void gg_verticalLine(FILE* f, unsigned int x, unsigned int y, unsigned long h, int color);
void gg_verticalLineTime(FILE* f, struct timeval tsx, unsigned int y, unsigned int h, int color);
void gg_diamondTime(FILE *f, struct timeval tsx, unsigned int y, int color);
void gg_diamondTimeDouble(FILE *f, struct timeval tsx, double y, int color);
void gg_textTime(FILE *f, struct timeval tsx, unsigned int y, char* text, int color);
void gg_writeHeader(FILE *f,char *way, char* title, char *xtype, char *ytype, char * xlabel, char *ylabel);
void gg_writeFooter(FILE *f,char *way, char* title, char *xtype, char *ytype, char * xlabel, char *ylabel);
FILE* gg_openGraphFile(char *name, int id, int way);

void initSeq(void** graphData, MPTCPConnInfo *mci);
void seqGrahSeq(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_map *seq,  void* graphData, MPTCPConnInfo *mi, int way);
void seqGrahAck(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_ack *ack,  void* graphData, MPTCPConnInfo *mi, int way);
void destroySeq(void** graphData, MPTCPConnInfo *mci);

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

struct bwData{
	FILE *graph[WAYS];
	mptcp_ack *mpa[WAYS];
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
};

struct wFSData{
	FILE *f;
	unsigned int *n[WAYS];
	unsigned int *nWighted[WAYS];
};

struct winFlightData{
	FILE *graph[WAYS];
	FILE *graphRE[WAYS];
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
};

extern graphModule modules[];
extern Writer Boris[];
extern int Vian;
extern tcpGraphModule tcpModules[];
extern int gpInterv;

#endif /* GRAPH_H_ */
