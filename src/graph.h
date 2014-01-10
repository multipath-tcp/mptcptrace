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

typedef struct graphModule graphModule;
typedef struct seqData seqData;
typedef struct winFlightData winFlightData;


void initSeq(void** graphData, MPTCPConnInfo *mci);
void seqGrahSeq(mptcp_sf *msf, mptcp_map *seq,  void* graphData, MPTCPConnInfo *mi, int way);
void seqGrahAck(mptcp_sf *msf, mptcp_ack *ack,  void* graphData, MPTCPConnInfo *mi, int way);
void destroySeq(void** graphData, MPTCPConnInfo *mci);

void initCI(void** graphData, MPTCPConnInfo *mci);
void CISeq(mptcp_sf *msf, mptcp_map *seq,  void* graphData, MPTCPConnInfo *mi, int way);
void CIAck(mptcp_sf *msf, mptcp_ack *ack,  void* graphData, MPTCPConnInfo *mi, int way);
void destroyCI(void** graphData, MPTCPConnInfo *mci);

void initWinFlight(void** graphData, MPTCPConnInfo *mci);
void winFlightSeq(mptcp_sf *msf, mptcp_map *seq,  void* graphData, MPTCPConnInfo *mi, int way);
void winFlightAck(mptcp_sf *msf, mptcp_ack *ack,  void* graphData, MPTCPConnInfo *mi, int way);
void destroyWinFlight(void** graphData, MPTCPConnInfo *mci);

struct seqData{
	FILE *graph[WAYS];
	OrderedList *seq[WAYS];
};

struct winFlightData{
	FILE *graph[WAYS];
	unsigned int rightEdge[WAYS];
};

struct graphModule{
	int activated;
	char *name;
	void (*initModule)(void** graphData, MPTCPConnInfo *mci);
	//maybe pass the raw tcp packet.
	void (*handleMPTCPSeq)(mptcp_sf *msf, mptcp_map *seq, void* graphData, MPTCPConnInfo *mi, int way);
	void (*handleMPTCPAck)(mptcp_sf *msf, mptcp_ack *ack, void* graphData, MPTCPConnInfo *mi, int way);
	void (*destroyModule)(void** graphData, MPTCPConnInfo *mci);
};
extern graphModule modules[];


#endif /* GRAPH_H_ */
