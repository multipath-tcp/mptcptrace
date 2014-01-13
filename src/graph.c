/*
 * graph.c
 *
 *  Created on: Jan 9, 2014
 *      Author: Benjamin Hesmans
 */

#include "graph.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "mptcptrace.h"
#include "allocations.h"
#include "MPTCPList.h"


graphModule modules[]={
		{ACTIVE_MODULE,
		"Global informations.",
		initCI,
		CISeq,
		CIAck,
		destroyCI},
		{
		UNACTIVE_MODULE,
		"Sequence Graph",
		initSeq,
		seqGrahSeq,
		seqGrahAck,
		destroySeq},
		{
		UNACTIVE_MODULE,
		"Window and flight size graph",
		initWinFlight,
		winFlightSeq,
		winFlightAck,
		destroyWinFlight,
		},
		{ACTIVE_MODULE,
		"MPTCP goodput",
		initBW,
		bWSeq,
		bWAck,
		destroyBW}
};

tcpGraphModule tcpModules[]={
		{ACTIVE_MODULE,
		"TCP flight size",
		initTcpWinFlight,
		tcpWinFlight,
		destroyTcpWinFlight},
};
char* wayString[]={"s2c","c2s"};

/******
 * helper
 */
//diamond etc, and all helper
void verticalLine(FILE* f, unsigned int x, unsigned int y, unsigned long h, int color){
	//TODO
}

void verticalLineTime(FILE* f, struct timeval tsx, unsigned int y, unsigned int h, int color){
	fprintf(f,"%i\n",color);
	fprintf(f,"line %li.%06li %u %li.%06li %u \n",tsx.tv_sec, tsx.tv_usec,y,tsx.tv_sec, tsx.tv_usec,y+h);
}

void diamondTime(FILE *f, struct timeval tsx, unsigned int y, int color){
	fprintf(f,"%i\n",color);
	fprintf(f,"diamond %li.%06li %u\n",tsx.tv_sec, tsx.tv_usec,y);
}

void diamondTimeDouble(FILE *f, struct timeval tsx, double y, int color){
	fprintf(f,"%i\n",color);
	fprintf(f,"diamond %li.%06li %f\n",tsx.tv_sec, tsx.tv_usec,y);
}

void textTime(FILE *f, struct timeval tsx, unsigned int y, char* text, int color){
	fprintf(f,"%i\n",color);
	fprintf(f,"atext %li.%06li %u\n R \n",tsx.tv_sec, tsx.tv_usec,y);
}
void writeHeader(FILE *f,char *way, char* title, char *xtype, char *ytype, char * xlabel, char *ylabel){
	fprintf(f,\
			"%s %s\n" \
			"title\n" \
			"%s - %s\n" \
			"xlabel\n" \
			"%s\n" \
			"ylabel\n" \
			"%s\n",xtype, ytype, way, title,xlabel,ylabel);
}

FILE* openGraphFile(char *name, int id, int way){
	char str[42];
	sprintf(str,"%s_%s_%d.xpl",wayString[way],name,id);
	return fopen(str,"w");
	//TODO header ?
}

/**
 * sequence graph
 */

void initSeq(void** graphData, MPTCPConnInfo *mci){
	seqData* data = (seqData*) exitMalloc(sizeof(seqData));
	*graphData = data;
	data->graph[S2C] = openGraphFile("seq",mci->mc->id,S2C);
	data->graph[C2S] = openGraphFile("seq",mci->mc->id,C2S);
	writeHeader(data->graph[S2C],wayString[S2C],"Time sequence",TIMEVAL,DOUBLE,LABELTIME,LABELSEQ);
	writeHeader(data->graph[C2S],wayString[C2S],"Time sequence",TIMEVAL,DOUBLE,LABELTIME,LABELSEQ);
	data->seq[S2C] = newOrderedList(NULL,compareMap);
	data->seq[C2S] = newOrderedList(NULL,compareMap);
	fprintf(stderr,"Seq graph init...\n");
}

int isReinjected(Node *n, List *seq){
	mptcp_map *prevmap = n->previous == NULL ? NULL : (mptcp_map*) n->previous->element;
	mptcp_map *currmap =  (mptcp_map*) n->element;

	if(n->previous != NULL && SEQ_MAP_END(prevmap) > SEQ_MAP_START(currmap) && prevmap->msf != currmap->msf){
		return prevmap->msf->id;
	}

	return -1;
}

void seqGrahSeq(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_map *seq, void* graphData, MPTCPConnInfo *mi, int way){
	seqData *data = ((seqData*) graphData);
	Node *n = addElementOrderedReverse(seq,data->seq[way]);
	int reinject = isReinjected(n,data->seq[way]->l);
	if( reinject >= 0)
		textTime(data->graph[way],seq->ts,SEQ_MAP_END(seq),"R",reinject);
	verticalLineTime(data->graph[way],seq->ts,SEQ_MAP_START(seq),SEQ_MAP_LEN(seq),msf->id);
}

void seqGrahAck(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_ack *ack, void* graphData, MPTCPConnInfo *mi, int way){
	seqData *data = ((seqData*) graphData);
	diamondTime(data->graph[TOGGLE(way)],ack->ts,ACK_MAP(ack),msf->id);
}

void destroySeq(void** graphData, MPTCPConnInfo *mci){
	seqData *data = ((seqData*) *graphData);
	fclose(data->graph[S2C]);
	fclose(data->graph[C2S]);
	fprintf(stderr,"Seq graph Destroy...\n");
}

/**
 * global information
 */
void initCI(void** graphData, MPTCPConnInfo *mci){
	printf("create global informations\n");
	mci->unacked[S2C] = newOrderedList(NULL,compareMap);
	mci->unacked[C2S] = newOrderedList(NULL,compareMap);
	mci->lastack[S2C] = NULL;
	mci->lastack[C2S] = NULL;
}




void CISeq(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_map *seq,  void* graphData, MPTCPConnInfo *mi, int way){
	int added;
	if(mi->lastack[TOGGLE(way)] == NULL  ||  SEQ_MAP_END( seq ) >= ACK_MAP(mi->lastack[TOGGLE(way)]))
		addElementOrderedReverseUnique(seq,mi->unacked[way],&added);
}

void stripUnack(mptcp_ack *ack, List *unacked){
	while(unacked->size > 0 && SEQ_MAP_END( ((mptcp_map*)unacked->head->element) ) <= ACK_MAP(ack))
		removeHead(unacked);
}

void CIAck(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_ack *ack,  void* graphData, MPTCPConnInfo *mi, int way){
	stripUnack(ack, mi->unacked[TOGGLE(way)]->l);
	if(mi->lastack[way] == NULL || ACK_MAP(mi->lastack[way]) < ACK_MAP(ack)){
		mi->lastack[way] = ack;
	}

}
void destroyCI(void** graphData, MPTCPConnInfo *mci){
	printf("Destroy global informations\n");
}

/***
 * Flight and window
 */
void initWinFlight(void** graphData, MPTCPConnInfo *mci){
	winFlightData* data = (winFlightData*) exitMalloc(sizeof(winFlightData));
	*graphData = data;
	data->graph[S2C] = openGraphFile("flight",mci->mc->id,S2C);
	data->graph[C2S] = openGraphFile("flight",mci->mc->id,C2S);
	writeHeader(data->graph[S2C],wayString[S2C],"Window and MPTCP flight size",TIMEVAL,DOUBLE,LABELTIME,"size");
	writeHeader(data->graph[C2S],wayString[C2S],"Window and MPTCP flight size",TIMEVAL,DOUBLE,LABELTIME,"size");
	data->rightEdge[S2C] = 0;
	data->rightEdge[C2S] = 0;
}

void sumFlight(void* element, int pos, void *fix, void *acc){
	mptcp_sf *msf = (mptcp_sf*) element;
	tcp_map *funa,*luna;
	unsigned int *sum = (int*) acc;
	int *way = (int*) fix;
	if(msf->tcpUnacked[*way]->l->size > 0){
		funa = (tcp_map*) msf->tcpUnacked[*way]->l->head->element;
		luna = (tcp_map*) msf->tcpUnacked[*way]->l->tail->element;
		*sum = (*sum) + (luna->end - funa->start);
	}
}

void winFlightSeq(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_map *seq,  void* graphData, MPTCPConnInfo *mi, int way){
	winFlightData *data = ((winFlightData*) graphData);
	mptcp_map *funa,*luna;
	unsigned int flightSum=0;
	if(mi->unacked[way]->l->size > 0){
		funa = (mptcp_map*) mi->unacked[way]->l->head->element;
		luna = (mptcp_map*) mi->unacked[way]->l->tail->element;
		diamondTime(data->graph[way],seq->ts,SEQ_MAP_END(luna) - SEQ_MAP_START(funa) ,2);
	}
	apply(msf->mc_parent->mptcp_sfs,sumFlight, &way, &flightSum);
	diamondTime(data->graph[way],seq->ts,flightSum ,3);
}

void winFlightAck(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_ack *ack,  void* graphData, MPTCPConnInfo *mi, int way){
	winFlightData *data = ((winFlightData*) graphData);
	mptcp_map *funa,*luna;
	unsigned int flightSum=0;
	if(data->rightEdge[way] == 0 || data->rightEdge[way] < ack->right_edge){
		data->rightEdge[way] = ack->right_edge;
	}
	if(mi->lastack[way] != NULL){
		diamondTime(data->graph[TOGGLE(way)],ack->ts,data->rightEdge[way] - ACK_MAP(mi->lastack[way]),1);
	}
	if(mi->unacked[TOGGLE(way)]->l->size > 0){
		funa = (mptcp_map*) mi->unacked[TOGGLE(way)]->l->head->element;
		luna = (mptcp_map*) mi->unacked[TOGGLE(way)]->l->tail->element;
		diamondTime(data->graph[TOGGLE(way)],ack->ts,SEQ_MAP_END(luna) - SEQ_MAP_START(funa) ,2);
	}
	apply(msf->mc_parent->mptcp_sfs,sumFlight, &way, &flightSum);
	diamondTime(data->graph[way],ack->ts,flightSum ,3);

}
void destroyWinFlight(void** graphData, MPTCPConnInfo *mci){
	winFlightData *data = ((winFlightData*) *graphData);
	fclose(data->graph[S2C]);
	fclose(data->graph[C2S]);
}

/****
 * TCP win  and flight... As the name does not suggest, just take a look at the flight size.
 */

void updateTCPUnack(struct sniff_ip *rawIP, struct sniff_tcp *rawTCP,mptcp_sf *msf, int way){
	tcp_map *seq = (tcp_map*)exitMalloc(sizeof(tcp_map));
	seq->start = TCP_SEQ(rawTCP);
	seq->end = seq->start + ntohs(rawIP->ip_len) - 4*(IP_HL(rawIP)) - 4*(TH_OFF(rawTCP));
	int added;
	if(msf->tcpLastAck[TOGGLE(way)] == NULL || seq->start >= *(msf->tcpLastAck[TOGGLE(way)]))
		addElementOrderedReverseUnique(seq,msf->tcpUnacked[way],&added);
}

void updateLastAck(struct sniff_tcp *rawTCP,mptcp_sf *msf, int way){
	unsigned int *ack;
	if(!ACK_SET(rawTCP)) return;
	ack = (unsigned int*)exitMalloc(sizeof(unsigned int));
	*ack = TCP_ACK(rawTCP);
	if(msf->tcpLastAck[way] == NULL || msf->tcpLastAck[way] < ack)
		msf->tcpLastAck[way] = ack;
}
void stripTCPUnack(struct sniff_tcp *rawTCP, List *unacked){
	unsigned int *ack = (unsigned int*)exitMalloc(sizeof(unsigned int));
	*ack = TCP_ACK(rawTCP);
	if(!ACK_SET(rawTCP)) return;
	while(unacked->size > 0 && ((tcp_map*)unacked->head->element)->end <= *ack)
		removeHead(unacked);
}
void initTcpWinFlight(void** graphData, MPTCPConnInfo *mci){

}
void tcpWinFlight(struct sniff_ip *rawIP, struct sniff_tcp *rawTCP, mptcp_sf *msf, void* graphData, MPTCPConnInfo *mi, int way){
	updateTCPUnack(rawIP,rawTCP,msf,way);
	updateLastAck(rawTCP,msf,way);
	stripTCPUnack(rawTCP,msf->tcpUnacked[TOGGLE(way)]->l);

}
void destroyTcpWinFlight(void** graphData, MPTCPConnInfo *mci){

}

/***
 * MPTCP bandwidth calculation
 */
void initBW(void** graphData, MPTCPConnInfo *mci){
	bwData* data = (bwData*) exitMalloc(sizeof(bwData));
	*graphData = data;
	data->graph[S2C] = openGraphFile("gput",mci->mc->id,S2C);
	data->graph[C2S] = openGraphFile("gput",mci->mc->id,C2S);
	writeHeader(data->graph[S2C],wayString[S2C],"MPTCP goodput",TIMEVAL,DOUBLE,LABELTIME,"Goodput");
	writeHeader(data->graph[C2S],wayString[C2S],"MPTCP goodput",TIMEVAL,DOUBLE,LABELTIME,"Goodput");
	data->mpa[S2C] = NULL;
	data->mpa[C2S] = NULL;
	data->bucket[S2C] = 0;
	data->bucket[C2S] = 0;
}

void bWSeq(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_map *seq,  void* graphData, MPTCPConnInfo *mi, int way){
	bwData *data = ((bwData*) graphData);
	//DO something
}

void bWAck(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_ack *ack,  void* graphData, MPTCPConnInfo *mi, int way){
	bwData *data = ((bwData*) graphData);
	struct timeval tmp = ack->ts;
	struct timeval tmp2 = ack->ts;
	if(data->mpa[way]==NULL){
		data->mpa[way]=ack;
		data->fmpa[way]=ack;
	}
	else{
		if(ACK_MAP(ack) <= ACK_MAP(data->mpa[way]) )
				return;
		if(data->bucket[way] == gpInterv){
			//TODO gestion des ack plus anciens !
			tv_sub(&tmp,data->mpa[way]->ts);
			diamondTimeDouble(data->graph[TOGGLE(way)],ack->ts,(ACK_MAP(ack) - ACK_MAP(data->mpa[way]))/(tmp.tv_sec+tmp.tv_usec/1000000.0) / 1000000.0,1);
			data->bucket[way]=0;
			data->mpa[way] = ack;

		}
		else
			data->bucket[way]++;
		tv_sub(&tmp2,data->fmpa[way]->ts);
		diamondTimeDouble(data->graph[TOGGLE(way)],ack->ts,(ACK_MAP(ack) - ACK_MAP(data->fmpa[way]))/(tmp2.tv_sec+tmp2.tv_usec/1000000.0) / 1000000.0 ,2);
	}


}
void destroyBW(void** graphData, MPTCPConnInfo *mci){
	bwData *data = ((bwData*) *graphData);
	fclose(data->graph[S2C]);
	fclose(data->graph[C2S]);
}
