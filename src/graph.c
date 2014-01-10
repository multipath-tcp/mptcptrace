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
		}
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

void seqGrahSeq(mptcp_sf *msf, mptcp_map *seq, void* graphData, MPTCPConnInfo *mi, int way){
	seqData *data = ((seqData*) graphData);
	Node *n = addElementOrderedReverse(seq,data->seq[way]);
	int reinject = isReinjected(n,data->seq[way]->l);
	if( reinject >= 0)
		textTime(data->graph[way],seq->ts,SEQ_MAP_END(seq),"R",reinject);
	verticalLineTime(data->graph[way],seq->ts,SEQ_MAP_START(seq),SEQ_MAP_LEN(seq),msf->id);
}

void seqGrahAck(mptcp_sf *msf, mptcp_ack *ack, void* graphData, MPTCPConnInfo *mi, int way){
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
	mci->lastack[S2C]=NULL;
	mci->lastack[C2S]=NULL;
}
void CISeq(mptcp_sf *msf, mptcp_map *seq,  void* graphData, MPTCPConnInfo *mi, int way){
	int added;
	if(mi->lastack[TOGGLE(way)] == NULL  ||  SEQ_MAP_END( seq ) >= ACK_MAP(mi->lastack[TOGGLE(way)]))
		addElementOrderedReverseUnique(seq,mi->unacked[way],&added);
}

void stripUnack(mptcp_ack *ack, List *unacked){
	while(unacked->size > 0 && SEQ_MAP_END( ((mptcp_map*)unacked->head->element) ) <= ACK_MAP(ack))
		removeHead(unacked);
}

void CIAck(mptcp_sf *msf, mptcp_ack *ack,  void* graphData, MPTCPConnInfo *mi, int way){
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
void winFlightSeq(mptcp_sf *msf, mptcp_map *seq,  void* graphData, MPTCPConnInfo *mi, int way){
	winFlightData *data = ((winFlightData*) graphData);
	mptcp_map *funa,*luna;
	if(mi->unacked[way]->l->size > 0){
		funa = (mptcp_map*) mi->unacked[way]->l->head->element;
		luna = (mptcp_map*) mi->unacked[way]->l->tail->element;
		diamondTime(data->graph[TOGGLE(way)],seq->ts,SEQ_MAP_END(luna) - SEQ_MAP_START(funa) ,2);
	}
}
void winFlightAck(mptcp_sf *msf, mptcp_ack *ack,  void* graphData, MPTCPConnInfo *mi, int way){
	winFlightData *data = ((winFlightData*) graphData);
	mptcp_map *funa,*luna;
	if(data->rightEdge[way] == 0 || data->rightEdge[way] < ack->right_edge){
		data->rightEdge[way] = ack->right_edge;
	}
	if(mi->lastack[way] != NULL){
		diamondTime(data->graph[way],ack->ts,data->rightEdge[way] - ACK_MAP(mi->lastack[way]),1);
	}
	if(mi->unacked[TOGGLE(way)]->l->size > 0){
		funa = (mptcp_map*) mi->unacked[TOGGLE(way)]->l->head->element;
		luna = (mptcp_map*) mi->unacked[TOGGLE(way)]->l->tail->element;
		diamondTime(data->graph[way],ack->ts,SEQ_MAP_END(luna) - SEQ_MAP_START(funa) ,2);
	}
	/*
	if(mi->lastack[way] == NULL){
		//Ensemble des unack = flight size
	}
	else{
		if(mi->unacked[TOGGLE(way)]->l->size > 0 ) {// et ack nouveau ?
			una = (mptcp_map*) mi->unacked[TOGGLE(way)]->l->tail->element;
			fprintf(stderr,"way %d size %d una %u lastack %u\n",way, mi->unacked[TOGGLE(way)]->l->size, SEQ_MAP_END(una), ACK_MAP(mi->lastack[way]));
			diamondTime(data->graph[way],ack->ts,SEQ_MAP_START(una) - ACK_MAP(mi->lastack[way]) ,2);
		}
	}*/
}
void destroyWinFlight(void** graphData, MPTCPConnInfo *mci){
	winFlightData *data = ((winFlightData*) *graphData);
	fclose(data->graph[S2C]);
	fclose(data->graph[C2S]);
}
