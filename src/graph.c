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
		destroySeq}
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
}
void CISeq(mptcp_sf *msf, mptcp_map *seq,  void* graphData, MPTCPConnInfo *mi, int way){
	int added;
	if(mi->lastack[way] == NULL  ||  SEQ_MAP_END( seq ) >= ACK_MAP(mi->lastack[way]))
		addElementOrderedReverseUnique(seq,mi->unacked[way],&added);
}

void stripUnack(mptcp_ack *ack, List *unacked){
	while(unacked->size > 0 && SEQ_MAP_END( ((mptcp_map*)unacked->head->element) ) <= ACK_MAP(ack))
		removeHead(unacked);
}

void CIAck(mptcp_sf *msf, mptcp_ack *ack,  void* graphData, MPTCPConnInfo *mi, int way){
	stripUnack(ack, mi->unacked[way]->l);

}
void destroyCI(void** graphData, MPTCPConnInfo *mci){
	printf("Destroy global informations\n");
}
