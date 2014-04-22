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
#include <string.h>
#include "mptcptrace.h"
#include "allocations.h"
#include "MPTCPList.h"



graphModule modules[]={
		{ACTIVE_MODULE,
		"Global informations.",
		initCI,
		CISeq,
		CIAck,
		destroyCI,
		NULL},
		{
		UNACTIVE_MODULE,
		"Sequence Graph",
		initSeq,
		seqGrahSeq,
		seqGrahAck,
		destroySeq,
		handleNewSFSeq},
		{
		UNACTIVE_MODULE,
		"Window and flight size graph",
		initWinFlight,
		winFlightSeq,
		winFlightAck,
		destroyWinFlight,
		NULL
		},
		{UNACTIVE_MODULE,
		"MPTCP goodput",
		initBW,
		bWSeq,
		bWAck,
		destroyBW,
		NULL},
		{
		UNACTIVE_MODULE,
		"window and fs are close enough ?",
		initWFS,
		wFSSeq,
		wFSAck,
		destroyWFS,
		NULL
		},
		{
		UNACTIVE_MODULE,
		"MPTCP Ack size",
		initAS,
		asGrahSeq,
		asGrahAck,
		destroyAS,
		NULL
		},
		{
		UNACTIVE_MODULE,
		"output series informations",
		initSeries,
		seriesSeq,
		seriesAck,
		destroySeries,
		NULL
		}
};

Writer Boris[]={
		{xpl_openGraphFile,
		xpl_writeHeader,
		xpl_diamondTime,
		xpl_diamondTimeDouble,
		xpl_verticalLineTime,
		NULL,
		xpl_textTime,
		xpl_writeFooter,
		xpl_writeSeries,
		},
		{gg_openGraphFile,
		gg_writeHeader,
		gg_diamondTime,
		gg_diamondTimeDouble,
		gg_verticalLineTime,
		NULL,
		gg_textTime,
		gg_writeFooter,
		gg_writeSeries
		},
		{csv_openGraphFile,
		csv_writeHeader,
		csv_diamondTime,
		csv_diamondTimeDouble,
		csv_verticalLineTime,
		NULL,
		csv_textTime,
		csv_writeFooter,
		csv_writeSeries
		}
};

tcpGraphModule tcpModules[]={
		{ACTIVE_MODULE,
		"TCP flight size",
		initTcpWinFlight,
		tcpWinFlight,
		destroyTcpWinFlight},
};
char* wayString[]={"s2c","c2s"};
int wayInt[]={S2C,C2S};


/******
 * helper
 */
//diamond etc, and all helper
void xpl_verticalLine(FILE* f, unsigned int x, unsigned int y, unsigned long h, int color){
	//TODO
}

void xpl_verticalLineTime(FILE* f, struct timeval tsx, unsigned int y, unsigned int h, int color){
	fprintf(f,"%i\n",color % 8);
	fprintf(f,"line %li.%06li %u %li.%06li %u \n",tsx.tv_sec, tsx.tv_usec,y,tsx.tv_sec, tsx.tv_usec,y+h);
}

void xpl_diamondTime(FILE *f, struct timeval tsx, unsigned int y, int color){
	fprintf(f,"%i\n",color % 8);
	fprintf(f,"diamond %li.%06li %u\n",tsx.tv_sec, tsx.tv_usec,y);
}

void xpl_diamondTimeDouble(FILE *f, struct timeval tsx, double y, int color){
	fprintf(f,"%i\n",color % 8);
	fprintf(f,"diamond %li.%06li %f\n",tsx.tv_sec, tsx.tv_usec,y);
	//TODO google api
	//fprintf(f,"[ new Date(%f), %f ],\n",tsx.tv_sec * 1000.0 + tsx.tv_usec / 1000.0 ,y);
}

void xpl_textTime(FILE *f, struct timeval tsx, unsigned int y, char* text, int color){
	fprintf(f,"%i\n",color % 8);
	fprintf(f,"atext %li.%06li %u\n R \n",tsx.tv_sec, tsx.tv_usec,y);
}
void xpl_writeHeader(FILE *f,char *way, char* title, char *xtype, char *ytype, char * xlabel, char *ylabel){
	fprintf(f,\
			"%s %s\n" \
			"title\n" \
			"%s - %s\n" \
			"xlabel\n" \
			"%s\n" \
			"ylabel\n" \
			"%s\n",xtype, ytype, way, title,xlabel,ylabel);
}

void xpl_writeSeries(FILE *f, char *type, char *name){
}

void xpl_writeFooter(FILE *f,char *way, char* title, char *xtype, char *ytype, char * xlabel, char *ylabel){
}


FILE* xpl_openGraphFile(char *name, int id, int way){
	char str[42];
	sprintf(str,"%s_%s_%d.xpl",wayString[way],name,id);
	return fopen(str,"w");
	//TODO header ?
}

void gg_verticalLine(FILE* f, unsigned int x, unsigned int y, unsigned long h, int color){
	//TODO
}

void gg_verticalLineTime(FILE* f, struct timeval tsx, unsigned int y, unsigned int h, int color){
	//fprintf(f,"%i\n",color);
	//fprintf(f,"line %li.%06li %u %li.%06li %u \n",tsx.tv_sec, tsx.tv_usec,y,tsx.tv_sec, tsx.tv_usec,y+h);
	fprintf(f,"row = data.addRow();\n");
	fprintf(f,"data.setCell(row,0, new Date(%f));\n",tsx.tv_sec * 1000.0 + tsx.tv_usec / 1000.0);
	fprintf(f,"data.setCell(row,%d, %u);\n",color,y);
}

void gg_diamondTime(FILE *f, struct timeval tsx, unsigned int y, int color){
	//fprintf(f,"%i\n",color);
	//fprintf(f,"diamond %li.%06li %u\n",tsx.tv_sec, tsx.tv_usec,y);
	//fprintf(f,"[ new Date(%f), %u ],\n",tsx.tv_sec * 1000.0 + tsx.tv_usec / 1000.0 ,y);
	fprintf(f,"row = data.addRow();\n");
	fprintf(f,"data.setCell(row,0, new Date(%f));\n",tsx.tv_sec * 1000.0 + tsx.tv_usec / 1000.0);
	fprintf(f,"data.setCell(row,%d, %u);\n",color,y);
}

void gg_diamondTimeDouble(FILE *f, struct timeval tsx, double y, int color){
	fprintf(f,"row = data.addRow();\n");
	fprintf(f,"data.setCell(row,0, new Date(%f));\n",tsx.tv_sec * 1000.0 + tsx.tv_usec / 1000.0);
	fprintf(f,"data.setCell(row,%d, %f);\n",color,y);
	//fprintf(f,"[ new Date(%f), %f ],\n",tsx.tv_sec * 1000.0 + tsx.tv_usec / 1000.0 ,y);
}

void gg_textTime(FILE *f, struct timeval tsx, unsigned int y, char* text, int color){
	//fprintf(f,"%i\n",color);
	//fprintf(f,"atext %li.%06li %u\n R \n",tsx.tv_sec, tsx.tv_usec,y);
}
void gg_writeHeader(FILE *f,char *way, char* title, char *xtype, char *ytype, char * xlabel, char *ylabel){
	fprintf(f,\
			"<html>\n" \
			"  <head>\n" \
			"    <script type=\"text/javascript\" src=\"https://www.google.com/jsapi\"></script>\n" \
			"    <script type=\"text/javascript\">\n" \
			"      google.load(\"visualization\", \"1\", {packages:[\"corechart\"]});\n" \
			"      google.setOnLoadCallback(drawChart);\n" \
			"      function drawChart() {\n" \
			"        var inputDiv = document.getElementById('select_div');\n" \
			"        var row;\n" \
			"        var data = new google.visualization.DataTable();\n");
	gg_writeSeries(f, "datetime", xlabel);
}

void gg_writeSeries(FILE *f, char *type, char *name){
	fprintf(f,"data.addColumn('%s','%s','certainty');\n",type, name);
	fprintf(f,"if(document.getElementById('%s') == null){\n" \
			"var checkbox = document.createElement('input');\n" \
			"checkbox.type =  \"checkbox\";\n" \
			"checkbox.name =  \"%s\";\n" \
			"checkbox.checked =  \"true\";\n" \
			"checkbox.id =  \"%s\";\n" \
			"checkbox.onclick =  function () {drawChart();} ;\n" \
			"var label = document.createElement('label');\n" \
			"label.htmlFor = \"id\";\n" \
			"label.appendChild(document.createTextNode('%s  |  '));\n" \
			"inputDiv.appendChild(checkbox);\n" \
			"inputDiv.appendChild(label);}\n",name,name,name,name);
}

void gg_writeFooter(FILE *f,char *way, char* title, char *xtype, char *ytype, char * xlabel, char *ylabel){
	fprintf(f,
/*	"         ]);\n"*/
	"        var options = { \n" \
	"          title: '%s - %s',\n" \
/*	"          hAxis: {title: 'Age', minValue: 0, maxValue: 15},\n" \
	"          vAxis: {title: 'Weight', minValue: 0, maxValue: 15},\n" \ */
/*	"          legend: 'none'\n" \*/
	"          explorer: { actions: ['dragToZoom', 'rightClickToReset'] } ,\n" \
	"          pointSize: 2\n,lineWidth: 1," \
	"        };\n" \
	"\n" \
	"        var chart = new google.visualization.ScatterChart(document.getElementById('chart_div'));\n" \
	"        var i=0;\n" \
	"        var selected=[];\n" \
	"        var children = inputDiv.childNodes;\n" \
	"        for(var j=0; j<children.length ; j++){\n" \
	"        	if(j%%2==0){\n" \
	"        		if(children[j].checked == true){\n" \
	"        			selected.push(i);\n" \
	"        		}\n" \
	"        		i++;\n" \
	"        	}\n" \
	"        }\n" \
	"        var myView = new google.visualization.DataView(data);\n"
	"        if(selected.length>1){myView.setColumns(selected);\n" \
	"        chart.draw(myView, options);}\n" \
	"      }\n" \
	"    </script>\n" \
	"  </head>\n" \
	"  <body>\n" \
	"    <div id=\"chart_div\" style=\"width: 900px; height: 500px;\"></div>\n" \
	"    <div id=\"select_div\"></div>\n" \
	"  </body>\n" \
	"</html>\n",way,title );
}


FILE* gg_openGraphFile(char *name, int id, int way){
	char str[42];
	sprintf(str,"%s_%s_%d.htm",wayString[way],name,id);
	return fopen(str,"w");
}

void csv_verticalLine(FILE* f, unsigned int x, unsigned int y, unsigned long h, int color){}
void csv_verticalLineTime(FILE* f, struct timeval tsx, unsigned int y, unsigned int h, int color){
	fprintf(f,"%li.%06li;%u;%i;1;%u;1\n",tsx.tv_sec, tsx.tv_usec,y,color,y+h);
}
void csv_diamondTime(FILE *f, struct timeval tsx, unsigned int y, int color){
	fprintf(f,"%li.%06li;%u;%i;0;0\n",tsx.tv_sec, tsx.tv_usec,y,color);
}
void csv_diamondTimeDouble(FILE *f, struct timeval tsx, double y, int color){
	fprintf(f,"%li.%06li;%f;%i;0;0\n",tsx.tv_sec, tsx.tv_usec,y,color);
}
void csv_textTime(FILE *f, struct timeval tsx, unsigned int y, char* text, int color){
	//TODO
}
void csv_writeHeader(FILE *f,char *way, char* title, char *xtype, char *ytype, char * xlabel, char *ylabel){}
void csv_writeFooter(FILE *f,char *way, char* title, char *xtype, char *ytype, char * xlabel, char *ylabel){}
FILE* csv_openGraphFile(char *name, int id, int way){
	char str[42];
	sprintf(str,"%s_%s_%d.csv",wayString[way],name,id);
	return fopen(str,"w");
}
void csv_writeSeries(FILE *f, char *type, char *name){}

void writeSeriesBoth(FILE **f, char *type, char *name){
	BOTH(Boris[Vian].writeSeries LP f, COMMA type  COMMA name RP )
}

void writeHeaderBoth(FILE **f,char* title, char *xtype, char *ytype, char * xlabel, char *ylabel){
	BOTH3(Boris[Vian].writeHeader LP f, COMMA wayString, COMMA  title COMMA xtype COMMA ytype COMMA xlabel COMMA ylabel RP )
}
void openGraphFileBoth(FILE **f,char *name, int id){
	BOTH3(f, = Boris[Vian].openFile LP name COMMA id COMMA wayInt, RP )
}

void incRefAck(mptcp_ack *ack,int i){
	ack->ref_count+=i;
	if(ack->ref_count==0)
		free(ack);
}
void incRefAckNode(Node *n){
	incRefAck((mptcp_ack*)n->element,1);
}
void decRefAckNode(Node *n){
	incRefAck((mptcp_ack*)n->element,-1);
}
void incRefSeq(mptcp_map *seq,int i){
	seq->ref_count+=i;
	if(seq->ref_count==0){
		//fprintf(stderr,"I'm freeeeeeeeee\n");
		free(seq);
	}
}
void incRefSeqNode(Node *n){
	incRefSeq((mptcp_map*)n->element,1);
}
void decRefSeqNode(Node *n){
	incRefSeq((mptcp_map*)n->element,-1);
}
/**
 * sequence graph
 */

void initSeq(void** graphData, MPTCPConnInfo *mci){
	seqData* data = (seqData*) exitMalloc(sizeof(seqData));
	*graphData = data;
	data->graph[S2C] = Boris[Vian].openFile("seq",mci->mc->id,S2C);
	data->graph[C2S] = Boris[Vian].openFile("seq",mci->mc->id,C2S);
	Boris[Vian].writeHeader(data->graph[S2C],wayString[S2C],"Time sequence",TIMEVAL,DOUBLE,LABELTIME,LABELSEQ);
	Boris[Vian].writeHeader(data->graph[C2S],wayString[C2S],"Time sequence",TIMEVAL,DOUBLE,LABELTIME,LABELSEQ);
	data->seq[S2C] = newOrderedList(NULL,compareMap);
	data->seq[C2S] = newOrderedList(NULL,compareMap);
	data->reinject[S2C] = 0;
	data->reinject[C2S] = 0;
	fprintf(stderr,"Seq graph init...\n");
}

int isReinjected(Node *n, List *seq){
	mptcp_map *prevmap = n->previous == NULL ? NULL : (mptcp_map*) n->previous->element;
	mptcp_map *currmap =  (mptcp_map*) n->element;

	//if(n->previous != NULL && SEQ_MAP_END(prevmap) > SEQ_MAP_START(currmap) && prevmap->msf != currmap->msf){
	if(n->previous != NULL && afterUI(SEQ_MAP_END(prevmap) , SEQ_MAP_START(currmap)) && prevmap->msf != currmap->msf){

		return prevmap->msf->id;
	}

	return -1;
}

void seqGrahSeq(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_map *seq, void* graphData, MPTCPConnInfo *mi, int way){
	seqData *data = ((seqData*) graphData);
	int added;
	Node *n = addElementOrderedReverseUnique(seq,data->seq[way],&added);
	int checkReinject=1;
	int reinject;
	/*for big traces, we can't keep all the map in memory, if seq reinjection is too late we won't see it*/
	if(maxSeqQueueLength != 0 && data->seq[way]->l->size > maxSeqQueueLength){
		decRefSeqNode(data->seq[way]->l->head);
		if(n==data->seq[way]->l->head) checkReinject=0;
		removeHeadFree(data->seq[way]->l);
	}

	if(!added){
		mptcp_map *orig = (mptcp_map*) n->element;
		reinject = checkReinject ? isReinjected(n,data->seq[way]->l) : -1;
		if(reinject > -1 && (orig->injectOnSF & 1 << seq->msf->id) == 0){
			orig->injectOnSF |= 1 << seq->msf->id;
			orig->injectCount += 1;
		}
	}
	else{
		incRefSeqNode(n);
		reinject = -1;
	}
	//int reinject = isReinjected(n,data->seq[way]->l);
	//if( mi->lastack[TOGGLE(way)] !=NULL && afterOrEUI(SEQ_MAP_START(seq),ACK_MAP(mi->lastack[TOGGLE(way)])))
	//	printf("ahahahhahhahahahahhahaahahhhahahahhahahhahah\n");

	if( reinject >= 0){
		Boris[Vian].writeTextTime(data->graph[way],seq->ts,SEQ_MAP_END(seq),"R",reinject);
		data->reinject[way] += SEQ_MAP_LEN(seq);
	}
	Boris[Vian].writeTimeVerticalLine(data->graph[way],seq->ts,SEQ_MAP_START(seq),SEQ_MAP_LEN(seq),(msf->id+1));
}

void seqGrahAck(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_ack *ack, void* graphData, MPTCPConnInfo *mi, int way){
	seqData *data = ((seqData*) graphData);
	Boris[Vian].writeTimeDot(data->graph[TOGGLE(way)],ack->ts,ACK_MAP(ack),(msf->id+1));
}

void decSeqList(void* element, int pos, void *fix, void *acc){
	mptcp_map* seq = (mptcp_map*) element;
	incRefSeq(seq,-1);
}
void writeMap(void* element, int pos, void *fix, void *acc){
	mptcp_map *m = (mptcp_map*) element;
	FILE *f = (FILE*) fix;
	if(m->injectCount > 1)
		fprintf(f,"%i,%i\n",pos,m->injectCount);
}

void destroySeq(void** graphData, MPTCPConnInfo *mci){
	seqData *data = ((seqData*) *graphData);

	char str[42];
	sprintf(str,"%s_map_reinject_%i.csv",wayString[C2S],mci->mc->id);
	FILE* f=fopen(str,"w");
	fprintf(f,"id,n\n");
	apply(data->seq[C2S]->l,writeMap,f,NULL);
	fclose(f);

	Boris[Vian].writeFooter(data->graph[S2C],wayString[S2C],"Time sequence",TIMEVAL,DOUBLE,LABELTIME,LABELSEQ);
	Boris[Vian].writeFooter(data->graph[C2S],wayString[C2S],"Time sequence",TIMEVAL,DOUBLE,LABELTIME,LABELSEQ);
	BOTH(apply LP data->seq,->l COMMA decSeqList COMMA NULL COMMA NULL RP)
	BOTH(destroyList LP data->seq,->l RP)
	BOTH(free LP data->seq, RP)
	fclose(data->graph[S2C]);
	fclose(data->graph[C2S]);
	fprintf(stderr,"Seq graph Destroy...\n");
	free(data);
}

void handleNewSFSeq(mptcp_sf *msf, void* graphData, MPTCPConnInfo *mi){
	seqData *data = ((seqData*) graphData);
	char str[42];
	sprintf(str,"subflow_%d",msf->id);
	FILE *f =  fopen(str,"w");
	fclose(f);

	Boris[Vian].writeSeries(data->graph[C2S],"number",str);
	Boris[Vian].writeSeries(data->graph[S2C],"number",str);
}

/**
 * global information
 */
void initCI(void** graphData, MPTCPConnInfo *mci){
	printf("create global informations\n");
	mci->unacked[S2C] = newOrderedList(free,compareMap);
	mci->unacked[C2S] = newOrderedList(free,compareMap);
	mci->lastack[S2C] = NULL;
	mci->lastack[C2S] = NULL;
	mci->firstSeq[S2C] = NULL;
	mci->firstSeq[C2S] = NULL;
	mci->lastAckSize[S2C] = 0;
	mci->lastAckSize[C2S] = 0;
}




void CISeq(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_map *seq,  void* graphData, MPTCPConnInfo *mi, int way){
	int added;
	Node *n;
	if(mi->firstSeq[way] == NULL){
		mi->firstSeq[way] = seq;
		incRefSeq(seq,1);
	}
	//if(mi->lastack[TOGGLE(way)] == NULL  ||  SEQ_MAP_END( seq ) >= ACK_MAP(mi->lastack[TOGGLE(way)]))
	if(mi->lastack[TOGGLE(way)] == NULL  ||  afterOrEUI(SEQ_MAP_END( seq ), ACK_MAP(mi->lastack[TOGGLE(way)]))){
		n=addElementOrderedReverseUnique(seq,mi->unacked[way],&added);
		if(added)
			incRefSeqNode(n);
	}
}

unsigned int stripUnack(mptcp_ack *ack, List *unacked){
	//while(unacked->size > 0 && SEQ_MAP_END( ((mptcp_map*)unacked->head->element) ) <= ACK_MAP(ack))
	unsigned int r=0;
	while(unacked->size > 0 && beforeOrEUI(SEQ_MAP_END( ((mptcp_map*)unacked->head->element) ) , ACK_MAP(ack))){
		r+=SEQ_MAP_LEN(((mptcp_map*)unacked->head->element));
		decRefSeqNode(unacked->head);
		removeHeadFree(unacked);
	}
	return r;
}

void CIAck(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_ack *ack,  void* graphData, MPTCPConnInfo *mi, int way){
	mi->lastAckSize[way] = stripUnack(ack, mi->unacked[TOGGLE(way)]->l);
	//if(mi->lastack[way] == NULL || ACK_MAP(mi->lastack[way]) < ACK_MAP(ack)){
	if(mi->lastack[way] == NULL || beforeOrEUI(ACK_MAP(mi->lastack[way]) , ACK_MAP(ack))){
		if(mi->lastack[way] != NULL ) incRefAck(mi->lastack[way],-1);
		mi->lastack[way] = ack;
		incRefAck(mi->lastack[way],1);
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

	openGraphFileBoth(data->graph,"flight",mci->mc->id);
	writeHeaderBoth(data->graph,"Window and MPTCP flight size",TIMEVAL,DOUBLE,LABELTIME,"size");
	writeSeriesBoth(data->graph,"number","Window");
	writeSeriesBoth(data->graph,"number", "MPTCP_Flight_size");
	writeSeriesBoth(data->graph,"number","Sum_of_the_TCP_flight_size");

	openGraphFileBoth(data->graphRE,"rightEdge",mci->mc->id);
	writeHeaderBoth(data->graphRE,"Right edge Evolution",TIMEVAL,DOUBLE,LABELTIME,"Right edge");

	openGraphFileBoth(data->graph2,"flight_per_flow",mci->mc->id);
	writeHeaderBoth(data->graph2,"Per flow flight size",TIMEVAL,DOUBLE,LABELTIME,"size");

	BOTH(data->rightEdge,= 0)

	INITBOTH(data->mpFlightSize,0,unsigned int);
	INITBOTH(data->mpWindow,0,unsigned int);
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
void sumFlight2(void* element, int pos, void *fix, void *acc){
	mptcp_sf *msf = (mptcp_sf*) element;
	tcp_map *funa,*luna;
	unsigned int *sum = (int*) acc;
	unsigned int toAdd=0;
	couple *c = (couple*) fix;
	int *way = c->x;
	struct timeval *ts = c->z;
	winFlightData *data = (winFlightData*)c->y;
	if(msf->tcpUnacked[*way]->l->size > 0){
		funa = (tcp_map*) msf->tcpUnacked[*way]->l->head->element;
		luna = (tcp_map*) msf->tcpUnacked[*way]->l->tail->element;
		toAdd =  (luna->end - funa->start);
		Boris[Vian].writeTimeVerticalLine(data->graph2[*way],*ts,*sum,toAdd,msf->id);
		*sum = (*sum) + toAdd;
	}
}


void winFlightSeq(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_map *seq,  void* graphData, MPTCPConnInfo *mi, int way){
	winFlightData *data = ((winFlightData*) graphData);
	mptcp_map *funa,*luna;
	unsigned int mpflight = 0;
	unsigned int flightSum=0;
	if(mi->unacked[way]->l->size > 0){
		funa = (mptcp_map*) mi->unacked[way]->l->head->element;
		luna = (mptcp_map*) mi->unacked[way]->l->tail->element;
		mpflight = SEQ_MAP_END(luna) - SEQ_MAP_START(funa);
		*(data->mpFlightSize[way]) = SEQ_MAP_END(luna) - SEQ_MAP_START(funa);
		Boris[Vian].writeTimeDot(data->graph[way],seq->ts,*(data->mpFlightSize[way]),2);
	}

	if (flight_select & FLIGHT_PER_FLOW ){
		couple c = {&way,data,&seq->ts};
		apply(msf->mc_parent->mptcp_sfs,sumFlight2, &c, &flightSum);
	}
	flightSum=0;
	apply(msf->mc_parent->mptcp_sfs,sumFlight, &way, &flightSum);
	Boris[Vian].writeTimeDot(data->graph[way],seq->ts,flightSum ,3);
}



void winFlightAck(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_ack *ack,  void* graphData, MPTCPConnInfo *mi, int way){
	winFlightData *data = ((winFlightData*) graphData);
	mptcp_map *funa,*luna;
	unsigned int flightSum=0;
	//if(data->rightEdge[way] == 0 || data->rightEdge[way] < ack->right_edge){
	//TODO handle wrap around
	if(data->rightEdge[way] == 0 || beforeOrEUI(data->rightEdge[way], ack->right_edge)){
		data->rightEdge[way] = ack->right_edge;
	//	Boris[Vian].writeTimeDot(data->graphRE[TOGGLE(way)],ack->ts,data->rightEdge[way] ,2);
	//	Boris[Vian].writeTimeDot(data->graphRE[TOGGLE(way)],ack->ts,ACK_MAP(mi->lastack[way]) ,1);
	}
	if(mi->lastack[way] != NULL){
		*(data->mpWindow[TOGGLE(way)]) = data->rightEdge[way] - ACK_MAP(mi->lastack[way]);
		Boris[Vian].writeTimeDot(data->graph[TOGGLE(way)],ack->ts,data->rightEdge[way] - ACK_MAP(mi->lastack[way]),1);
	}
	if(mi->unacked[TOGGLE(way)]->l->size > 0){
		funa = (mptcp_map*) mi->unacked[TOGGLE(way)]->l->head->element;
		luna = (mptcp_map*) mi->unacked[TOGGLE(way)]->l->tail->element;
		*(data->mpFlightSize[TOGGLE(way)]) = SEQ_MAP_END(luna) - SEQ_MAP_START(funa);
		Boris[Vian].writeTimeDot(data->graph[TOGGLE(way)],ack->ts, *(data->mpFlightSize[TOGGLE(way)]) ,2);
	}
	apply(msf->mc_parent->mptcp_sfs,sumFlight, &way, &flightSum);
	Boris[Vian].writeTimeDot(data->graph[way],ack->ts,flightSum ,3);

	if (flight_select & FLIGHT_PER_FLOW ){
		couple c = {&way,data,&ack->ts};
		flightSum=0;
		apply(msf->mc_parent->mptcp_sfs,sumFlight2, &c, &flightSum);
	}


}
void destroyWinFlight(void** graphData, MPTCPConnInfo *mci){
	winFlightData *data = ((winFlightData*) *graphData);
	Boris[Vian].writeFooter(data->graph[S2C],wayString[S2C],"Window and MPTCP flight size",TIMEVAL,DOUBLE,LABELTIME,"size");
	Boris[Vian].writeFooter(data->graph[C2S],wayString[C2S],"Window and MPTCP flight size",TIMEVAL,DOUBLE,LABELTIME,"size");
	Boris[Vian].writeFooter(data->graphRE[S2C],wayString[S2C],"Right edge Evolution",TIMEVAL,DOUBLE,LABELTIME,"Right edge");
	Boris[Vian].writeFooter(data->graphRE[C2S],wayString[C2S],"Right edge Evolution",TIMEVAL,DOUBLE,LABELTIME,"Right edge");
	BOTH(fclose LP data->graph2,RP)
	fclose(data->graph[S2C]);
	fclose(data->graph[C2S]);
	fclose(data->graphRE[C2S]);
	fclose(data->graphRE[S2C]);
	free(data->mpFlightSize[S2C]);
	free(data->mpFlightSize[C2S]);
	free(data->mpWindow[C2S]);
	free(data->mpWindow[S2C]);
	free(data);
}

/****
 * TCP win  and flight... As the name does not suggest, just take a look at the flight size.
 */

void updateTCPUnack(struct sniff_ip *rawIP, struct sniff_tcp *rawTCP,mptcp_sf *msf, int way){
	tcp_map *seq = (tcp_map*)exitMalloc(sizeof(tcp_map));
	seq->start = TCP_SEQ(rawTCP);
	seq->end = seq->start + ntohs(rawIP->ip_len) - 4*(IP_HL(rawIP)) - 4*(TH_OFF(rawTCP));
	int added;
	Node *n;
	//if(msf->tcpLastAck[TOGGLE(way)] == NULL || seq->start >= *(msf->tcpLastAck[TOGGLE(way)]))
	if(msf->tcpLastAck[TOGGLE(way)] == NULL || afterOrEUI(seq->start , *(msf->tcpLastAck[TOGGLE(way)]))){
		n=addElementOrderedReverseUnique(seq,msf->tcpUnacked[way],&added);
		if(!added) free(seq);
	}
	else
		free(seq);
}

void updateLastAck(struct sniff_tcp *rawTCP,mptcp_sf *msf, int way){
	unsigned int *ack;
	if(!ACK_SET(rawTCP)) return;
	ack = (unsigned int*)exitMalloc(sizeof(unsigned int));
	*ack = TCP_ACK(rawTCP);
	//if(msf->tcpLastAck[way] == NULL || msf->tcpLastAck[way] < ack)
	if(msf->tcpLastAck[way] == NULL || beforeUI(*(msf->tcpLastAck[way]) , *ack)){
		if(msf->tcpLastAck[way] != NULL) free(msf->tcpLastAck[way]);
		msf->tcpLastAck[way] = ack;
	}
	else
		free(ack);
}
void stripTCPUnack(struct sniff_tcp *rawTCP, List *unacked){
	//unsigned int *ack = (unsigned int*)exitMalloc(sizeof(unsigned int));
	unsigned int ack;
	ack = TCP_ACK(rawTCP);
	if(!ACK_SET(rawTCP)) return;
	//while(unacked->size > 0 && ((tcp_map*)unacked->head->element)->end <= *ack)
	while(unacked->size > 0 && beforeOrEUI(((tcp_map*)unacked->head->element)->end, ack)){
		free(unacked->head->element);
		removeHeadFree(unacked);
	}
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
	data->graph[S2C] = Boris[Vian].openFile("gput",mci->mc->id,S2C);
	data->graph[C2S] = Boris[Vian].openFile("gput",mci->mc->id,C2S);
	Boris[Vian].writeHeader(data->graph[S2C],wayString[S2C],"MPTCP goodput",TIMEVAL,DOUBLE,LABELTIME,"Goodput");
	Boris[Vian].writeHeader(data->graph[C2S],wayString[C2S],"MPTCP goodput",TIMEVAL,DOUBLE,LABELTIME,"Goodput");
	data->mpa[S2C] = NULL;
	data->mpa[C2S] = NULL;
	data->bucket[S2C] = 0;
	data->bucket[C2S] = 0;
	data->lastNacks[C2S] = exitMalloc(sizeof(mptcp_ack*) * gpInterv);
	data->lastNacks[S2C] = exitMalloc(sizeof(mptcp_ack*) * gpInterv);
	memset(data->lastNacks[C2S],0,sizeof(mptcp_ack*) * gpInterv);
	memset(data->lastNacks[S2C],0,sizeof(mptcp_ack*) * gpInterv);
	BOTH(data->ackedData,=0)
	data->movingAvg[C2S] = 0;
	data->movingAvg[S2C] = 0;
	data->movingAvgFull[C2S] = 0;
	data->movingAvgFull[S2C] = 0;
}

void bWSeq(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_map *seq,  void* graphData, MPTCPConnInfo *mi, int way){
	bwData *data = ((bwData*) graphData);
	//DO something
}

void bWAck(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_ack *ack,  void* graphData, MPTCPConnInfo *mi, int way){
	bwData *data = ((bwData*) graphData);
	int i=1;

	struct timeval tmp = ack->ts;
	struct timeval tmp2 = ack->ts;
	struct timeval tmp3 = ack->ts;
	if(data->mpa[way]==NULL){
		data->mpa[way]=ack;
		data->fmpa[way]=ack;
		data->lastNacks[way][0]=ack;
		data->movingAvg[way]=1;
		incRefAck(ack,3);
	}
	else{
		i=data->movingAvg[way]==0 ? gpInterv - 1 : data->movingAvg[way] - 1 % gpInterv;
		//if(ACK_MAP(ack) <= ACK_MAP(data->mpa[way]) )
		if(beforeOrEUI(ACK_MAP(ack),ACK_MAP(data->lastNacks[way][i])))
			return;
		if(beforeOrEUI(ACK_MAP(ack) , ACK_MAP(data->mpa[way]) ))
		//if(beforeUI(ACK_MAP(ack) , ACK_MAP(data->mpa[way]) ))
				return;
		if(data->bucket[way] == gpInterv){
			data->movingAvgFull[way]=1;
			//TODO gestion des ack plus anciens !
			tv_sub(&tmp,data->mpa[way]->ts);
			Boris[Vian].writeTimeDotDouble(data->graph[TOGGLE(way)],ack->ts,(ACK_MAP(ack) - ACK_MAP(data->mpa[way]))/(tmp.tv_sec+tmp.tv_usec/1000000.0) / 1000000.0,1);
			data->bucket[way]=0;
			incRefAck(data->mpa[way],-1);
			data->mpa[way] = ack;
			incRefAck(ack,1);

		}
		else
			data->bucket[way]++;
		tv_sub(&tmp2,data->fmpa[way]->ts);
		//Boris[Vian].writeTimeDotDouble(data->graph[TOGGLE(way)],ack->ts,(ACK_MAP(ack) - ACK_MAP(data->fmpa[way]))/(tmp2.tv_sec+tmp2.tv_usec/1000000.0) / 1000000.0 ,2);

		if( data->lastNacks[way][data->movingAvg[way]] != NULL) incRefAck(data->lastNacks[way][data->movingAvg[way]],-1);
		data->lastNacks[way][data->movingAvg[way]]=ack;
		incRefAck(ack,1);

		if(!(data->movingAvgFull[way]==0 && data->bucket[way]<1)){
			//fprintf(stderr,"%u %u\n",data->movingAvg[way],i);
			data->ackedData[TOGGLE(way)] += (ACK_MAP(data->lastNacks[way][data->movingAvg[way]]) - ACK_MAP(data->lastNacks[way][i]) );
			//fprintf(stderr,"here%u\n",(ACK_MAP(data->lastNacks[way][data->movingAvg[way]]) - ACK_MAP(data->lastNacks[way][i]) ));
			Boris[Vian].writeTimeDotDouble(data->graph[TOGGLE(way)],ack->ts,data->ackedData[TOGGLE(way)]/(tmp2.tv_sec+tmp2.tv_usec/1000000.0) / 1000000.0 ,2);
		}

		data->movingAvg[way] = (data->movingAvg[way] + 1) % gpInterv;
		//moving avg
		if(data->movingAvgFull[way]){
			tv_sub(&tmp3,data->lastNacks[way][data->movingAvg[way]]->ts);
			Boris[Vian].writeTimeDotDouble(data->graph[TOGGLE(way)],ack->ts,(ACK_MAP(ack) - ACK_MAP(data->lastNacks[way][data->movingAvg[way]]))/(tmp3.tv_sec+tmp3.tv_usec/1000000.0) / 1000000.0 ,3);
		}
	}


}
void destroyBW(void** graphData, MPTCPConnInfo *mci){
	bwData *data = ((bwData*) *graphData);
	Boris[Vian].writeFooter(data->graph[S2C],wayString[S2C],"MPTCP goodput",TIMEVAL,DOUBLE,LABELTIME,"Goodput");
	Boris[Vian].writeFooter(data->graph[C2S],wayString[C2S],"MPTCP goodput",TIMEVAL,DOUBLE,LABELTIME,"Goodput");
	incRefAck(data->fmpa[C2S],-1);
	incRefAck(data->fmpa[S2C],-1);
	incRefAck(data->mpa[S2C],-1);
	incRefAck(data->mpa[C2S],-1);
	fclose(data->graph[S2C]);
	fclose(data->graph[C2S]);
	int i=0;
	for(i=0;i<gpInterv;i++){
		BOTH3(if LP data->lastNacks,[i]!=NULL RP incRefAck LP data->lastNacks,[i] COMMA -1 RP)
	}
	BOTH(free LP data->lastNacks,RP)
	free(data);
}

void initWFS(void** graphData, MPTCPConnInfo *mci){
	wFSData* data = (wFSData*) exitMalloc(sizeof(bwData));
	*graphData = data;
	char str[42];
	sprintf(str,"stats_%i.csv",mci->mc->id);
	data->f = fopen(str,"w");

	data->n[S2C] = exitMalloc(sizeof(unsigned int));
	data->n[C2S] = exitMalloc(sizeof(unsigned int));

	*(data->n[S2C]) = 0;
	*(data->n[C2S]) = 0;

}
void wFSSeq(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_map *seq,  void* graphData, MPTCPConnInfo *mi, int way){
	winFlightData *winData = ((winFlightData*) msf->mc_parent->graphdata[WIN_FLIGHT]);
	wFSData *wfsData = ((wFSData*) graphData);
	if(modules[WIN_FLIGHT].activated && *(winData->mpWindow[way]) - *(winData->mpFlightSize[way]) < WINDOW_CLOSE_TO_FS){
		(*(wfsData->n[way]))++;
	}
}
void wFSAck(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_ack *ack,  void* graphData, MPTCPConnInfo *mi, int way){
	winFlightData *winData = ((winFlightData*) msf->mc_parent->graphdata[WIN_FLIGHT]);
	wFSData *wfsData = ((wFSData*) graphData);
	if(*(winData->mpWindow[TOGGLE(way)]) - *(winData->mpFlightSize[TOGGLE(way)]) < WINDOW_CLOSE_TO_FS){
		(*(wfsData->n[TOGGLE(way)]))++;
	}
}

void writeStats(FILE *f, char *statName, int conID,unsigned int c2s, unsigned int s2c){
	fprintf(f,"%s;%i;%s;%u;%u\n",filename,conID,statName,c2s,s2c);
}

void writeStatsD(FILE *f, char *statName, int conID,double c2s, double s2c){
	fprintf(f,"%s;%i;%s;%f;%f\n",filename,conID,statName,c2s,s2c);
}
void destroyWFS(void** graphData, MPTCPConnInfo *mci){
	seqData *sData = ((seqData*) mci->mc->graphdata[GRAPH_SEQUENCE] );
	wFSData *wfsData = ((wFSData*) *graphData);
	struct timeval tmp = mci->lastack[S2C]->ts ;
	tv_sub(&tmp,mci->firstSeq[C2S]->ts );
	//TODO determine constant value
	writeStats(wfsData->f,"winFsClose",mci->mc->id,*(wfsData->n[C2S]),*(wfsData->n[S2C]));
	writeStats(wfsData->f,"firstSeq",mci->mc->id,SEQ_MAP_START(mci->firstSeq[C2S]),SEQ_MAP_START(mci->firstSeq[S2C]) );
	writeStats(wfsData->f,"lastAck",mci->mc->id,ACK_MAP(mci->lastack[C2S]),ACK_MAP(mci->lastack[S2C]) );
	writeStatsD(wfsData->f,"conTime",mci->mc->id,tmp.tv_sec + tmp.tv_usec / 1000000.0,tmp.tv_sec + tmp.tv_usec / 1000000.0 );
	writeStats(wfsData->f,"seqAcked",mci->mc->id,ACK_MAP(mci->lastack[TOGGLE(C2S)]) - SEQ_MAP_START(mci->firstSeq[C2S]),ACK_MAP(mci->lastack[TOGGLE(S2C)]) - SEQ_MAP_START(mci->firstSeq[S2C]));
	if(modules[GRAPH_SEQUENCE].activated == ACTIVE_MODULE){
		writeStats(wfsData->f,"reinjected",mci->mc->id,sData->reinject[C2S],sData->reinject[S2C]);
		writeStatsD(wfsData->f,"precentReinjected",mci->mc->id,sData->reinject[C2S]*1.0/(ACK_MAP(mci->lastack[TOGGLE(C2S)]) - SEQ_MAP_START(mci->firstSeq[C2S])) ,
															   sData->reinject[S2C]*1.0/(ACK_MAP(mci->lastack[TOGGLE(S2C)]) - SEQ_MAP_START(mci->firstSeq[S2C])) );
	}
	fclose(wfsData->f);
}


void initAS(void** graphData, MPTCPConnInfo *mci){
	asData* data = (asData*) exitMalloc(sizeof(asData));
	*graphData = data;
	data->graph[S2C] = Boris[Vian].openFile("acksize",mci->mc->id,S2C);
	data->graph[C2S] = Boris[Vian].openFile("acksize",mci->mc->id,C2S);
	Boris[Vian].writeHeader(data->graph[S2C],wayString[S2C],"MPTCP Ack size",TIMEVAL,DOUBLE,LABELTIME,"Ack size");
	Boris[Vian].writeHeader(data->graph[C2S],wayString[C2S],"MPTCP Ack size",TIMEVAL,DOUBLE,LABELTIME,"Ack size");
}
void asGrahSeq(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_map *seq,  void* graphData, MPTCPConnInfo *mi, int way){

}
void asGrahAck(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_ack *ack,  void* graphData, MPTCPConnInfo *mi, int way){
	asData *data = ((asData*) graphData);
	Boris[Vian].writeTimeDot(data->graph[TOGGLE(way)],ack->ts,mi->lastAckSize[way],msf->id + 1 );
}
void destroyAS(void** graphData, MPTCPConnInfo *mci){
	asData *data = ((asData*) *graphData);
	Boris[Vian].writeFooter(data->graph[S2C],wayString[S2C],"MPTCP Ack size",TIMEVAL,DOUBLE,LABELTIME,"Ack size");
	Boris[Vian].writeFooter(data->graph[S2C],wayString[S2C],"MPTCP Ack size",TIMEVAL,DOUBLE,LABELTIME,"Ack size");
	fclose(data->graph[S2C]);
	fclose(data->graph[C2S]);
	free(data);
}


void initSeries(void** graphData, MPTCPConnInfo *mci){
	seriesData* data = (seriesData*) exitMalloc(sizeof(seriesData));
	*graphData = data;
	openGraphFileBoth(data->graph,"sf",mci->mc->id);
}
void seriesSeq(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_map *seq,  void* graphData, MPTCPConnInfo *mi, int way){
	msf->info[way].tput += SEQ_MAP_LEN(seq);
}
void seriesAck(struct sniff_tcp *rawTCP, mptcp_sf *msf, mptcp_ack *ack,  void* graphData, MPTCPConnInfo *mi, int way){

}
void outputSF(void* element, int pos, void *fix, void *acc){
	mptcp_sf *msf = (mptcp_sf*) element;
	FILE* f = (FILE*) fix;
	//TODO, we could hava per flow informations printed out here
	fprintf(f,"%d,%u,%u\n",msf->id,msf->info[C2S].tput,msf->info[S2C].tput);
}
void destroySeries(void** graphData, MPTCPConnInfo *mci){
	seriesData *data = ((seriesData*) *graphData);
	BOTH(applyReverse LP mci->mc->mptcp_sfs COMMA outputSF COMMA data->graph, COMMA NULL RP )
	BOTH(fclose LP data->graph, RP)
}
void handleNewSFSeries(mptcp_sf *msf, void* graphData, MPTCPConnInfo *mi){
//MOVE to destroy... we know more thing a this point.
}
