/*
 * MPTCPList.c
 *
 *  Created on: Jan 8, 2014
 *      Author: Benjamin Hesmans
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <sys/time.h>
#include "string.h"
#include "list.h"
#include "mptcptrace.h"
#include "TCPOptions.h"
#include "allocations.h"
#include "MPTCPList.h"
#include "graph.h"
#include "timingTools.h"

int compareMap(void *e1, void *e2){
	mptcp_map* m1 = (mptcp_map *)e1;
	mptcp_map* m2 = (mptcp_map *)e2;
	if(SEQ_MAP_START(m1)<SEQ_MAP_START(m2)) return -1;
	return (SEQ_MAP_START(m1)>SEQ_MAP_START(m2)) ? 1 : 0;
}

int compareTcpMap(void *e1, void *e2){
	tcp_map* m1 = (tcp_map *)e1;
	tcp_map* m2 = (tcp_map *)e2;
	if(m1->start < m2->start) return -1;
	return (m1->start > m2->start) ? 1 : 0;
}

int compareInt(void *e1, void *e2){
	unsigned int* i1 = (unsigned int *)e1;
	unsigned int* i2 = (unsigned int *)e2;
	if(i1 < i2) return -1;
	return i1 > i2 ? 1 : 0;
}
int sublfowsEqual(mptcp_sf* s1,  mptcp_sf* s2){
	if(memcmp(&s1->ip_dst,&s2->ip_dst,sizeof(struct in_addr)) == 0 &&
			memcmp(&s1->ip_src, &s2->ip_src,sizeof(struct in_addr)) == 0 &&
			memcmp(&s1->th_dport, &s2->th_dport,sizeof(u_short)) == 0 &&
			memcmp(&s1->th_sport, &s2->th_sport,sizeof(u_short)) == 0)
		return 1;
	return 0;
}

int sublfowsEqualWrapper(void* s1, int pos, void* s2, void* acc){
	mptcp_sf *sf1 = (mptcp_sf*) s1;
	mptcp_sf *sf2 = (mptcp_sf*) s2;
	return sublfowsEqual(s1,s2);
}
int searchMPTCPConnection(void* mc, int pos, void* searchFun, void *acc){
	int (*s)(void*, int, void*, void*) = (int (*)(void*, int, void*, void*)) searchFun;
	mptcp_sf* sf = (mptcp_sf*) search(((mptcp_conn*)mc)->mptcp_sfs,s,((toFindRes*)acc)->toFind,NULL);
	((toFindRes*)acc)->result = sf;
	return sf == NULL ? 0 : 1;

}


mptcp_sf* getSubflow(List *l,mptcp_sf *msf){
	toFindRes acc;
	acc.toFind = msf;
	acc.result = NULL;
	search(l,searchMPTCPConnection,sublfowsEqualWrapper,&acc);
	return (mptcp_sf*) acc.result;
}

mptcp_sf* getSubflowFromIPTCP(List *l,struct sniff_ip *ip, struct sniff_tcp *tcp, int *way){
	mptcp_sf msf, *found;
	build_msf(ip,tcp,&msf,DONOTREVERT,0);
	found = getSubflow(l,&msf);
	if(found){
		*way = C2S;
		return found;
	}
	else{
		build_msf(ip,tcp,&msf,REVERT,0);
		found = getSubflow(l,&msf);
		*way = S2C;
		return found;
	}
}

void add_MPTCP_conn_syn(List* l, struct sniff_ip *ip, struct sniff_tcp *tcp){
	mptcp_sf *msf = new_msf(ip,tcp);
	int i;
	u_char* wscale = next_opt_x(OPTION_TCP_HEADER(tcp),MAX_TCP_HEADER(tcp), TCP_OPT_WSCALE);
	if(wscale)
		msf->wscale[C2S] = *(wscale+2);

	if(getSubflow(l,msf)){
		printf("Retransmitted syn ..... \n");
		free(msf);
	}
	else{
		mptcp_conn *mc = (mptcp_conn*) exitMalloc(sizeof(mptcp_conn));
		MPTCPConnInfo *mci = (MPTCPConnInfo *) exitMalloc(sizeof(MPTCPConnInfo));
		mc->mci = mci;
		mc->id = l->size;
		mc->mci->mc = mc;
		for(i=0;i<MAX_GRAPH;i++) if(modules[i].activated)  modules[i].initModule(&mc->graphdata[i],mc->mci);
		for(i=0;i<TCP_MAX_GRAPH;i++) if(tcpModules[i].activated) tcpModules[i].destroyModule(&mc->graphdata[i],mc->mci);
		u_char* mpcapa = first_MPTCP_sub(tcp,MPTCP_SUB_CAPABLE);
		memcpy(&mc->client_key, mpcapa+4, KEY_SIZE);
		//TODO free them
		mc->mptcp_sfs = newList(NULL);
		fprintf(stderr,"Fixing mc_parent...\n");
		msf->mc_parent = mc;
		msf->id=mc->mptcp_sfs->size;
		addElementHead(msf,mc->mptcp_sfs);
		addElementHead(mc,l);
	}
}

void add_MPTCP_conn_synack(List* l, struct sniff_ip *ip, struct sniff_tcp *tcp){
	mptcp_sf msfr;
	build_msf(ip,tcp,&msfr,REVERT,0);
	mptcp_sf *msf = getSubflow(l,&msfr);
	if(msf){
		u_char* mpcapa = first_MPTCP_sub(tcp,MPTCP_SUB_CAPABLE);
		//TODO msf should allow access to the parent
		if(msf->mc_parent == NULL){
			fprintf(stderr,"Should not happen...\n");

		}
		else{
			memcpy(&(msf->mc_parent)->server_key, mpcapa+4, 8);
		}
		u_char* wscale = next_opt_x(OPTION_TCP_HEADER(tcp),MAX_TCP_HEADER(tcp), TCP_OPT_WSCALE);
		if(wscale)
			msf->wscale[S2C] = *(wscale+2);
		fprintf(stderr, "well done, we find him  ! ..... \n");
	}
	else{
		fprintf(stderr, "could not find syn, sorry...\n");
	}
}

void updateListCapable(List* l, struct sniff_ip *ip, struct sniff_tcp *tcp){
	if(SYN_SET(tcp)){
		if(ACK_SET(tcp)){
			//TODO
			add_MPTCP_conn_synack(l, ip, tcp);
		}
		else{
			add_MPTCP_conn_syn(l, ip, tcp);
		}
	}
	else{
		if(ACK_SET(tcp)){
			fprintf(stderr, "3 in 3HWS\n");
		}
		else{
			printf("MMMMmmmmm \n");
		}
	}
}

int checkSynAckJoin(mptcp_sf *msf){
	mptcp_conn *mc =  msf->mc_parent;
	u_char hmac[20];
	char  nonceBA[2*NONCE_SIZE];
	char keyBA[2*KEY_SIZE];
	memcpy(&keyBA,mc->server_key,KEY_SIZE);
	memcpy(keyBA + KEY_SIZE,mc->client_key,KEY_SIZE);
	memcpy(&nonceBA,&msf->server_nonce,NONCE_SIZE);
	memcpy(nonceBA+NONCE_SIZE,&msf->client_nonce,NONCE_SIZE);
	HMAC(EVP_sha1(),keyBA,2*KEY_SIZE,nonceBA,2*NONCE_SIZE,hmac,NULL);
	//TODO, add reverse way, if connection comes from the server.
	if(memcmp(hmac,msf->hmac_server,8)==0){
		fprintf(stderr, "Good HMAC ! \n");
		return 0;
	}
	else{
		fprintf(stderr, "Wrong HMAAAAAAAAAAAAAAAAAAC ! \n");
		return 1;
	}


}

void add_MPTCP_join_synack(List* l, struct sniff_ip *ip, struct sniff_tcp *tcp){
	mptcp_sf msfr, *msf;
	build_msf(ip,tcp,&msfr,REVERT,0);

	msf = getSubflow(l,&msfr);
	if(msf==NULL){
		fprintf(stderr, "Warning, unfound syn...\n");
		return;
	}

	u_char* wscale = next_opt_x(OPTION_TCP_HEADER(tcp),MAX_TCP_HEADER(tcp), TCP_OPT_WSCALE);
	if(wscale)
		msf->wscale[S2C] = *(wscale+2);
	u_char* mpcapa = first_MPTCP_sub(tcp,MPTCP_SUB_JOIN);

	memcpy(&msf->server_nonce,mpcapa+12,4);
	memcpy(&msf->hmac_server,mpcapa+4,8);
	if(checkSynAckJoin(msf)==0){
		fprintf(stderr, "Server h-mac has been checked ! ..... \n");
	}
	else{
		fprintf(stderr, "Server h-mac is wrong ... \n");
	}
}

int compareHash(void* element, int pos, void* arg, void *acc){
	mptcp_conn *mc = (mptcp_conn*)element;
	u_char sha_dig2[20];
	SHA1(mc->server_key,KEY_SIZE,sha_dig2);
	return (memcmp(sha_dig2,arg,4)==0) ? 1 : 0;
}

mptcp_conn* getConnectionFromHash(List* l,u_char* hash){
	return (mptcp_conn*)search(l,compareHash, hash,NULL);
}

void add_MPTCP_join_syn(List* l, struct sniff_ip *ip, struct sniff_tcp *tcp){
	mptcp_sf *msf = new_msf(ip,tcp);
	u_char* wscale = next_opt_x(OPTION_TCP_HEADER(tcp),MAX_TCP_HEADER(tcp), TCP_OPT_WSCALE);
	if(wscale)
		msf->wscale[C2S] = *(wscale+2);
	u_char* mpcapa = first_MPTCP_sub(tcp,MPTCP_SUB_JOIN);
	mptcp_conn *mc = getConnectionFromHash(l,mpcapa+4);
	if(mc){
		msf->mc_parent = mc;
		msf->id=mc->mptcp_sfs->size;
		addElementHead(msf, mc->mptcp_sfs);
		memcpy(&msf->client_nonce,mpcapa+8,NONCE_SIZE);
		fprintf(stderr, "The key has been found and the nonce copied ! ..... \n");
	}
	else{
		free(msf);
		fprintf(stderr, "no Key found :(...\n");
	}
}

void updateListJoin(List* l,  struct sniff_ip *ip, struct sniff_tcp *tcp){
	if(SYN_SET(tcp)){
		if(ACK_SET(tcp)){
			add_MPTCP_join_synack(l,ip,tcp);
		}
		else{
			add_MPTCP_join_syn(l,ip, tcp);
		}
	}
	else{
		if(ACK_SET(tcp)){
			fprintf(stderr, "3 in 3HWS\n"); // we could check the second hmac
		}
		else{
			printf("MMMMmmmmm \n");
		}
	}
}

void printMPTCPSublflow(void* element, int pos, void* fix, void* acc){
	mptcp_sf *msf = (mptcp_sf*) element;
	printf("\tSubflow %d with wscale : %d %d\n",pos,msf->wscale[C2S], msf->wscale[S2C]);
}
void printMPTCPConnections(void* element, int pos, void* fix, void* acc){
	printf("MPTCP connection %d\n",pos);
	apply(((mptcp_conn*)element)->mptcp_sfs,printMPTCPSublflow,NULL,NULL);
}
void printAllConnections(List *l){
	apply(l,printMPTCPConnections,NULL,NULL);
}

void destroyModules(void* element, int pos, void* fix, void* acc){
	int i;
	mptcp_conn *mc = (mptcp_conn*) element;
	for(i=0;i<MAX_GRAPH;i++) if(modules[i].activated) modules[i].destroyModule(&mc->graphdata[i],mc->mci);
	for(i=0;i<TCP_MAX_GRAPH;i++) if(tcpModules[i].activated) tcpModules[i].destroyModule(&mc->graphdata[i],mc->mci);
}

