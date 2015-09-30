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
#include "traceInfo.h"

int id_con=0;

//TODO TODO il faut faire le memset pour pouvoir utiliseer une fo de hash (sil y a du padding)
#ifdef USE_HASHTABLE
int SF_KEY_LEN = (offsetof(mptcp_sf, state) - offsetof(mptcp_sf, ip_src));
int CON_KEY_LEN =  HASH_SIZE;
#endif

void addMPTCPConnection(void *l, mptcp_conn *mc, int update){
	if(!update){
		incCounter(CONNECTION_COUNTER,C2S);
		int i= 0;
		for(i=0;i<MAX_GRAPH;i++) if(modules[i].activated)  modules[i].initModule(&mc->graphdata[i],mc->mci);
		for(i=0;i<TCP_MAX_GRAPH;i++) if(tcpModules[i].activated) tcpModules[i].initModule(&mc->graphdata[i],mc->mci);
	}
#ifdef USE_HASHTABLE
	mptcp_conn ** ht = l;
	u_char sha_dig2[20];
	SHA1(mc->server_key,KEY_SIZE,sha_dig2);

	if(getConnectionFromHash(l,sha_dig2)){
		printf("%s collision ? \n",__func__);
		return;
	}else{
		memcpy(&mc->hash_s,sha_dig2,HASH_SIZE);
	//printf("%s %p \n", __func__, *ht);
	//printf("%s 0x%x 0x%x 0x%x 0x%x\n",__func__, sha_dig2[0], sha_dig2[1], sha_dig2[2], sha_dig2[3]);
	//printf("%s before I add ..pointeris %p id is %d\n",__func__, *ht, id_con);
	HASH_ADD( hh, *ht, hash_s, CON_KEY_LEN, mc);
	//printf("%s do I finish this ? \n",__func__);
	}
	//printf("%s %p %p\n", __func__, *ht,mc);
	fflush(stdout);
#else
	addElementHead(mc,l);
#endif
}

void AddLostSyn(void *l, mptcp_sf *msf){
#ifdef USE_HASHTABLE
	mptcp_sf ** ht = l;
	if(getSubflow(l,msf)){printf("%s collision ? \n",__func__); return;}
	//printf("%s before I add ..pointeris %p \n",__func__, *ht);
	HASH_ADD( hh, *ht, ip_src, SF_KEY_LEN, msf);
	//printf("%s %p \n", __func__, *ht);
#else
	addElementHead(msf, l);
#endif
}
void rmLostSyn(void *l, mptcp_sf *msf){
#ifdef USE_HASHTABLE
	mptcp_sf ** ht = l;
	//printf("%s Removing", __func__);
	//printf("%s before I del ..pointeris %p \n",__func__, *ht);
	fflush(stdout);
	HASH_DEL( *ht, msf);
	//printf("%s %p \n", __func__, *ht);
#else

#endif
}

void rmConn(void *l, mptcp_conn *mc){
#ifdef USE_HASHTABLE
	if(checkServerKey(mc->server_key)){
		return;
	}
	mptcp_conn ** ht = l;
	//printf("%s Removing", __func__);
	//printf("%s before I del ..pointeris %p \n",__func__, *ht);
	fflush(stdout);
	HASH_DEL( *ht, mc);
	//printf("%s %p \n", __func__, *ht);
#else

#endif
}


void addMPTCPSubflow(void *local, void *global, mptcp_sf *msf){
	incCounter(SUBFLOW_COUNTER,C2S);//TODO define way ??
#ifdef USE_HASHTABLE
	mptcp_sf ** ht = global;
	//printf("%s %p \n", __func__, *ht);
	if(getSubflow(global,msf)){printf("%s collision ? \n",__func__);}else{
	//printf("%s before I add ..pointeris %p \n",__func__, *ht);
	HASH_ADD( hh, *ht, ip_src, SF_KEY_LEN, msf);
	}
	//printf("%s %p \n", __func__, *ht);
#endif
	addElementHead(msf, local);
}

int beforeUI(unsigned int ui1, unsigned int ui2){
	return (int)(ui1-ui2)<0;
}

int afterUI(unsigned int ui1, unsigned int ui2){
	return beforeUI(ui2,ui1);
}

int afterOrEUI(unsigned int ui1, unsigned int ui2){
	return !beforeUI(ui1,ui2);
}

int beforeOrEUI(unsigned int ui1, unsigned int ui2){
	return !afterUI(ui1,ui2);
}

int compareMap(void *e1, void *e2){
	mptcp_map* m1 = (mptcp_map *)e1;
	mptcp_map* m2 = (mptcp_map *)e2;
	if(beforeUI(SEQ_MAP_START(m1),SEQ_MAP_START(m2))) return -1;
	return afterUI(SEQ_MAP_START(m1),SEQ_MAP_START(m2)) ? 1 : 0;
	//if(SEQ_MAP_START(m1)<SEQ_MAP_START(m2)) return -1;
	//return (SEQ_MAP_START(m1)>SEQ_MAP_START(m2)) ? 1 : 0;
}

int compareTcpMap(void *e1, void *e2){
	tcp_map* m1 = (tcp_map *)e1;
	tcp_map* m2 = (tcp_map *)e2;
	if(beforeUI(m1->start , m2->start)) return -1;
	return (afterUI(m1->start , m2->start)) ? 1 : 0;
	//if(m1->start < m2->start) return -1;
	//return (m1->start > m2->start) ? 1 : 0;
}

int compareInt(void *e1, void *e2){
	unsigned int* i1 = (unsigned int *)e1;
	unsigned int* i2 = (unsigned int *)e2;
	if(beforeUI(*i1 ,*i2)) return -1;
	return afterUI(*i1 , *i2) ? 1 : 0;
}
int subflowsEqual(mptcp_sf* s1,  mptcp_sf* s2){
	if(		s1->family == s2->family &&
			memcmp(&s1->ip_dst,&s2->ip_dst, s1->family == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr)) == 0 &&
			memcmp(&s1->ip_src, &s2->ip_src,s1->family == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr)) == 0 &&
			memcmp(&s1->th_dport, &s2->th_dport,sizeof(u_short)) == 0 &&
			memcmp(&s1->th_sport, &s2->th_sport,sizeof(u_short)) == 0)
		return 1;
	return 0;
}

int subflowsEqualWrapper(void* s1, int pos, void* s2, void* acc){
	mptcp_sf *sf1 = (mptcp_sf*) s1;
	mptcp_sf *sf2 = (mptcp_sf*) s2;
	return subflowsEqual(s1,s2);
}
int searchMPTCPConnection(void* mc, int pos, void* searchFun, void *acc){
	int (*s)(void*, int, void*, void*) = (int (*)(void*, int, void*, void*)) searchFun;
	mptcp_sf* sf = (mptcp_sf*) search(((mptcp_conn*)mc)->mptcp_sfs,s,((toFindRes*)acc)->toFind,NULL);
	((toFindRes*)acc)->result = sf;
	return sf == NULL ? 0 : 1;

}


mptcp_sf* getSubflow(void *l,mptcp_sf *msf){
#ifndef USE_HASHTABLE
	toFindRes acc;
	acc.toFind = msf;
	acc.result = NULL;
	search(l,searchMPTCPConnection,subflowsEqualWrapper,&acc);
	return (mptcp_sf*) acc.result;
#else
	mptcp_sf ** ht = l;
	mptcp_sf *res=NULL;
	//printf("key len = %d \n", SF_KEY_LEN);
	//printf("%s %p msfp %p \n", __func__, *ht, msf);
	HASH_FIND( hh, *ht, &msf->ip_src, SF_KEY_LEN , res);
	return res;
#endif
}
void closeConn(void *l, void *ht, mptcp_conn *mc){
	if(!checkServerKey(mc->server_key)){
		destroyModules(mc,0,NULL,NULL);
	}
	printMPTCPConnections(mc,0,stdout,NULL);
	fflush(stdout);
	freecon(mc,NULL);
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

//#ifdef USE_HASHTABLE
//int getConnectionID(mptcp_conn *l){
//	return HASH_COUNT(l);
//}
//#else
int getConnectionID(){
	id_con+=1;
	return id_con;
}
//#endif

void add_MPTCP_conn_syn(void* l, struct sniff_ip *ip, struct sniff_tcp *tcp, void *ht, struct timeval ts){
	mptcp_sf *msf = new_msf(ip,tcp);
	mptcp_sf *fmsf;
	int i;
	u_char* wscale = next_opt_x(OPTION_TCP_HEADER(tcp),MAX_TCP_HEADER(tcp), TCP_OPT_WSCALE);
	if(wscale)
		msf->wscale[C2S] = *(wscale+2);

	fmsf = getSubflow(l,msf);
	if(fmsf){
		if(fmsf->id != 0) {
			mplogmsf(WARN, msf, "Capable follow a join... Reuising port !\n");
			incCounter(CAPABLE_AFTER_JOIN_REUSE_PORT,C2S);
			rmLostSyn(l, fmsf);

		}
		else {
			mplogmsf(WARN,msf, "Retransmitted syn ..... \n");
			free(msf);
			return;
		}
	}

	mptcp_conn *mc = (mptcp_conn*) exitMalloc(sizeof(mptcp_conn));
	MPTCPConnInfo *mci = (MPTCPConnInfo *) exitMalloc(sizeof(MPTCPConnInfo));
	char str[42];

	mc->mci = mci;
	mc->id = getConnectionID();
	mc->mci->mc = mc;
	mc->mci->lastActivity = ts;
	memset(&mc->server_key,0,KEY_SIZE);

	if(add_addr){
		sprintf(str,"add_addr_%d.csv",mc->id);
		mc->addAddr=fopen(str,"w");
	}
	if(rm_addr){
		sprintf(str,"rm_addr_%d.csv",mc->id);
		mc->rmAddr=fopen(str,"w");
	}

	//for(i=0;i<MAX_GRAPH;i++) if(modules[i].activated)  modules[i].initModule(&mc->graphdata[i],mc->mci);
	//for(i=0;i<TCP_MAX_GRAPH;i++) if(tcpModules[i].activated) tcpModules[i].initModule(&mc->graphdata[i],mc->mci);
	u_char* mpcapa = first_MPTCP_sub(tcp,MPTCP_SUB_CAPABLE);
	memcpy(&mc->client_key, mpcapa+4, KEY_SIZE);
	//TODO free them
	mc->mptcp_sfs = newList(freemsf,l);
	mplog(LOGALL, "%s Fixing mc_parent...\n",__func__);
	msf->mc_parent = mc;
	mplog(LOGALL,  "-----------Adding master sf ... ! ..... \n");
	msf->id=mc->mptcp_sfs->size;
	//addElementHead(msf,mc->mptcp_sfs);
	addMPTCPSubflow(mc->mptcp_sfs, l, msf);
	mplog(LOGALL, "%s subflow added!..\n",__func__);
	//addElementHead(mc,l);
#ifndef USE_HASHTABLE
	addMPTCPConnection(ht,mc, 0);
#endif
}

void initSequenceNumber(mptcp_conn *mc, struct timeval ts){
	mptcp_map *initSeq[WAYS];
	mptcp_ack *initAck[WAYS];
	initSeq[C2S] = exitMalloc(sizeof(mptcp_map));
	initSeq[S2C] = exitMalloc(sizeof(mptcp_map));
	unsigned int tmp;
	u_char sha_dig2[20];
	SHA1(mc->client_key,KEY_SIZE,sha_dig2);
	memcpy(initSeq[C2S]->start,&sha_dig2[16],4);
	//TODO pass the rest of the informations.
	//initSeq[C2S]->len = 1;
	initSeq[C2S]->ts =  ts;
	initSeq[C2S]->msf = mc->mptcp_sfs->head->element;
	mc->mci->firstSeq[C2S] = initSeq[C2S];
	SHA1(mc->server_key,KEY_SIZE,sha_dig2);
	memcpy(initSeq[S2C]->start,&sha_dig2[16],4);
	initSeq[S2C]->msf = mc->mptcp_sfs->head->element;
	mc->mci->firstSeq[S2C] = initSeq[S2C];
	initSeq[S2C]->ts =  ts;

	//TODO CLEAN
	// init last ack if needed.
	initAck[C2S] = exitMalloc(sizeof(mptcp_ack));
	initAck[S2C] = exitMalloc(sizeof(mptcp_ack));
	tmp = SEQ_MAP_START(initSeq[C2S]) - 1;
	tmp = htonl(tmp);
	memcpy(initAck[S2C]->ack, &tmp, sizeof(unsigned int));
	tmp = SEQ_MAP_START(initSeq[S2C]) - 1;
	tmp = htonl(tmp);
	memcpy(initAck[C2S]->ack, &tmp, sizeof(unsigned int));
	initAck[C2S]->ts = ts;
	initAck[S2C]->ts = ts;
	mc->mci->lastack[C2S] = initAck[C2S];
	mc->mci->lastack[S2C] = initAck[S2C];
	mc->mci->lastack[C2S]->ref_count=1;
	mc->mci->lastack[S2C]->ref_count=1;

	mc->mci->lastActivity = ts;
}

void add_MPTCP_conn_thirdAck(void* l, struct sniff_ip *ip, struct sniff_tcp *tcp, void *lostSynCapable, struct timeval ts, void* ht){
	mptcp_sf msfs,*msf;
	int i;
	build_msf(ip,tcp,&msfs,DONOTREVERT,0);
	msf = getSubflow(l,&msfs);
	if(msf==NULL){
		mplogmsf(LOGALL, &msfs,"------------------------syn lost, looking to recover...\n");
#ifndef USE_HASHTABLE
		msf = search(lostSynCapable,subflowsEqualWrapper,&msfs,NULL);
#else
		printf("%s %p \n",__func__,*((void**)lostSynCapable));
		msf = getSubflow(lostSynCapable, &msfs);
#endif
		if(msf != NULL){
			mplogmsf(LOGALL,msf,"Find him in the lost list...\n");
			//consider the same scale...
			msf->wscale[C2S] = msf->wscale[S2C];
			mptcp_conn *mc = (mptcp_conn*) exitMalloc(sizeof(mptcp_conn));
			MPTCPConnInfo *mci = (MPTCPConnInfo *) exitMalloc(sizeof(MPTCPConnInfo));
			memset(mc,0,sizeof(mptcp_conn));
			char str[42];
			mc->mci = mci;
			mc->id = getConnectionID();
			mc->mci->mc = mc;
			mc->mci->lastActivity = ts;

			if(add_addr){
				sprintf(str,"add_addr_%d.csv",mc->id);
				mc->addAddr=fopen(str,"w");
			}
			if(rm_addr){
				sprintf(str,"rm_addr_%d.csv",mc->id);
				mc->rmAddr=fopen(str,"w");
			}

			//for(i=0;i<MAX_GRAPH;i++) if(modules[i].activated)  modules[i].initModule(&mc->graphdata[i],mc->mci);
			//for(i=0;i<TCP_MAX_GRAPH;i++) if(tcpModules[i].activated) tcpModules[i].initModule(&mc->graphdata[i],mc->mci);
			u_char* mpcapa = first_MPTCP_sub(tcp,MPTCP_SUB_CAPABLE);
			memcpy(&mc->client_key, mpcapa+4, KEY_SIZE);
			memcpy(&mc->server_key, mpcapa+4+KEY_SIZE, KEY_SIZE);
			//TODO free them
			mc->mptcp_sfs = newList(freemsf, l);
			fprintf(stderr,"%s Fixing mc_parent...\n",__func__);
			msf->mc_parent = mc;
			msf->id=mc->mptcp_sfs->size;
			//TODO we should remove msf from the lost list
			rmLostSyn(lostSynCapable,msf);
			//addElementHead(msf,mc->mptcp_sfs);
			addMPTCPSubflow(mc->mptcp_sfs, l, msf);
			//addElementHead(mc,l);
			addMPTCPConnection(ht,mc, 0);
		}
		else{
			mplogmsf(LOGALL, &msfs, "------------------------------I do not find him in the lost list...\n");
			return;
		}
	}
	else{
		u_char* mpcapa = first_MPTCP_sub(tcp,MPTCP_SUB_CAPABLE);
		if(memcmp(msf->mc_parent->client_key, mpcapa + 4, KEY_SIZE) ||
				memcmp(msf->mc_parent->server_key, mpcapa + 4 + KEY_SIZE, KEY_SIZE)){
			mplogmsf(WARN, msf, "The key from SYN or SYNACK differs from third ack.\n");
			rmConn(ht, msf->mc_parent);
			memcpy(&msf->mc_parent->client_key, mpcapa + 4, KEY_SIZE);
			memcpy(&msf->mc_parent->server_key, mpcapa + 4 + KEY_SIZE, KEY_SIZE);
			addMPTCPConnection(ht, msf->mc_parent, 1);
			incCounter(THIRD_ACK_KEYDIFF, C2S);
		}
	}
	initSequenceNumber(msf->mc_parent,ts);
	for(i=0;i<MAX_GRAPH;i++) if(modules[i].activated && modules[i].handleNewSF) modules[i].handleNewSF(msf,msf->mc_parent->graphdata[i],msf->mc_parent->mci);
	//TODO build the init sequence number based on key
}
int checkServerKey(u_char *k){
	int i;
	for(i=0;i<KEY_SIZE;i++){
		if(*(k+i)!=0) return 0;
	}
	return 1;
}
void add_MPTCP_conn_synack(void* l, struct sniff_ip *ip, struct sniff_tcp *tcp, List *lostSynCapable,  void *ht){
	mptcp_sf msfr;
	mptcp_sf *msfSynLost;
	build_msf(ip,tcp,&msfr,REVERT,0);
	//printf("%s %p\n",__func__,*((void**)l));
	mptcp_sf *msf = getSubflow(l,&msfr);
	if(msf){
		u_char* mpcapa = first_MPTCP_sub(tcp,MPTCP_SUB_CAPABLE);
		//TODO msf should allow access to the parent
		if(msf->mc_parent == NULL){
			mplog(BUG, "%s : Conection parent not fixed in a subflow...\n",__func__);

		}
		else{
			if(memcmp(&(msf->mc_parent)->server_key,mpcapa+4,KEY_SIZE)==0){
				mplogmsf(WARN,msf,"%s Duplicate syn ack ?\n",__func__);
				return;
			}
			if(checkServerKey(msf->mc_parent->server_key) == 0){
				incCounter(SYNACK_DIFFKEY_COUNTER,C2S);
				mplogmsf(WARN,msf,"Syn-ack with different key : \n");
				return;
			}
			memcpy(&(msf->mc_parent)->server_key, mpcapa+4, 8);
		}
		u_char* wscale = next_opt_x(OPTION_TCP_HEADER(tcp),MAX_TCP_HEADER(tcp), TCP_OPT_WSCALE);
		if(wscale)
			msf->wscale[S2C] = *(wscale+2);
		mplog(LOGALL, "well done, we find him  ! ..... \n");
#ifdef USE_HASHTABLE
		addMPTCPConnection(ht,msf->mc_parent, 0);
#endif
		//fprintf(stderr, "And finish to add connection ! ..... \n");
	}
	else{
		msfSynLost = (mptcp_sf*) exitMalloc(sizeof(mptcp_sf));
		build_msf(ip,tcp,msfSynLost,REVERT,1);
		u_char* wscale = next_opt_x(OPTION_TCP_HEADER(tcp),MAX_TCP_HEADER(tcp), TCP_OPT_WSCALE);
		if(wscale)
			msfSynLost->wscale[S2C] = *(wscale+2);
		//addElementHead(msfSynLost,lostSynCapable);
		//addMPTCPSubflow(lostSynCapable, NULL, msfSynLost);
		AddLostSyn(lostSynCapable,msfSynLost);
		//TODO create a msf, put in a special list, lost syn...
		mplog(LOGALL,  "could not find syn, put him in backup list...\n");
	}
}

void updateListCapable(void* l, struct sniff_ip *ip, struct sniff_tcp *tcp, void *lostSynCapable, struct timeval ts,  void *ht){
	if(SYN_SET(tcp)){
		if(ACK_SET(tcp)){
			//TODO
			add_MPTCP_conn_synack(l, ip, tcp, lostSynCapable, ht);
		}
		else{
			add_MPTCP_conn_syn(l, ip, tcp, ht, ts);
		}
	}
	else{
		if(ACK_SET(tcp)){
			mplog(LOGALL,  "MPTCP capable : 3 in 3HWS\n");
			add_MPTCP_conn_thirdAck(l,ip,tcp,lostSynCapable,ts, ht);
		}
		else{
			mplog(BUG, "%s MPCAPABLE without syn nor ack set \n",__func__);
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
		mplog(LOGALL, "Good HMAC ! \n");
		return 0;
	}
	else{
		incCounter(JOIN_WRONG_HMAC_COUNTER,C2S);
		mplogmsf(WARN, msf, "Hmac can not be check for the in the join : \n");
		return 1;
	}


}

void add_MPTCP_join_synack(void* l, struct sniff_ip *ip, struct sniff_tcp *tcp){
	mptcp_sf msfr, *msf;
	build_msf(ip,tcp,&msfr,REVERT,0);

	msf = getSubflow(l,&msfr);
	if(msf==NULL){
		mplogmsf(WARN, &msfr, "Can not find Join syn for ..\n");
		incCounter(JOIN_FAILED_COUNTER,C2S);
		return;
	}

	u_char* wscale = next_opt_x(OPTION_TCP_HEADER(tcp),MAX_TCP_HEADER(tcp), TCP_OPT_WSCALE);
	if(wscale)
		msf->wscale[S2C] = *(wscale+2);
	u_char* mpcapa = first_MPTCP_sub(tcp,MPTCP_SUB_JOIN);

	memcpy(&msf->server_nonce,mpcapa+12,4);
	memcpy(&msf->hmac_server,mpcapa+4,8);
	if(checkSynAckJoin(msf)==0){
		mplog(LOGALL,  "Server h-mac has been checked ! ..... \n");
	}
	else{
		//fprintf(stderr, "Server h-mac is wrong ... !\n");
		//printf("Server h-mac is wrong ... !\n");
		//printMPTCPSubflow(msf,0,stdout,NULL);
	}
}

int compareHash(void* element, int pos, void* arg, void *acc){
	mptcp_conn *mc = (mptcp_conn*)element;
	u_char sha_dig2[20];
	SHA1(mc->server_key,KEY_SIZE,sha_dig2);
	return (memcmp(sha_dig2,arg,4)==0) ? 1 : 0;
}

mptcp_conn* getConnectionFromHash(void* l,u_char* hash){
#ifndef USE_HASHTABLE
	return (mptcp_conn*)search(l,compareHash, hash,NULL);
#else
	mptcp_conn ** ht = l;
	mptcp_conn *res=NULL;
	//printf("%s 0x%x 0x%x 0x%x 0x%x\n", __func__,hash[0], hash[1], hash[2], hash[3]);
	HASH_FIND( hh, *ht, hash, CON_KEY_LEN , res);
	return res;
#endif
}

void add_MPTCP_join_syn(void* l, struct sniff_ip *ip, struct sniff_tcp *tcp, void *ht){
	mptcp_sf *msf = new_msf(ip,tcp);
	int i;
	u_char* wscale = next_opt_x(OPTION_TCP_HEADER(tcp),MAX_TCP_HEADER(tcp), TCP_OPT_WSCALE);
	if(getSubflow(l,msf)){
		mplogmsf(WARN,msf,"Retransmitted syn_join ..... \n");
		free(msf);
		return;
	}
	if(wscale)
		msf->wscale[C2S] = *(wscale+2);
	u_char* mpcapa = first_MPTCP_sub(tcp,MPTCP_SUB_JOIN);
#ifndef USE_HASHTABLE
	mptcp_conn *mc = getConnectionFromHash(l,mpcapa+4);
#else
	mptcp_conn *mc = getConnectionFromHash(ht,mpcapa+4);
#endif
	if(mc){
		msf->mc_parent = mc;
		msf->id=mc->mptcp_sfs->size;
		mplog(LOGALL, "-----------Adding sf ... ! ..... \n");
		//addElementHead(msf, mc->mptcp_sfs);
		addMPTCPSubflow(mc->mptcp_sfs, l, msf);
		memcpy(&msf->client_nonce,mpcapa+8,NONCE_SIZE);
		mplog(LOGALL, "The key has been found and the nonce copied ! ..... \n");
		for(i=0;i<MAX_GRAPH;i++) if(modules[i].activated && modules[i].handleNewSF) modules[i].handleNewSF(msf,mc->graphdata[i],mc->mci);
	}
	else{
		incCounter(JOIN_FAILED_COUNTER,C2S);
		mplogmsf(WARN , msf, "no Key found :(...\n");
		free(msf);
	}
}

void updateListJoin(void* l,  struct sniff_ip *ip, struct sniff_tcp *tcp, void *ht){
	if(SYN_SET(tcp)){
		if(ACK_SET(tcp)){
			add_MPTCP_join_synack(l,ip,tcp);
		}
		else{
			add_MPTCP_join_syn(l,ip, tcp, ht);
		}
	}
	else{
		if(ACK_SET(tcp)){
			mplog(LOGALL,"3 in 3HWS\n");
		}
		else{
			mplog(LOGALL,"MMMMmmmmm \n");
		}
	}
}

void printMPTCPSubflow(void* element, int pos, void* fix, void* acc){
	mptcp_sf *msf = (mptcp_sf*) element;
	char straddr[INET6_ADDRSTRLEN+1];

	fprintf(fix, "\tSubflow %d with wscale : %d %d IPv%d ",pos,msf->wscale[C2S], msf->wscale[S2C], msf->family == AF_INET ? 4 : 6);
	fprintf(fix, "sport %hu",ntohs(msf->th_sport));
	fprintf(fix, " dport %hu ",ntohs(msf->th_dport));
	if(msf->family == AF_INET){
		fprintf(fix, "saddr %s ", inet_ntoa(msf->ip_src.in));
		fprintf(fix, "daddr %s \n", inet_ntoa(msf->ip_dst.in));
	}
	else{
		inet_ntop(AF_INET6,&msf->ip_src.in6,straddr,INET6_ADDRSTRLEN+1);
		fprintf(fix, "saddr %s ",straddr);
		inet_ntop(AF_INET6,&msf->ip_dst.in6,straddr,INET6_ADDRSTRLEN+1);
		fprintf(fix, "daddr %s \n",straddr);
	}
}
void printMPTCPConnections(void* element, int pos, void* fix, void* acc){
	fprintf(fix,"MPTCP connection %d with id %d\n",pos,((mptcp_conn*)element)->id);
	apply(((mptcp_conn*)element)->mptcp_sfs,printMPTCPSubflow,fix,NULL);
}
void printAllConnections(List *l){
	apply(l,printMPTCPConnections,stdout,NULL);
}

void destroyModules(void* element, int pos, void* fix, void* acc){
	int i;
	mptcp_conn *mc = (mptcp_conn*) element;
	for(i=0;i<MAX_GRAPH;i++) if(modules[i].activated) modules[i].destroyModule(&mc->graphdata[i],mc->mci);
	for(i=0;i<TCP_MAX_GRAPH;i++) if(tcpModules[i].activated) tcpModules[i].destroyModule(&mc->graphdata[i],mc->mci);
}

