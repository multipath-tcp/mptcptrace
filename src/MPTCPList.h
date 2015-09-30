/*
 * MPTCPList.h
 *
 *  Created on: Jan 8, 2014
 *      Author: Benjamin Hesmans
 */

#ifndef MPTCPLIST_H_
#define MPTCPLIST_H_

int subflowsEqual(mptcp_sf* s1,  mptcp_sf* s2);
int subflowsEqualWrapper(void* s1, int pos, void* s2, void* acc);
int searchMPTCPConnection(void* mc, int pos, void* searchFun, void *acc);

mptcp_sf* getSubflowFromIPTCP(List *l,struct sniff_ip *ip, struct sniff_tcp *tcp, int *way);
mptcp_sf* getSubflow(void *l,mptcp_sf *msf);
void add_MPTCP_conn_syn(void* l, struct sniff_ip *ip, struct sniff_tcp *tcp, void *ht, struct timeval ts);
void add_MPTCP_conn_synack(void* l, struct sniff_ip *ip, struct sniff_tcp *tcp, List *lostSynCapable, void *ht);
void updateListCapable(void* l, struct sniff_ip *ip, struct sniff_tcp *tcp, void *lostSynCapable, struct timeval ts, void *ht);
int checkSynAckJoin(mptcp_sf *msf);
void add_MPTCP_join_synack(void* l, struct sniff_ip *ip, struct sniff_tcp *tcp);
int compareHash(void* element, int pos, void* arg, void *acc);
mptcp_conn* getConnectionFromHash(void* l,u_char* hash);

void add_MPTCP_join_syn(void* l, struct sniff_ip *ip, struct sniff_tcp *tcp, void *ht);
void updateListJoin(void* l,  struct sniff_ip *ip, struct sniff_tcp *tcp, void *ht);
void printMPTCPSubflow(void* element, int pos, void* fix, void* acc);
void printMPTCPConnections(void* element, int pos, void* fix, void* acc);
void printAllConnections(List *l);
void destroyModules(void* element, int pos, void* fix, void* acc);

int compareMap(void *e1, void *e2);
int compareInt(void *e1, void *e2);
int compareTcpMap(void *e1, void *e2);

int beforeUI(unsigned int ui1, unsigned int ui2);
int afterUI(unsigned int ui1, unsigned int ui2);
int afterOrEUI(unsigned int ui1, unsigned int ui2);
int beforeOrEUI(unsigned int ui1, unsigned int ui2);

void addMPTCPConnection(void *l, mptcp_conn *mc, int update);
void addMPTCPSubflow(void *local, void *global, mptcp_sf *msf);
void closeConn(void *l, void *ht, mptcp_conn *mc);
void rmConn(void *l, mptcp_conn *mc);

#endif /* MPTCPLIST_H_ */
