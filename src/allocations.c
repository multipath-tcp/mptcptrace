/*
 * allocations.c
 *
 *  Created on: Jan 8, 2014
 *      Author: Benjamin Hesmans
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <sys/time.h>
#include <string.h>
#include "mptcptrace.h"
#include "TCPOptions.h"
#include "allocations.h"
#include "MPTCPList.h"

mptcp_map* new_mpm(){
	mptcp_map *mpm = (mptcp_map*) malloc(sizeof(mptcp_map));
	return mpm;
}

mptcp_ack* new_mpa(){
	mptcp_ack *mpa = (mptcp_ack*) malloc(sizeof(mptcp_ack));
	return mpa;
}

void build_msf(struct sniff_ip *ip, struct sniff_tcp *tcp, mptcp_sf *msf, int revert, int initList){
	if(revert){
		memcpy(&msf->ip_dst,&ip->ip_src,sizeof(struct in_addr));
		memcpy(&msf->ip_src,&ip->ip_dst,sizeof(struct in_addr));
		memcpy(&msf->th_dport,&tcp->th_sport,sizeof(u_short));
		memcpy(&msf->th_sport,&tcp->th_dport,sizeof(u_short));
	}
	else{
		memcpy(&msf->ip_dst,&ip->ip_dst,sizeof(struct in_addr));
		memcpy(&msf->ip_src,&ip->ip_src,sizeof(struct in_addr));
		memcpy(&msf->th_dport,&tcp->th_dport,sizeof(u_short));
		memcpy(&msf->th_sport,&tcp->th_sport,sizeof(u_short));
	}
	if(initList){
		//TODO define the free fun
		msf->mseqs[S2C] = newList(NULL);
		msf->mseqs[C2S] = newList(NULL);
		msf->macks[S2C] = newList(NULL);
		msf->macks[C2S] = newList(NULL);
		msf->tcpUnacked[C2S] = newOrderedList(NULL,compareTcpMap);
		msf->tcpUnacked[S2C] = newOrderedList(NULL,compareTcpMap);
		msf->tcpLastAck[C2S] = NULL;
		msf->tcpLastAck[S2C] = NULL;
	}
	msf->mc_parent = NULL;
}

mptcp_sf* new_msf(struct sniff_ip *ip, struct sniff_tcp *tcp){
	mptcp_sf *msf = (mptcp_sf*) exitMalloc(sizeof(mptcp_sf));
	build_msf(ip,tcp,msf,DONOTREVERT,1);
	return msf;
}
mptcp_sf* new_msf_revert(struct sniff_ip *ip, struct sniff_tcp *tcp){
	mptcp_sf *msf = (mptcp_sf*) exitMalloc(sizeof(mptcp_sf));
	build_msf(ip,tcp,msf,REVERT,1);
	return msf;
}

