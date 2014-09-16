/*
 * TCPOptions.c
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

u_char* next_opt_x(u_char *opt, u_char* max, u_char x){
	u_char* next_opt = opt;
	while(next_opt < max){
		if(*next_opt == TCPOPT_EOL)
			return NULL;
		if(*next_opt == x)
			return next_opt;
		if(*next_opt == TCPOPT_NOP)
			next_opt++;
		else{
			next_opt += (uint8_t)*(next_opt + 1);
		}
	}
	return NULL;
}

u_char* next_MPTCP_opt(u_char *opt, u_char* max){
	return next_opt_x(opt,max,TCPOPT_MPTCP);
}

u_char* next_MPTCP_sub(u_char *opt, u_char* max, u_char sub){
	u_char* cur = next_MPTCP_opt(opt, max);
	while(cur){
		if(*(cur + 2) >> 4 == sub)
			return cur;
		cur = next_MPTCP_opt(cur+(uint8_t)*(cur + 1), max);
	}
	return NULL;
}

u_char* first_MPTCP_sub(struct sniff_tcp *tcp,u_char sub){
	return next_MPTCP_sub(OPTION_TCP_HEADER(tcp),MAX_TCP_HEADER(tcp),sub );
}
int isIPv4(struct sniff_ethernet *ethernet){
	return ntohs(ethernet->ether_type) == IPv4_ETHERTYPE;
}
int isIPVersionCorrect(struct sniff_ip *ip){
	return IP_V(ip) == 4 || IP_V(ip) == 6;
}
int isTCP(struct sniff_ip *ip){
	return ip->ip_p == 6;
}
int isSYNSegment(struct sniff_tcp *tcp){
	return SYN_SET(tcp);
}
u_char* contains_MPTCP(struct sniff_tcp *tcp){
	return next_MPTCP_opt(OPTION_TCP_HEADER(tcp),MAX_TCP_HEADER(tcp) );
}

u_char* isMPTCP_capable(struct sniff_tcp *tcp){
	return first_MPTCP_sub(tcp,MPTCP_SUB_CAPABLE );
}



u_char* isMPTCP_join(struct sniff_tcp *tcp){
	return first_MPTCP_sub(tcp,MPTCP_SUB_JOIN );
}

u_char* isMPTCP_dss(struct sniff_tcp *tcp){
	return first_MPTCP_sub(tcp,MPTCP_SUB_DSS);
}

u_char* isMPTCP_addAddr(struct sniff_tcp *tcp){
	return first_MPTCP_sub(tcp,MPTCP_ADD_ADDR);
}

u_char* isMPTCP_rmAddr(struct sniff_tcp *tcp){
	return first_MPTCP_sub(tcp,MPTCP_RM_ADDR);
}

