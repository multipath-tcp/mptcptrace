/*
 * TCPOptions.h
 *
 *  Created on: Jan 8, 2014
 *      Author: Benjamin Hesmans
 */

#ifndef TCPOPTIONS_H_
#define TCPOPTIONS_H_

/***
 * OPTIONS PARSING
 */
u_char* next_opt_x(u_char *opt, u_char* max, u_char x);
u_char* next_MPTCP_opt(u_char *opt, u_char* max);
u_char* next_MPTCP_sub(u_char *opt, u_char* max, u_char sub);
u_char* first_MPTCP_sub(struct sniff_tcp *tcp,u_char sub);
int isIPv4(struct sniff_ethernet *ethernet);
int isIPVersionCorrect(struct sniff_ip *ip);
int isTCP(struct sniff_ip *ip);
int isSYNSegment(struct sniff_tcp *tcp);
int isRSTSegment(struct sniff_tcp *tcp);
int isFINSegment(struct sniff_tcp *tcp);
u_char* contains_MPTCP(struct sniff_tcp *tcp);
u_char* isMPTCP_capable(struct sniff_tcp *tcp);
u_char* isMPTCP_join(struct sniff_tcp *tcp);
u_char* isMPTCP_dss(struct sniff_tcp *tcp);
u_char* isMPTCP_addAddr(struct sniff_tcp *tcp);
u_char* isMPTCP_rmAddr(struct sniff_tcp *tcp);

#endif /* TCPOPTIONS_H_ */
