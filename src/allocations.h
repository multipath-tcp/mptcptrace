/*
 * allocations.h
 *
 *  Created on: Jan 8, 2014
 *      Author: Benjamin Hesmans
 */

#ifndef ALLOCATIONS_H_
#define ALLOCATIONS_H_


void build_msf(struct sniff_ip *ip, struct sniff_tcp *tcp, mptcp_sf *msf, int revert, int initList);
mptcp_sf* new_msf(struct sniff_ip *ip, struct sniff_tcp *tcp);
mptcp_sf* new_msf_revert(struct sniff_ip *ip, struct sniff_tcp *tcp);
mptcp_map* new_mpm();

mptcp_ack* new_mpa();

#endif /* ALLOCATIONS_H_ */
