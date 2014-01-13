/*
 * mptcptrace.h
 *
 *  Created on: Jan 7, 2014
 *      Author: Benjamin Hesmans
 */

#ifndef MPTCPTRACE_H_
#define MPTCPTRACE_H_

#include "list.h"
#include <sys/time.h>

#define REVERT 1
#define DONOTREVERT 0

#define S2C 	0
#define C2S		1
#define WAYS	2


#define TCPOPT_MPTCP		30

#define NONCE_SIZE			4
#define KEY_SIZE			8
#define SEQ_SIZE			4
#define ACK_SIZE			4
#define LEN_SIZE			2
#define HMAC_SIZE			8

#define MPTCP_SUB_CAPABLE	0
#define MPTCP_SUB_JOIN		1
#define MPTCP_SUB_DSS		2

#define TCP_OPT_WSCALE		3

#define CONN_INFO			0
#define GRAPH_SEQUENCE		1
#define WIN_FLIGHT			2
#define MAX_GRAPH			3

#define TCP_WIN_FLIGHT		0
#define TCP_MAX_GRAPH		1



typedef struct mptcp_sf mptcp_sf;
typedef struct mptcp_conn mptcp_conn;
typedef struct mptcp_map mptcp_map;
typedef struct tcp_map tcp_map;
typedef struct mptcp_ack mptcp_ack;
typedef struct mptcp_road mptcp_road;
typedef struct graph_files graph_files;
typedef struct min_way min_way;
typedef struct seq_block seq_block;
typedef struct MPTCPConnInfo MPTCPConnInfo;

typedef struct toFindRes toFindRes;


struct MPTCPConnInfo{
	mptcp_conn *mc;
	OrderedList *unacked[WAYS];
	mptcp_ack *lastack[WAYS];

	//win etc.
};

struct toFindRes{
	void* toFind;
	void* result;
};
/*
 * A mptcp sublflow
 */
struct mptcp_sf{
	int id;
	mptcp_conn* mc_parent;
	struct in_addr  ip_src, ip_dst;
	u_short th_sport;
	u_short th_dport;
	int state;
	u_char client_nonce[NONCE_SIZE];
	u_char server_nonce[NONCE_SIZE];
	u_char hmac_server[HMAC_SIZE];
	u_char hmac_client[HMAC_SIZE];
	List* mseqs[2];
	List* macks[2];
	u_char wscale[2];

	//unacked by subflow
	OrderedList *tcpUnacked[WAYS];
	unsigned int *tcpLastAck[WAYS];
};

struct mptcp_conn{
	int id;
	List* mptcp_sfs;
	u_char client_key[KEY_SIZE];
	u_char server_key[KEY_SIZE];

	void* graphdata[MAX_GRAPH];
	void* tcpgraphdata[TCP_MAX_GRAPH];
	MPTCPConnInfo *mci;
};

struct mptcp_map{
	u_char start[SEQ_SIZE];
	u_char len[LEN_SIZE];
	struct timeval ts;
	mptcp_sf *msf;
};

struct mptcp_ack{
	u_char ack[ACK_SIZE];
	struct timeval ts;
	unsigned int right_edge;
};

struct mptcp_road{
	int mpc;
	int mpsf;
	int way;
	FILE *output;
};

struct tcp_map{
	unsigned int start;
	unsigned int end;
};





typedef u_int32_t tcp_seq;

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

#define IPv4_ETHERTYPE 0x800

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* Ethernet header */
struct sniff_ethernet {
	u_char          ether_dhost[ETHER_ADDR_LEN];	/* Destination host address */
	u_char          ether_shost[ETHER_ADDR_LEN];	/* Source host address */
	u_short         ether_type;	/* IP? ARP? RARP? etc */
};

	/* IP header */
struct sniff_ip {
	u_char          ip_vhl;	/* version << 4 | header length >> 2 */
	u_char          ip_tos;	/* type of service */
	u_short         ip_len;	/* total length */
	u_short         ip_id;	/* identification */
	u_short         ip_off;	/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char          ip_ttl;	/* time to live */
	u_char          ip_p;	/* protocol */
	u_short         ip_sum;	/* checksum */
	struct in_addr  ip_src, ip_dst;	/* source and dest address */
};

/* TCP header */
struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */

	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

#define SYN_SET(tcp) (tcp->th_flags & TH_SYN)
#define ACK_SET(tcp) (tcp->th_flags & TH_ACK)

#define SEQ_MAP_START(mpm) ((unsigned int)(ntohl(*((int*)(&mpm->start)))))
#define SEQ_MAP_LEN(mpm) ((unsigned int)(ntohs(*((int*)(&mpm->len)))))
#define SEQ_MAP_END(mpm) (SEQ_MAP_START(mpm) + SEQ_MAP_LEN(mpm))
#define ACK_MAP(mpa) ((unsigned int)(ntohl(*((int*)(&mpa->ack)))))

#define TCP_ACK(tcp) ((unsigned int)(ntohl(tcp->th_ack)))
#define TCP_SEQ(tcp) ((unsigned int)(ntohl(tcp->th_seq)))

#define MAX_TCP_HEADER(tcp) (((u_char*)(tcp+1))+(TH_OFF(tcp)*4-20))
#define OPTION_TCP_HEADER(tcp) ((u_char*)(tcp+1))

#define TOGGLE(way) (way==S2C ? C2S : S2C)

#endif /* MPTCPTRACE_H_ */
