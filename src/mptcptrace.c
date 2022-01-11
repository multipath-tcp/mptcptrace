/*
 * mptcptrace.c
 *
 *  Created on: Jan 7, 2014
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

char *filename = NULL;
int offset_opt = -1;
int gpInterv = 0;
int Vian = 0;
int maxSeqQueueLength = 0; // back log we want to keep to check for reinjection, if 0, infinite back log.
int flight_select=0;
int rtt_select=0;
int add_addr = 0;
int rm_addr = 0;

void printHelp(){
	printf("mptcptrace help :\n");
	printf("\t -f trace : mandatory, specify the trace to analyze\n");
	printf("\t -s : generate sequence number graph\n");
	printf("\t -F : generate MPTCP window/flight size/tcp subflow flight sizes' sum and right edge/ack graph\n");
	printf("\t -G x : generate MPTCP goodput, interval is defined by x\n");
}

void write_info(){
	FILE* f = fopen("mptcptrace_info","w");
	//Version is defined in the makefile based on git last commit.
	fprintf(f,"Version : %s\n",VERSION);
	fclose(f);
}

int parseArgs(int argc, char *argv[]){
	int c;
	while ((c = getopt (argc, argv, "haG:sARSr:f:o:F:w:q:")) != -1)
		switch (c){
		case 'A':
			add_addr=1;
			break;
		case 'R':
			rm_addr=1;
			break;
		case 's':
			modules[GRAPH_SEQUENCE].activated = ACTIVE_MODULE;
			break;
		case 'S':
			modules[STAT_WFS].activated = ACTIVE_MODULE;
			break;
		case 'q':
			maxSeqQueueLength = atoi(optarg);
			break;
		case 'o':
			offset_opt = atoi(optarg);
			break;
		case 'f':
			filename = optarg;
			break;
		case 'h':
			printHelp();
			exit(0);
			break;
		case 'a':
			modules[GRAPH_ACKSIZE].activated = ACTIVE_MODULE;
		   break;
		case 'r':
			rtt_select = atoi(optarg);
			modules[RTT].activated = ACTIVE_MODULE;
		   break;
		case 'G':
			gpInterv = atoi(optarg);
			if(gpInterv <=1){
				fprintf(stderr, "Specify the number of ACK to account for the bw mving avg. Should be at least 2.(%i)\n", gpInterv);
				exit(0);
			}
			modules[GRAPH_GOODPUT].activated = ACTIVE_MODULE;
		   break;
		case 'w':
			Vian = atoi(optarg);
			if(Vian == CSV_WRITER) modules[OUTPUT_SERIES].activated = ACTIVE_MODULE;
		   break;
		case 'F':
			flight_select=atoi(optarg);
			modules[WIN_FLIGHT].activated = ACTIVE_MODULE;
		   break;
		case '?':
			if (optopt == 'r')
				fprintf (stderr, "Option -%c requires an argument.\n", optopt);
			else if (isprint (optopt))
				fprintf (stderr, "Unknown option `-%c'.\n", optopt);
			else
				fprintf (stderr,
						"Unknown option character `\\x%x'.\n",
						optopt);
			printHelp();
			exit(0);
			break;
		default:
			abort ();
		}
	return filename == NULL ? 1 : 0;
}

int openFile(int *offset, pcap_t **handle){
	char           errbuf[PCAP_ERRBUF_SIZE];
	int type;
	*handle = pcap_open_offline(filename, errbuf);
	if (*handle == NULL) {
		fprintf(stderr, "Couldn't open file %s: %s\n", filename, errbuf);
		return (2);
	}
	if(offset_opt > -1){
		fprintf(stderr,"Offset by hand: skipping %d bytes to get to the ip header\n",offset_opt);
		*offset=offset_opt;
	}
	else{
		type = pcap_datalink(*handle);
		switch(type){
		case DLT_EN10MB:
			fprintf(stderr,"ethernet ?\n");
			*offset = 14;
			break;
		case DLT_LINUX_SLL:
			fprintf(stderr,"linux cooked ?\n");
			*offset = 16;
			break;
#ifdef DLT_LINUX_SLL2
		case DLT_LINUX_SLL2:
			fprintf(stderr,"linux cooked 2 ?\n");
			*offset = 20;
			break;
#endif
		default:
			fprintf(stderr,"Unknown encapsulation type, please use option -o to precise the offset (bytes) to find the ip header...\n");
			return 2;
		}
	}
	return 0;
}
void handle_MPTCP_ADDADDR(List* l, struct sniff_ip *ip, struct sniff_tcp *tcp, struct timeval ts){
	int way;

	mptcp_sf *msf = getSubflowFromIPTCP(l,ip,tcp,&way);
	if(msf==NULL)
		return;

	char straddr[INET6_ADDRSTRLEN+1];
	u_char* addrOpt = isMPTCP_addAddr(tcp);
	int ip_version = (*(addrOpt+2)) & 0x0f;

	if (ip_version == 4){
		inet_ntop(AF_INET,addrOpt+4,straddr,INET6_ADDRSTRLEN+1);
		fprintf(msf->mc_parent->addAddr,"%i,%s\n",way, straddr);
	}
	else{
		inet_ntop(AF_INET6,addrOpt+4,straddr,INET6_ADDRSTRLEN+1);
		fprintf(msf->mc_parent->addAddr,"%i,%s\n",way, straddr);
	}
}

void handle_MPTCP_RMADDR(List* l, struct sniff_ip *ip, struct sniff_tcp *tcp, struct timeval ts){
	int way,n,i,id;

	mptcp_sf *msf = getSubflowFromIPTCP(l,ip,tcp,&way);
	if(msf==NULL)
		return;

	u_char* addrOpt = isMPTCP_rmAddr(tcp);
	n=((uint8_t)*(addrOpt + 1) - 3);
	for(i=0;i<n;i++){
		id=(uint8_t)*(addrOpt + 3 + i);
		fprintf(msf->mc_parent->rmAddr,"%i,%i\n",way, id);
	}
}

void handle_MPTCP_DSS(List* l, struct sniff_ip *ip, struct sniff_tcp *tcp, struct timeval ts){
	mptcp_map *mpmap;
	mptcp_ack *mpack;
	u_char* mpdss = first_MPTCP_sub(tcp,MPTCP_SUB_DSS);
	int way;
	mptcp_sf *msf = getSubflowFromIPTCP(l,ip,tcp,&way);
	int ackoff = *(mpdss+3) & 0x01 ? 4 : 0;
	if(msf==NULL){
		//fprintf(stderr,"Error DSS found but connection not found....\n");
		return;
	}
	int i;
	//TODO gérer la partie TCP avant les call, retirer le raw TCP des fo modules ?
	for(i=0;i<TCP_MAX_GRAPH;i++) if(modules[i].activated)  tcpModules[i].handleTCP(ip,tcp, msf, msf->mc_parent->graphdata[i], msf->mc_parent->mci, way);
	for(i=0;i<MAX_GRAPH;i++){
		if(*(mpdss+3) & 0x04){
			mpmap = new_mpm();
			mpmap->ref_count++;
			memcpy(&mpmap->start,mpdss+4+ackoff,SEQ_SIZE);
			memcpy(&mpmap->len,mpdss+4+ackoff+8,LEN_SIZE);
			mpmap->ts=ts;
			mpmap->msf = msf;
			mpmap->injectCount=1;
			mpmap->injectOnSF = 0;
			mpmap->injectOnSF |= 1 << msf->id;
			if(modules[i].activated) modules[i].handleMPTCPSeq(tcp, msf, mpmap, msf->mc_parent->graphdata[i], msf->mc_parent->mci, way);
			mpmap->ref_count--;
			if(mpmap->ref_count==0){
				//fprintf(stderr,"we should free this map");
				free(mpmap);
			}
		}
		if(*(mpdss+3) & 0x01){
			mpack = new_mpa();
			mpack->ref_count++;
			memcpy(&mpack->ack,mpdss+4,ACK_SIZE);
			mpack->right_edge = ACK_MAP(mpack) + (ntohs(tcp->th_win) << msf->wscale[way]);
			mpack->ts=ts;
			if(modules[i].activated)  modules[i].handleMPTCPAck(tcp, msf, mpack, msf->mc_parent->graphdata[i], msf->mc_parent->mci, way);
			mpack->ref_count--;
			if(mpack->ref_count==0){
				//fprintf(stderr,"we should free this ack");
				free(mpack);
			}
		}
	}
}
int get_ip_header_len(const u_char* packet, int offset){
	if( IP_V((struct sniff_ip *) (packet + offset)) == 4 ){
		if(isTCP((struct sniff_ip *) (packet + offset))){
			return IP_HL((struct sniff_ip *) (packet + offset)) * 4;
		}
		else{
			return -1;
		}
	}
	else{ //ipv6

		if(*(packet+offset+6)==6)
			return 40;
		else
			return -1;
	}
}
int mainLoop(){
	int offset;
	int ip_header_len; // not in the standard way...
	pcap_t *handle;
	const u_char   *packet;
	struct pcap_pkthdr header;
	struct sniff_tcp *tcp_segment;
	struct sniff_ip *ip_packet;
	List *l;
	List *lostSynCapable;
	l = newList(freecon);
	lostSynCapable = newList(NULL);
	if(openFile(&offset,&handle) != 0){
		fprintf(stderr,"Couldn't open the file %s\n",filename);
		exit(1);
	}
	packet = pcap_next(handle, &header);
	while (packet != NULL) {
		if (isIPVersionCorrect((struct sniff_ip *) (packet + offset)) /*&&
			isTCP((struct sniff_ip *) (packet + offset))*/) {
				ip_header_len = get_ip_header_len(packet,offset);
				if(ip_header_len > 0){
					ip_packet = (struct sniff_ip *) (packet + offset);
					tcp_segment=(struct sniff_tcp*) (packet + offset + ip_header_len);
					struct timeval ts;
					if(isMPTCP_capable(tcp_segment))
						updateListCapable(l,ip_packet,tcp_segment,lostSynCapable, header.ts);

					if(isMPTCP_join(tcp_segment))
						updateListJoin(l,ip_packet,tcp_segment);

					if(isMPTCP_dss(tcp_segment))
						handle_MPTCP_DSS(l,ip_packet, tcp_segment, header.ts);

					if(isMPTCP_addAddr(tcp_segment) && add_addr)
						handle_MPTCP_ADDADDR(l,ip_packet,tcp_segment,header.ts);

					if(isMPTCP_rmAddr(tcp_segment) && rm_addr)
						handle_MPTCP_RMADDR(l,ip_packet,tcp_segment,header.ts);

				}
		}
		packet = pcap_next(handle, &header);
	}
	pcap_close(handle);
	printAllConnections(l);
	apply(l,destroyModules,NULL,NULL);
	destroyList(l);
	destroyList(lostSynCapable);
	return 0;

}


int main(int argc, char *argv[]){
	printf("MPTCP trace V0.0 alpha : says Hello.\n");
	if(parseArgs(argc,argv) != 0){
		fprintf(stderr, "Could not parse the args...\n");
		printHelp();
		exit(1);
	}
	mainLoop();
	write_info();

}
