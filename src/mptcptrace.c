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
#include <netinet/tcp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <sys/time.h>
#include <errno.h>
#include <dirent.h>

#include "string.h"
#include "list.h"
#include "mptcptrace.h"
#include "TCPOptions.h"
#include "allocations.h"
#include "MPTCPList.h"
#include "graph.h"
#include "traceInfo.h"


DIR  *dir;
char *trace_dir 		= NULL;
char *filename			= NULL;

int offset_opt			= -1;
int gpInterv			= 0;
int Vian				= 0;
int maxSeqQueueLength	= 0; // back log we want to keep to check for reinjection, if 0, infinite back log.
int flight_select		= 0;
int rtt_select			= 0;
int add_addr			= 0;
int rm_addr				= 0;
int paramLevel			= 0;
int timeout				= -1;

void printHelp(){
	printf("mptcptrace help :\n");
	printf("\t -f trace : mandatory, specify the trace to analyze\n");
	printf("\t -s : generate sequence number graph\n");
	printf("\t -F : generate MPTCP window/flight size/tcp subflow flight sizes' sum and right edge/ack graph\n");
	printf("\t -G x : generate MPTCP goodput, interval is defined by x\n");
	printLogHelp();
}

void write_info(){
	FILE* f = fopen("mptcptrace_info","w");
	//Version is defined in the makefile based on git last commit.
	fprintf(f,"Version : %s\n",VERSION);
	fclose(f);
}

int parseArgs(int argc, char *argv[]){
	int c;
	while ((c = getopt (argc, argv, "haG:sARSr:f:d:o:F:w:q:l:t:v")) != -1)
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
		case 'l':
			paramLevel = atoi(optarg);
			break;
		case 'o':
			offset_opt = atoi(optarg);
			break;
		case 't':
			timeout = atoi(optarg);
			break;
		case 'f':
			filename = optarg;
			break;
		case 'd':
			trace_dir = optarg;
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
	return (filename == NULL)&&(trace_dir == NULL)  ? 1 : 0;
}

int openFile(const char * file, int *offset, pcap_t **handle){
	char           errbuf[PCAP_ERRBUF_SIZE];
	int type;
	*handle = pcap_open_offline(file, errbuf);
	if (*handle == NULL) {
		fprintf(stderr, "Couldn't open file %s: %s\n", file, errbuf);
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
			mplog(LOGALL, "ethernet ?\n");
			*offset = 14;
			break;
		case DLT_LINUX_SLL:
			mplog(LOGALL, "linux cooked ?\n");
			*offset = 16;
			break;
		default:
			fprintf(stderr,"Unknown encapsulation type, please use option -o to precise the offset (bytes) to find the ip header...\n");
			return 2;
		}
	}
	return 0;
}

void handle_MPTCP_ADDADDR(void* l, struct sniff_ip *ip, struct sniff_tcp *tcp, struct timeval ts){
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

void handle_MPTCP_RMADDR(void* l, struct sniff_ip *ip, struct sniff_tcp *tcp, struct timeval ts){
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

void handle_MPTCP_FASTCLOSE(void* l, struct sniff_ip *ip, struct sniff_tcp *tcp, struct timeval ts, void *ht){
	int way;
	mptcp_sf *msf = getSubflowFromIPTCP(l,ip,tcp,&way);
	//TODO this is a first a not so good approach, we should check if the other side sends reset in reply to this.
	incCounter(FAST_CLOSE_SEEN_COUNTER,way);
	if(msf){
		incCounter(FAST_CLOSE_COUNTER,way);
		mplog(LOGALL,"%s fast close \n",__func__);
		rmConn(ht,msf->mc_parent);
		closeConn(l,  NULL, msf->mc_parent);
	}
	else{
		//TODO it may be a fast close retransmission.
		mplog(LOGALL,"No ref conn to fast close\n");
	}
}

void buildLastSeq(mptcp_conn *mc, mptcp_map *seq, int way){
	mptcp_map *endSeq = new_mpm();
	memcpy(endSeq,seq,sizeof(mptcp_map));
	mc->mci->finSeq[way] = endSeq;
}

void handle_MPTCP_DSS(void* l, struct sniff_ip *ip, struct sniff_tcp *tcp, struct timeval ts, void *ht){
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
	msf->mc_parent->mci->lastActivity=ts;
	int i;
	//TODO gérer la partie TCP avant les call, retirer le raw TCP des fo modules ?
	for(i=0;i<TCP_MAX_GRAPH;i++) if(modules[i].activated)  tcpModules[i].handleTCP(ip,tcp, msf, msf->mc_parent->graphdata[i], msf->mc_parent->mci, way);
	//for(i=0;i<MAX_GRAPH;i++){
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
			for(i=0;i<MAX_GRAPH;i++) if(modules[i].activated) modules[i].handleMPTCPSeq(tcp, msf, mpmap, msf->mc_parent->graphdata[i], msf->mc_parent->mci, way);
#ifdef ENDCONN
				if(*(mpdss+3) & 0x10){
					mplog(LOGALL, "%s Should end the connection\n",__func__);
					buildLastSeq(msf->mc_parent,mpmap,way);
				}
				else{
					//fprintf(stderr,"%s not a fin the connection\n",__func__);
				}
#endif
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
			for(i=0;i<MAX_GRAPH;i++) if(modules[i].activated)  modules[i].handleMPTCPAck(tcp, msf, mpack, msf->mc_parent->graphdata[i], msf->mc_parent->mci, way);
			mpack->ref_count--;
			if(mpack->ref_count==0){
				//fprintf(stderr,"we should free this ack");
				free(mpack);
			}
			if(msf->mc_parent->mci->finSeq[way] && msf->mc_parent->mci->finSeq[TOGGLE(way)]){
				//fprintf(stderr,"%s ok both want to end %u %u\n",__func__,SEQ_MAP_END(msf->mc_parent->mci->finSeq[way]),SEQ_MAP_END(msf->mc_parent->mci->finSeq[TOGGLE(way)]));
				if(msf->mc_parent->mci->lastack[TOGGLE(way)] && msf->mc_parent->mci->lastack[way] ){
					//fprintf(stderr,"%s ok both want to end %u %u\n",__func__,ACK_MAP(msf->mc_parent->mci->lastack[TOGGLE(way)]),ACK_MAP(msf->mc_parent->mci->lastack[way]));
					if(SEQ_MAP_END(msf->mc_parent->mci->finSeq[way]) == ACK_MAP(msf->mc_parent->mci->lastack[TOGGLE(way)]) &&
							SEQ_MAP_END(msf->mc_parent->mci->finSeq[TOGGLE(way)]) == ACK_MAP(msf->mc_parent->mci->lastack[way]) ){
						mplog(LOGALL, "%s ok both seems to finished... we should close here ! \n",__func__);
						incCounter(FINISHED_COUNTER,C2S);
						rmConn(ht,msf->mc_parent);
						closeConn(l,  NULL, msf->mc_parent);
					}
				}
			}
#ifdef ENDCONN

#endif
		}
//	}
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

void removeTimedOut(struct timeval ts, void *tokenht){
#ifndef USE_HASHTABLE
	mplog(BUG,"sorry this option needs the hash table for now\n");
#else
	mptcp_conn *c, *tmp;
	mptcp_conn **ht = tokenht;
	ts.tv_sec -= timeout;
	HASH_ITER(hh, *ht, c, tmp){
		if(tv_cmp(c->mci->lastActivity,ts) < 0){
			incCounter(CONN_TIMEOUT_COUNTER,C2S);
			mplog(WARN, "Connection timedout !\n");
			rmConn(ht,c);
			closeConn(NULL,  NULL, c);
		}
	}

#endif
}

int ends_with(const char* name, const char* extension )
{
  const char* ldot = strrchr(name, '.');
  if (ldot != NULL) {
    size_t length = strlen(extension);
    return strncmp(ldot + 1, extension, length) == 0;
  }
  return 0;
}

void  processDir(void *l, void *lostSynCapable, void *tokenht){
	if ( (dir = opendir(trace_dir) ) ==NULL )
		perror ("could not open directory");
	if(chdir(trace_dir) != 0){
		fprintf(stderr, "Can not change to dir %s...\n",trace_dir);
		exit(-1);
	}
	struct dirent **namelist;
	char* file;
	// read list of files into namelist
	int n = scandir(".", &namelist, 0, alphasort);
	if (n < 0)	perror("scandir");
	/* parse each file within directory */
	int i = 0;
	while (i < n) {
		file = namelist[i]->d_name;
		if (ends_with(file,"pcap"))
			processFile(file,l,lostSynCapable,tokenht);
		free(namelist[i]);
		i++;
		}
	free(namelist);
}

int mainProcess(){
#ifndef USE_HASHTABLE
	List *l;
	List *lostSynCapable;
	l = newList(freecon,NULL);
	lostSynCapable = newList(NULL,NULL);
	List *tokenht = l;
#else
	mptcp_sf * _l = NULL;
	mptcp_sf * _lostSynCapable = NULL;
	mptcp_conn * _tokenht  = NULL;
	mptcp_sf **l = &_l;
	mptcp_sf **lostSynCapable = &_lostSynCapable ;
	mptcp_conn **tokenht  = &_tokenht;
#endif
	if (trace_dir == NULL){
		processFile(filename,l,lostSynCapable,tokenht);
	}
	else{
		processDir(l,lostSynCapable,tokenht);
	}
#ifndef USE_HASHTABLE
	printAllConnections(l);
	apply(l,destroyModules,NULL,NULL);
	destroyList(l);
	destroyList(lostSynCapable);
#else
	//USE ITER on l, dont forget the implicit free con
	mptcp_conn *c, *tmp;
	HASH_ITER(hh, *tokenht, c, tmp){
		destroyModules(c,0,NULL,NULL);
		printMPTCPConnections(c,0,stdout,NULL);
		freecon(c,NULL);
	}

#endif
	return 0;
}

int processFile(const char * file, List *l, List *lostSynCapable, List *tokenht){
	int offset;
	int ip_header_len; // not in the standard way...
	pcap_t *handle;
	const u_char   *packet;
	struct pcap_pkthdr header;
	struct sniff_tcp *tcp_segment;
	struct sniff_ip *ip_packet;
	struct timeval nextCheck;

	if(openFile(file, &offset,&handle) != 0){
		fprintf(stderr,"Couldn't open the file %s\n",file);
		exit(1);
	}
	packet = pcap_next(handle, &header);
	nextCheck=header.ts;
	nextCheck.tv_sec += timeout;
	while (packet != NULL) {
		if (isIPVersionCorrect((struct sniff_ip *) (packet + offset)) /*&&
			isTCP((struct sniff_ip *) (packet + offset))*/) {
				ip_header_len = get_ip_header_len(packet,offset);
				if(ip_header_len > 0){
					ip_packet = (struct sniff_ip *) (packet + offset);
					tcp_segment=(struct sniff_tcp*) (packet + offset + ip_header_len);
					struct timeval ts;
					if(isMPTCP_capable(tcp_segment))
						updateListCapable(l,ip_packet,tcp_segment,lostSynCapable, header.ts, tokenht);

					if(isMPTCP_join(tcp_segment))
						updateListJoin(l,ip_packet,tcp_segment, tokenht);

					if(isMPTCP_dss(tcp_segment))
						handle_MPTCP_DSS(l,ip_packet, tcp_segment, header.ts, tokenht);

					if(isMPTCP_addAddr(tcp_segment) && add_addr)
						handle_MPTCP_ADDADDR(l,ip_packet,tcp_segment,header.ts);

					if(isMPTCP_rmAddr(tcp_segment) && rm_addr)
						handle_MPTCP_RMADDR(l,ip_packet,tcp_segment,header.ts);

					if(isMPTCP_fastclose(tcp_segment, tokenht))
						handle_MPTCP_FASTCLOSE(l,ip_packet,tcp_segment,header.ts,tokenht);

				}
		}
		packet = pcap_next(handle, &header);
		if(timeout > 0 && tv_cmp(nextCheck,header.ts) < 0){
			mplog(BUG, "Ok we should do the timeout check ! \n");
			removeTimedOut(nextCheck,tokenht);
			nextCheck.tv_sec += timeout;
		}
	}
	pcap_close(handle);
	return 0;

}


int main(int argc, char *argv[]){
	fprintf(stderr,"MPTCP trace V0.0 alpha : says Hello.\n");
	initTraceInfo();
	if(parseArgs(argc,argv) != 0){
		fprintf(stderr, "Could not parse the args...\n");
		printHelp();
		exit(1);
	}
	mainProcess();
	write_info();
	destroyTraceInfo();

}
