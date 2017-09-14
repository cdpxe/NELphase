/* Simple Implementation of a Network Environment Learning (NEL) Phase
 * with a Feedback Channel.
 *
 * Keywords: Covert Channels, Network Steganography
 *
 * Copyright (C) 2017 Steffen Wendzel, steffen (at) wendzel (dot) de
 *                    http://www.wendzel.de
 *
 * Please have a look at our academic publications on the NEL phase
 * (see ./documentation/).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Cf. `LICENSE' file.
 *
 */

#include "nel.h"
#include "cs.h"

/* This is a core component of NEL: each array element contains a rule name,
 * a scapy command and finally a PCAP filter for each covert channel technique
 * to be tested.
 * Rules developed in joint-work with all authors of the paper. */
char *ruleset[ANNOUNCED_PROTO_NUMBERS+1][3] = {
	/* update ANNOUNCED_PROTO_NUMBERS after adding new proto here! */
	{ "IPv4 w/ reserved flag set",
		"a=IP(flags=0x4)",
		"ip[6] = 0x80" },
	{ "IPv4 w/ identifier embedded CC",
		"a=IP(id=0x270f)",
		"ip[4:2] == 0x270f" },
	{ "IPv4 w/ Type of Service field",
		"a=IP(tos=0x03)",
		"ip[1] == 3" }, /* fixed */
	{ "IPv4 w/ data embed.@frag.offset +DF set",
		"a=IP(flags=2, frag=0x12)",
		"(ip[6:2] & 0x1fff)==0x12" },
	{ "IPv4 w/ CC using TTL",
		"a=IP(ttl=255)/TCP(sport=9999)",
		"ip[8]=255 and src port 9999" }, /* fixed */
	{ "IPv4 w/ embedded CC in SRC IP",
		"a=IP(src=\"201.201.201.201\")/TCP(flags=\"S\")",
		"src 201.201.201.201 and tcp[13]==0x02" },

	{ "ICMP echo-embedded CC data",
		"a=IP()/ICMP()/\"Covert.Channel\"",
		"icmp[icmptype] = icmp-echo and icmp[icmpcode] = 0 and icmp[8]=0x43" },
	{ "ICMP t.= 3 w/ embed. data in unused fld",
		"a=IP()/ICMP(type=3, unused=0x1F3)",
		"icmp[icmptype]=3 and icmp[4:4]==0x1F3" }, /* was rule 14 */
	{ "ICMP t.=17 w/ data in Identifier field",
		"a=IP()/ICMP(type=17, id=0x1)",
		"icmp[0]==0x11 and icmp[4:2]==0x0001" },
	{ "ICMP t.=17 w/ data in sequence number",
		"a=IP()/ICMP(type=17, seq=0x1)",
		"icmp[0]==0x11 and icmp[6:2]==0x0001" },
	{ "ICMP t.=4 w/ data in unused field",
		"a=IP()/ICMP(type=4, unused=0x1111)",
		"icmp[4:4]==0x1111" },
	{ "ICMP t.=10 w/ data in unused field",
		"a=IP()/ICMP(type=10, unused=0x1010)",
		"icmp[icmptype]=10 and icmp[4:4]==0x1010" },
	{ "ICMP t.=11 w/ data in unused field",
		"a=IP()/ICMP(type=11, unused=0x0111)",
		"icmp[icmptype]=11 and icmp[4:4]==0x0111" },
	{ "ICMP t.=12 w/ data in unused field",
		"a=IP()/ICMP(type=12, reserved=0x1234)",
		"icmp[icmptype]=12 and icmp[6:2]==0x1234" }, /* fixed */
	
	{ "TCP w/ URG flg set & urg. field!=zero",
		"a=IP()/TCP(flags=\"U\", urgptr=6363)",
		"tcp[18:2]==6363" },
	{ "TCP embedded data in seq number",
		"a=IP()/TCP(seq=0x12345678)",
		"tcp[4:4]== 0x12345678" },
	{ "TCP w/ IP flags DF",
		"a=IP(flags=0x02)/TCP(sport=1234)",
		"ip[6] == 64 and src port 1234" },
	{ "TCP w/ embedded data in dst port=81",
		"a=IP()/TCP(dport=81, window=512)",
		"dst port 81 and tcp[14:2]=512" }, /* fixed */
	{ "TCP w/ embedded data in checksum",
		"a=IP()/TCP(chksum=0x001)",
		"tcp[16:2]==0x001" },
	{ "TCP w/ data in ack seq field",
		"a=IP()/TCP(ack=0xa0f0aaaf)",
		"tcp[8:4]==0xa0f0aaaf" },
	
	{ "UDP w/ embedded data in checksum",
		"a=IP(chksum=0x001)",
		"ip[10:2]==0x001" },
	{ "UDP w/ embedded data in source port",
		"a=IP()/UDP(sport=9001)",
		"udp[0:2]==0x2329" },
		
	/* new hiding techniques and filter rules added on Sep-12-2017 as proposed
	 * by Mehdi Chourib (Mn1-29). */
	{ "Mn1",
		"a=IP()/UDP(sport=68, dport=67)/BOOTP(xid=123456)/DHCP(options=[(\"message-type\",\"inform\")])",
		"udp[12:4] == 0x0001e240" },
	{ "Mn2",
		"a=IP(ttl=130)/ICMP()/UDPerror(chksum=1234)",
		"icmp[14:2] == 0x4d2 and ip[8]==130" },
	{ "Mn3",
		"a=IP(ttl=160)/ICMP()/UDPerror(sport=11111)",
		"icmp[8:2] == 0x2B67 and ip[8]==160" },
	{ "Mn4",
		"a=IP(ttl=190)/ICMP()/UDPerror(dport=22222)",
		"icmp[10:2] == 0x56CE and ip[8]==190" },
	{ "Mn5",
		"a=IP(ttl=200)/ICMP()/UDP(len=3232)",
		"icmp[12:2] == 0x0ca0 and ip[8]==200" },
	{ "Mn6",
		"a=IP(ttl=220)/ICMP()/TCPerror(dport=6666)",
		"icmp[10:2] == 0x1a0a and ip[8]==220" },
	{ "Mn7",
		"a=IP(ttl=230)/ICMP()/TCPerror(seq=777)",
		"icmp[12:4] == 0x00000309 and ip[8]==230" },
	{ "Mn8",
		"a=IP(ttl=240)/ICMP()/TCPerror(ack=8888)",
		"icmp[16:4] == 0x000022b8 and ip[8]==240" },
	{ "Mn9",
		"a=IP(ttl=250)/ICMP()/TCPerror(dataofs=9999)",
		"icmp[20] & 0xf0 == 0xf0 and ip[8]==250" },
	{ "Mn10",
		"a=IP(ttl=140)/ICMP()/TCPerror(reserved=111)",
		"icmp[21] & 0x40 >= 0 and ip[8]==140" },
	{ "Mn11",
		"a=IP(ttl=150)/ICMP()/TCPerror(flags=0x02)",
		"icmp[21] == 0x02 and ip[8]==150" },
	{ "Mn12",
		"a=IP(ttl=170)/ICMP()/TCPerror(window=222)",
		"icmp[22:2] ==0xde and ip[8]==170" },
	{ "Mn13",
		"a=IP(ttl=180)/ICMP()/TCPerror(chksum=101)",
		"icmp[24:2] == 0x65 and ip[8]==180" },
	{ "Mn14",
		"a=IP(ttl=120)/ICMP()/TCPerror(urgptr=1)",
		"icmp[26:2] ==0x1 and ip[8]==120" },
	{ "Mn15",
		"a=IP(ttl=110)/ICMP()/ICMPerror(type=3, reserved=123)",
		"icmp[10:2]== 0xfcff and ip[8]==110" },
	{ "Mn16", // should work now
		"a=IP(ttl=105)/ICMP()/ICMPerror(type=11, reserved=191)",
		"icmp[10:2]== 0xf4ff and ip[8]==105" },
	{ "Mn17",
		"a=IP(ttl=106)/ICMP()/ICMPerror(type=12, unused=742)",
		"icmp[10:2]== 0xf3ff and ip[8]==106" },
	{ "Mn18",
		"a=IP(ttl=107)/ICMP()/ICMPerror(type=4, unused=4343)",
		"icmp[12:4] == 0x0010f7 and ip[8]==107" },
	{ "Mn19",
		"a=IP(tos=88)/SCTP()/SCTPChunkError(type=0)",
		"ip[32] == 0 and ip[1]==0x58" },
	{ "Mn20",
		"a=IP(tos=99)/SCTP()/SCTPChunkError(type=1)",
		"ip[32] == 0x01 and ip[1]==0x63" },
	{ "Mn21",
		"a=IP(tos=100)/SCTP()/SCTPChunkError(type=2)",
		"ip[32] == 0x02 and  ip[1]==0x64" },
	{ "Mn22",
		"a=IP(tos=101)/SCTP()/SCTPChunkError(type=7)",
		"ip[32] == 0x07 and  ip[1]==0x65" },
	{ "Mn23",
		"a=IP(tos=102)/SCTP()/SCTPChunkError(type=8)",
		"ip[32] == 0x08 and  ip[1]==0x66" },
	{ "Mn24",
		"a=IP(tos=103)/SCTP()/SCTPChunkError(type=10)",
		"ip[32] == 0xa and  ip[1]==0x67" },
	{ "Mn25",
		"a=IP(tos=104)/SCTP()/SCTPChunkError(type=11)",
		"ip[32] == 0xb and  ip[1]==0x68" },
	{ "Mn26",
		"a=IP(tos=105)/SCTP()/SCTPChunkError(type=12)",
		"ip[32] == 0xc and ip[1]==0x69" },
	{ "Mn27",
		"a=IP(tos=106)/SCTP()/SCTPChunkError(type=13)",
		"ip[32] == 0xd and ip[1]==0x6a" },
	{ "Mn28",
		"a=IP(tos=107)/SCTP()/SCTPChunkError(type=14)",
		"ip[32] == 0xe and ip[1]==0x6b" },
	{ "Mn29",
		"a=IP(tos=108)/SCTP()/SCTPChunkError(type=15)",
		"ip[32] == 0xf and ip[1]==0x6c" },		
	/* update ANNOUNCED_PROTO_NUMBERS after adding new proto here! */
	{NULL, NULL, NULL}
};



/*************************
 * SHARED: NEL+COMM PHASE
 *************************/
/* the set of currently non-blocked protocols (indicated by '1'. Set
 * to '0' by default and set back to '0' once discovered as blocked
 * again.
 */
u_int32_t P_nb[ANNOUNCED_PROTO_NUMBERS] = { 0 };

/* cs-internal debug function */
void print_Pnb(void)
{
	int i;
	
	fprintf(stderr, "P_nb={");
	for (i = 0; i < ANNOUNCED_PROTO_NUMBERS; i++) {
			fprintf(stderr, "%i=>%i, ", i, P_nb[i]);
	}
	fprintf(stderr, "eol}\n");
}

void send_CC_packet(u_int32_t announced_proto)
{
	extern char *warden_link_ip;
	char *scapy_cmd;
	int i = 0;
	char buf[2048] = {'\0'};
	
	printf("sending protocol %i...\n", announced_proto);
	scapy_cmd = ruleset[announced_proto][1];
	
	/* the dirty part ... */
	snprintf(buf, sizeof(buf) - 1,
		"echo '%s;a.dst=\"%s\";send(a)' | scapy >scapy.log 2>&1",
		scapy_cmd, warden_link_ip);
	
	/* send one packet */
#ifdef DEBUGMODE
	fprintf(stderr, "DEBUG: CMDLINE-STR:\n------\n%s\n------\n", buf);
#endif
	/* this call not secure; code should be only be used for research
	 * purposes, not in any productive environment! */
	if (system(buf) != 0) {
		fprintf(stderr, "System command returned an error while "
			"running '%s'. Please see scapy.log for details (maybe"
			" the wrong scapy-cmd was provided?).\n", buf);
	}
}


/*************************
 * NEL PHASE
 *************************/

/* Cs: send announcements to receiver + receive results (blocking I/O) */
void *cs_NEL_handler(void *sockfd_ptr)
{
	int n;
	nel_proto_t buf;
	int *sockfd = (int *) sockfd_ptr;
	int i;
#ifdef INCREMENTAL_PROTO_SELECT
	int p = 0;
#endif
	
	while (1) {
		bzero(&buf, sizeof(buf));
#ifdef INCREMENTAL_PROTO_SELECT
		buf.announced_proto = p++ % ANNOUNCED_PROTO_NUMBERS;
#else
		/* randomly chose the protocol to try next */
		srand(time(NULL));
		buf.announced_proto = rand() % ANNOUNCED_PROTO_NUMBERS;
#endif
		if ((n = send(*sockfd, &buf, sizeof(buf), 0)) < 0) {
			perror("send()");
			sleep(1);
		}
		
		sleep(1); /* wait one second before sending data (CR waits much
			   * longer, so we will have no problem here). */
		
		/* send three packets of test traffic each time */
		for (i = 0; i < 3; i++)
			send_CC_packet(buf.announced_proto);
		
		if ((n = recv(*sockfd, &buf, sizeof(buf), 0)) < 0) {
			perror("recv()");
			sleep(1);
		} if (n == 0) {
			fprintf(stderr, "%%");
			sleep(1);
		} else {
			/* update P_nb */
			P_nb[buf.announced_proto] = buf.result;
			fprintf(stderr, "\trecv'd feedback for proto=%u, "
					"result=%u, ", buf.announced_proto,
					buf.result);
			/* show P_nb for debugging and rule checking */
			print_Pnb();
		}
	}

	return NULL;
}




/*************************
 * COMMUNICATION PHASE
 *************************/
 
void *cs_COMM_sender(void *unused)
{
	int i;
	int pkts_sent = 0;
	int sent_during_current_loop;
	nel_proto_t proto;
	
	/* iterate through P_bn to send NUM_COMM_PHASE_PKTS packets,
	 * only use available protocols marked as non-blocked in P_nb
	 */
	while (pkts_sent < NUM_COMM_PHASE_PKTS) {
		sent_during_current_loop = 0;
		for (i = 0; i < ANNOUNCED_PROTO_NUMBERS; i++) {
			proto.announced_proto = i;			
			if (P_nb[i] == 1) {
				//printf("non-blocked protocol %i found\n", i);
				int pkt_cnt = 0;
				for (pkt_cnt = 0;
				     pkt_cnt < NUM_COMM_PHASE_SND_PKTS_P_PROT;
				     pkt_cnt++) {
				     	/* use this non-blocked protocol! */
					send_CC_packet(proto.announced_proto);
				}
				pkts_sent += NUM_COMM_PHASE_SND_PKTS_P_PROT;
				sent_during_current_loop = 1;
			} else {
				//printf("skipping blocked protocol\n");
			}
		}
		/* if we found no non-blocked protocol, NEL is either
		 * not initially completed or needs to re-run, so we
		 * need to wait a little */
		if (sent_during_current_loop == 0)
			sleep(1);
	}

	fprintf(stderr, "\n===== COMMUNICATION PHASE COMPLETED =====\n");
	fprintf(stderr, "exiting.\n");
	exit(0);
	/* NOTREACHED */
	return NULL;
}


