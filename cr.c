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

int test_traffic_pkt_cnt = 0;
pcap_t *handle;

extern char *ruleset[ANNOUNCED_PROTO_NUMBERS][3];

void cr_pcap_interrupt_alarm_handler(int a)
{
	pcap_breakloop(handle);
}

void pkt_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *byte)
{
	test_traffic_pkt_cnt++;
}

int rc_chk_for_test_pkts(u_int32_t announced_proto)
{
	extern char *net_if;
	int snapshot_len = 100;
	char *filter_str = NULL;
	int promisc = 0;
	int timeout = 5000; /* does not seem to work; I use alarm() instead */
	struct bpf_program filter;
	char err_buf[PCAP_ERRBUF_SIZE];
	
	filter_str = ruleset[announced_proto][2];
	
	test_traffic_pkt_cnt = 0; /* reset packet counter for test traffic */
	
	if ((handle = pcap_open_live(net_if, snapshot_len, promisc, timeout,
	    err_buf)) == NULL) {
		perror("pcap_open_live");
		sleep(1);
		return 0;
	}
	
	if (pcap_compile(handle, &filter, filter_str, 0,
	    PCAP_NETMASK_UNKNOWN) != 0) {
		pcap_perror(handle, "pcap_compile in CR");
		sleep(1);
		return 0;
	}
	if (pcap_setfilter(handle, &filter) == -1) {
		perror("pcap_setfilter");
		sleep(1);
		return 0;
	}
	
	fprintf(stderr, "waiting for test pkts ... ");
	alarm(CR_NEL_TESTPKT_WAITING_TIME);
	signal(SIGALRM, cr_pcap_interrupt_alarm_handler);
	pcap_loop(handle, NUM_COMM_PHASE_SND_PKTS_P_PROT /* just one pkt needed to pass */, pkt_handler,
		NULL);
	/* wait until timeout */
	pcap_close(handle);
	
	if (test_traffic_pkt_cnt >= 1) {
		fprintf(stderr, "\tsuccess. Received %i test packets for this CC type!\n", test_traffic_pkt_cnt);
	} else {
		fprintf(stderr, "\ttimeout. Received 0 test packets for this CC type!\n");
	}
	
	 /* return no. of recv'd test traffic pkts */
	return test_traffic_pkt_cnt;
}

/* CR: receive announcements from sender + send back results (blocking I/O) */
void *cr_NEL_handler(void *clifd_ptr)
{
	int n;
	nel_proto_t buf;
	int *clifd = (int *) clifd_ptr;
	extern int global_measurement_start;
	
	while (1) {
		if ((n = recv(*clifd, &buf, sizeof(buf), 0)) < 0) {
			perror("recv()");
			sleep(1);
		} if (n == 0) {
			fprintf(stderr, "%%");
			sleep(1);
		} else {
			/* parse buffer */
			fprintf(stderr, "received: protocol announcement for "
				"proto=='%s' (ar-elem=%i)\n",
				ruleset[buf.announced_proto][0],
				buf.announced_proto);
			/* In case we do not measure time so far,
			 * start measuring time NOW. */
			global_measurement_start = 1;
		}
		
		/* Check whether we receive the test packet(s) and send back
		 * the result */
		n = rc_chk_for_test_pkts(buf.announced_proto);
		if (n) {
			buf.result = RESULT_RECVD;
		} else {
			buf.result = RESULT_TIMEOUT;
		}
		if (!send(*clifd, &buf, sizeof(buf), 0)) {
			perror("send()");
			sleep(1);
		}
		
		bzero(&buf, sizeof(buf));
	}

	return NULL;
}

