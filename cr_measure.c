/* Simple Implementation of a Network Environment Learning (NEL) Phase
 * with a Feedback Channel.
 *
 * Keywords: Covert Channels, Network Steganography
 *
 * Copyright (C) 2017-2021 Steffen Wendzel, steffen (at) wendzel (dot) de
 *                    https://www.wendzel.de
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
#ifdef __MACH__
 #include <mach/clock.h>
 #include <mach/mach.h>
#endif

int global_measurement_start = 0;
/* amount of CC packets receiver through warden */
int recv_through_warden_pkt_cnt = 0;

extern char *ruleset[ANNOUNCED_PROTO_NUMBERS][3];

extern u_int32_t goalcfg;

/* / from CCEAP: client.c \ */
void print_time_diff(void)
{
	long ms;
	time_t s;
	struct timespec spec_now;
	static struct timespec spec_last;
	static int first_call = 1;
#ifdef __MACH__ /* code from Stackoverflow.com (Mac OS lacks clock_gettime()) */
	#warning "Including experimental code for MacOS. CCEAP runs best on Linux!"
	clock_serv_t cclock;
	mach_timespec_t mts;

	host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
	clock_get_time(cclock, &mts);
	mach_port_deallocate(mach_task_self(), cclock);
	spec_now.tv_sec = mts.tv_sec;
	spec_now.tv_nsec = mts.tv_nsec;
#else
	clock_gettime(CLOCK_REALTIME, &spec_now);
#endif
	
	if (first_call) {
		printf("0.000\n");
		first_call = 0;
	} else {
		s  = spec_now.tv_sec - spec_last.tv_sec;
		ms = (spec_now.tv_nsec - spec_last.tv_nsec) / 1.0e6;	
		if (ms < 0) {
			ms = 1000 + ms;
			s -= 1;
		}
		printf("%"PRIdMAX".%03ld seconds\n", (intmax_t)s, ms);
	}
	bcopy(&spec_now, &spec_last, sizeof(struct timespec));
}
/* \ end: from CCEAP: client.c / */

void pkt_handler_COM(u_char *user, const struct pcap_pkthdr *h,
			 const u_char *bytes)
{
	recv_through_warden_pkt_cnt++;
	fprintf(stderr, "received: %d packets\n", recv_through_warden_pkt_cnt); fflush(stderr);

	if (recv_through_warden_pkt_cnt >= NUM_OVERALL_REQ_PKTS) {
		u_int32_t warden;
		u_int32_t blocked;
		u_int32_t reload_interval;
		u_int32_t inactive_checked2active;
		
		fprintf(stderr, "MEASUREMENT COMPLETED; received %i CC "
			"packets through warden link (through combined "
			"pcap filter, i.e. excluding non-CC traffic).\n",
			NUM_OVERALL_REQ_PKTS);
		print_time_diff();
		
		warden = (goalcfg & 0xff000000) >> 24;
		blocked = (goalcfg & 0x00ff0000) >> 16;
		reload_interval = (goalcfg & 0x0000ff00) >> 8;
		inactive_checked2active = (goalcfg & 0x000000ff);
		
		fprintf(stderr,
			"CS's configuration: warden=0x%X (%s), non-blocked=%i/%i (%f%%), "
			"reload_interval=%i, inactive_checked2active=%i\n",
			warden,
			(warden == WARDEN_MODE_NO_WARDEN ? "NO warden" :
				(warden == WARDEN_MODE_REG_WARDEN ? "REGULAR warden" :
					(warden == WARDEN_MODE_DYN_WARDEN ? "DYNAMIC warden" :
						(warden == WARDEN_MODE_ADP_WARDEN ? "simplif. ADAPTIVE warden" :
							"UNKNOWN(!!!) warden")))),
			blocked, ANNOUNCED_PROTO_NUMBERS, (float)blocked/(float)ANNOUNCED_PROTO_NUMBERS,
			reload_interval, inactive_checked2active);
		fflush(stderr);fflush(stdout);
		exit(0);
	}
}

void *cr_measure(void *unused)
{
	extern char *net_if;
	int snapshot_len = 100;
	char *filter_str = NULL;
	int promisc = 0;
	int timeout = 0;
	struct bpf_program filter;
	char err_buf[PCAP_ERRBUF_SIZE];
	int i;
	int filter_rule = 0;
	pcap_t *handle_measure;
	
	if ((handle_measure = pcap_open_live(net_if, snapshot_len, promisc,
					     timeout, err_buf)) == NULL) {
		perror("pcap_open_live in cr_measure");
		exit(1);
	}
	
	fprintf(stderr, "setting up pcap combined filter CC traffic ...\n");
	for (i = 0; i < ANNOUNCED_PROTO_NUMBERS; i++) {
		filter_str = realloc(filter_str,
				(filter_str == NULL
					? 0
					: strlen(filter_str)) + 1 + 6 /* for: ' or ()' */
					  + strlen(ruleset[i][2]));
		if (!filter_str) {
			fprintf(stderr, "ERR: memory alloc (realloc())\n");
			exit(1);
		}
		if (filter_rule == 0) {
			snprintf(filter_str, 3 + strlen(ruleset[i][2]), "(%s)",
				 ruleset[i][2]);
			filter_rule ++;
		} else {
			snprintf((char *)(filter_str+strlen(filter_str)),
				 7 + strlen(ruleset[i][2]),
				 " or (%s)",
				 ruleset[i][2]);
		}
	}
	fprintf(stderr, "Combined filter will be set to: ```%s'''\n",
		filter_str);
	if (pcap_compile(handle_measure, &filter, filter_str, 0,
			PCAP_NETMASK_UNKNOWN) != 0) {
		fprintf(stderr, "pcap_compile() error in cr_measure()");
		pcap_perror(handle_measure, "pcap_compile in cr_measure");
		exit(1);
	}
	if (pcap_setfilter(handle_measure, &filter) == -1) {
		fprintf(stderr, "pcap_setfilter() error in cr_measure()");
		perror("pcap_setfilter in cr_measure");
		exit(1);
	}
	
	fprintf(stderr, "waiting for CC pkts in cr_measure ... ");
	fflush(stderr);
	
	/* wait for measurement to start (triggered by first announcement
	 * from CS!) */
	while (!global_measurement_start) {
		sleep(1);
	}
	printf("Starting timer: ");
	print_time_diff();
	
	pcap_loop(handle_measure, 0 /*inf pkts*/, pkt_handler_COM, NULL);
	
	pcap_close(handle_measure);
	return NULL;
}


