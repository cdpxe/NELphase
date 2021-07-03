/* Simple Implementation of a Network Environment Learning (NEL) Phase
 * with a Feedback Channel.
 *
 * Keywords: Covert Channels, Network Steganography
 *
 * Copyright (C) 2017 Steffen Wendzel, steffen (at) wendzel (dot) de
 *					http://www.wendzel.de
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

/* iface to sniff on at CR (warden-link) in order to see whether CC test pkts
 * arrive */
char *net_if = NULL;

/* warden_link_ip: used to send scapy packets by CS (in other words:
 * this is the warden-link IP of CR) */
char *warden_link_ip = NULL;

int main(int argc, char *argv[])
{
	int mode = MODE_UNSET;
	struct sockaddr_in srv, cli;
	int sockfd, clifd;
	pthread_t th1, th2;
	pthread_t th_comm_ph; /* only SENDER for COMM. phase */
	pthread_t th_rule_reload; /* only SENDER for DYN+ADP warden */
	extern char *ruleset[ANNOUNCED_PROTO_NUMBERS][3];
	
	printf(WELCOME_MESSAGE);
	
	/* configuration check: is ANNOUNCED_PROTO_NUMBERS up-to-date with the
	 * ruleset? */
	if (ruleset[ANNOUNCED_PROTO_NUMBERS][0] != NULL
	 || ruleset[ANNOUNCED_PROTO_NUMBERS][1] != NULL
	 || ruleset[ANNOUNCED_PROTO_NUMBERS][2] != NULL) {
		fprintf(stderr, "ruleset not updated. Please adjust the macro "
		"`ANNOUNCED_PROTO_NUMBERS' in nel.h to the number of rules in "
		" `ruleset'.\n");
		exit(1);
	}
		
	if (argc < 4)
		usage();

/* checking the mode */
	if (strstr(argv[1], "sender") != NULL) {
		printf("sender mode.\n");
		mode = MODE_SENDER;
	} else if (strstr(argv[1], "receiver")  != NULL) {
		printf("receiver mode.\n");
		mode = MODE_RECEIVER;
	} else {
		usage();
		/* NOTREACHED */
	}
	
	/* argv[2] is used by the particular MODES below */

/* setting up the connection */
	switch (mode) {
/* SENDER */
	case MODE_SENDER:
		sockfd = socket(AF_INET, SOCK_STREAM, 0);
		if (sockfd < 0) {
			perror("socket");
			exit(1);
		}
	
		bzero(&srv, sizeof(srv));
		/* checking peer address */
		if (!inet_aton(argv[2], &srv.sin_addr)) {
			perror("inet_aton");
			usage();
			/* NOTREACHED */
		}
		srv.sin_family = AF_INET;
		srv.sin_port = htons(12345);
		if (connect(sockfd, (struct sockaddr *) &srv,
			sizeof(srv)) < 0) {
			perror("connect");
			exit(1);
		}
		
		/* 3rd parameter is the DST IP that will be used for scapy */
		warden_link_ip = argv[3];
		
		/* NEL thread */
		if (pthread_create(&th1, NULL, cs_NEL_handler, &sockfd)) {
			perror("pthread_create(NEL.phase.CS)");
			exit(1);
		}
		/* COMM phase thread */
		if (pthread_create(&th_comm_ph, NULL, cs_COMM_sender, NULL)) {
			perror("pthread_create(comm.phase.CS)");
			exit(1);
		}
		/* rule reloader */
		if (WARDEN_MODE == WARDEN_MODE_DYN_WARDEN || WARDEN_MODE == WARDEN_MODE_ADP_WARDEN) {
			if (pthread_create(&th_rule_reload, NULL, cs_RuleReloader, NULL)) {
				perror("pthread_create(rule_reloader.CS)");
				exit(1);
			}
		}
		/* clean-up */
		if(pthread_join(th1, NULL)) {
			perror("pthread joining error");
		}
		close(sockfd);
		break;
/* RECEIVER */
	case MODE_RECEIVER:
		/* set the network interface to sniff on w/ pcap */
		net_if = argv[3];
	
		sockfd = socket(AF_INET, SOCK_STREAM, 0);
		if (sockfd < 0) {
			perror("socket");
			exit(1);
		}
		
		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
			&(int){1}, sizeof(int)) < 0) {
			perror("setsockopt");
			exit(1);
		}
	
		bzero(&srv, sizeof(srv));
		srv.sin_family = AF_INET;
		srv.sin_addr.s_addr = htonl(INADDR_ANY);
		srv.sin_port = htons(12345);
		
		if (bind(sockfd, (struct sockaddr *)&srv,
			sizeof(srv)) < 0) {
   			perror("bind");
   			exit(1);
		}
		if (listen(sockfd, 5 ) == -1 ) {
			perror("listen");
			exit(1);
		}
		
		/* run measurement thread in parallel */
		if (pthread_create(&th2, NULL, cr_measure, NULL)) {
			perror("pthread_create(CR.measure)");
			exit(1);
		}
		
		/* now accept a connection and run the actual NEL phase */
		while (1) {
			socklen_t len;
			
			len = sizeof(cli);
			clifd = accept(sockfd, (struct sockaddr *)&cli, &len);
			if (clifd < 0) {
				perror("accept()");
				exit(1);
			}
			
			if (pthread_create(&th1, NULL, cr_NEL_handler, &clifd)) {
				perror("pthread_create(NEL.phase.CR)");
				exit(1);
			}

			if(pthread_join(th1, NULL)) {
				perror("pthread joining error");
			}
			close(clifd);
		}
		break;
	case MODE_UNSET:
		/* FALLTHROUGH */
	default:
		fprintf(stderr, "internal error.\n");
		exit(1);
	}

	return 0;
}
