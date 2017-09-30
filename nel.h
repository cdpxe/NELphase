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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h> 
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <pcap.h>
#include <signal.h>
#include <inttypes.h>
#include <math.h>
#include <time.h>

#define TOOL_VERSION		"0.2.1"
#define WELCOME_MESSAGE		"NEL: Implementation of a Network Environment Learning (NEL) Phase\n" \
				"     for Network Covert Channel Research\n\n" \
				"(C) 2017 Steffen Wendzel (wendzel (at) hs-worms (dot) de), Network Security Research Group/ZTT, Worms University of Applied Sciences, www.wendzel.de\n" \
				"Version " TOOL_VERSION "\n\n"

#define CR_NEL_TESTPKT_WAITING_TIME	7 /* Waiting time of NEL receiver for packets from Alice (in seconds) */
#define NUM_COMM_PHASE_PKTS		1000  /* number of COMM phase packets to send; should be enough to succeed also under heavily-blocked circumstances */
#define NUM_OVERALL_REQ_PKTS	400   /* number of CC packets (overall) that must go through warden before we count NEL as completed */
#define NUM_COMM_PHASE_SND_PKTS_P_PROT	4 /* how many packets to send during the communication phase per non-blocked protocol in a row */


#define MODE_UNSET		0x00
#define MODE_SENDER		0x01
#define MODE_RECEIVER	0x02

#define ANNOUNCED_PROTO_NUMBERS		50

/*#define INCREMENTAL_PROTO_SELECT*/
/*#define DEBUGMODE*/

typedef struct {
	u_int32_t			announced_proto;
#define RESULT_RECVD		0x01
#define RESULT_TIMEOUT		0x00 /* not received during time-slot */
	u_int32_t			result;
} nel_proto_t;

void *cs_COMM_sender(void *);
void *cs_NEL_handler(void *);
void *cr_NEL_handler(void *);
void *cr_measure(void *);
void usage(void);


