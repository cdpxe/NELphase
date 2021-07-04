/* Simple Implementation of a Network Environment Learning (NEL) Phase
 * with a Feedback Channel.
 *
 * Keywords: Covert Channels, Network Steganography
 *
 * Copyright (C) 2017-2021 Steffen Wendzel, steffen (at) wendzel (dot) de
 * 					https://www.wendzel.de
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

/*#define DEBUGMODE*/

#define TOOL_VERSION		"0.4.0"
#define WELCOME_MESSAGE		"NEL: Implementation of a Network Environment Learning (NEL) Phase\n" \
				"     for Network Covert Channel Research\n\n" \
				"(C) 2017-2021 Steffen Wendzel (wendzel (at) hs-worms (dot) de), " \
				"Network Security Research Group (NSRG), " \
				"Worms University of Applied Sciences, " \
				"WWW: https://www.wendzel.de\n" \
				"Version " TOOL_VERSION "\n\n"

/* How many CCs are implemented (cs.c)? This value needs to match
 * the number of array "ruleset"'s elements! */
#define ANNOUNCED_PROTO_NUMBERS		50

/* CR_NEL_TESTPKT_WAITING_TIME:
 * Waiting time of NEL receiver for packets from Alice (in sec) */
#define CR_NEL_TESTPKT_WAITING_TIME	5

/* NUM_COMM_PHASE_PKTS:
 * number of COMM phase packets to send; should be enough to
 * succeed also under heavily-blocked circumstances */
#define NUM_COMM_PHASE_PKTS		100000

/* NUM_OVERALL_REQ_PKTS:
 * number of CC packets (overall) that must go through warden
 * before we count NEL as completed */
#define NUM_OVERALL_REQ_PKTS		100

/* NUM_COMM_PHASE_SND_PKTS_P_PROT:
 * how many packets to send during the *COMM* phase per
 * non-blocked protocol in a row */
#define NUM_COMM_PHASE_SND_PKTS_P_PROT	5

/* NUM_NEL_TESTPKT_SND_PKTS_P_PROT:
 * how many packets to be sent per CC type during *NEL* phase */
#define NUM_NEL_TESTPKT_SND_PKTS_P_PROT 5

#define WARDEN_MODE_NO_WARDEN           0x10
#define WARDEN_MODE_REG_WARDEN          0x20 /* regular warden */
#define WARDEN_MODE_DYN_WARDEN          0x40 /* dynamic warden (Mazurczyk et al.) */
#define WARDEN_MODE_ADP_WARDEN          0x80 /* *SIMPLIFIED* Adaptive Warden(!) */
#define WARDEN_MODE                     WARDEN_MODE_NO_WARDEN

/* WARDEN_MODE_REG/DYN/ADP_WARDEN -> SIM_LIMIT_FOR_BLOCKED_SENDING -- NEW in v.0.2.6:
 * Simulate a WARDEN already in this tool w/o relying on extra software.
 * Values:
 * 0=sender will send 0% (block 100%) of the probe packets;
 * 2=sender will send 4% (block 96%) of the probe packets;
 * 25=sender will send/block 50% of the probe packets;
 * 50=sender will send 100% of the probe protocols (DEFAULT) */
#define SIM_LIMIT_FOR_BLOCKED_SENDING 25
/* WARDEN_MODE_DYN/ADP -> RELOAD_INTERVAL [seconds]:
 * After how many seconds should we shuffle the active rules again?
 * Note: This is not exact. It is always RELOAD_INTERVAL+small overhead.
 */
#define RELOAD_INTERVAL		 10
/* WARDEN_MODE_ADP -> SIM_INACTIVE_CHECKED_MOVE_TO_ACTIVE:
 * How many of the recently triggered inactive rules are activated
 * during the next run?
 * 0=No rules will be moved (essentially this means: deactivation of feature!)
 * 2=the 2 latest triggered rules would be moved
 * 50=All rules will be moved (i.e. warden only based on observations of triggers!)
 */
#define SIM_INACTIVE_CHECKED_MOVE_TO_ACTIVE  5


/* remaining basic definitions */
#define MODE_UNSET		0x00
#define MODE_SENDER		0x01
#define MODE_RECEIVER           0x02

/* INCREMENTAL_PROTO_SELECT:
 * This macro (if uncommented) ensures that protocols are selected in an incremental
 * manner instead of randomly */
/*#define INCREMENTAL_PROTO_SELECT*/

#define min(a, b)		(a < b ? a : b)

typedef struct {
	u_int32_t		announced_proto;
#define RESULT_RECVD		0x01 /* received during time-slot */
#define RESULT_TIMEOUT		0x00 /* not received during time-slot */
	u_int32_t		result;
} nel_proto_t;

void *cs_COMM_sender(void *);
void *cs_NEL_handler(void *);
void *cs_RuleReloader(void *);
void *cr_NEL_handler(void *);
void *cr_measure(void *);
void usage(void);
void pretend_sending(u_int32_t);

