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

void usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s  \'sender\'|\'receiver\'  <specific parameters, see below>:\n", __progname);
	fprintf(stderr, "       %s  sender   CR-NEL-link-IP CR-warden-link-IP\n", __progname);
	fprintf(stderr, "       %s  receiver CS-NEL-link-IP CR-warden-link-Interface\n\n", __progname);
	fprintf(stderr,
			"Example Setup:      NEL-IP                   CS/CR-WARDEN-LINK-IP      CS/CR-LINK-IFACE\n"
			"                    ----------------         ---------------------     ------------------\n"
			"          Sender:   192.168.2.104*           172.16.2.104              eth0\n"
			"          Receiver: 192.168.2.103*           172.16.2.103*             wlp4s0*\n"
			"             *=value actually used, other values are not provided as cmd-line parameters!\n"
			"%s sender   192.168.2.103 172.16.2.103\n"
			"%s receiver 192.168.2.104 wlp4s0\n\n", __progname, __progname);
	exit(1);
	/* NOTREACHED */
}


