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

#include "nel.h"

/* Some tests go here */
#if (WARDEN_MODE == WARDEN_MODE_NO_WARDEN) && (SIM_LIMIT_FOR_BLOCKED_SENDING != 50)
	#error SIM_LIMIT_FOR_BLOCKED_SENDING must be set to 0 if in NO-warden mode!
#endif

#if (WARDEN_MODE == WARDEN_MODE_DYN_WARDEN) && (ANNOUNCED_PROTO_NUMBERS - SIM_LIMIT_FOR_BLOCKED_SENDING) < 1
	#error Please check source code for error 0x377: too many blocked rules!
#endif

#if (WARDEN_MODE == WARDEN_MODE_ADP_WARDEN) && (ANNOUNCED_PROTO_NUMBERS - SIM_LIMIT_FOR_BLOCKED_SENDING - SIM_INACTIVE_CHECKED_MOVE_TO_ACTIVE) < 1
	#error Please check source code for error 0x378: too many inactive + blocked rules in combination.
#endif

