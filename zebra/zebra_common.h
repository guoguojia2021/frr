/* zebra daemon main routine.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _ZEBRA_COMMON_H
#define _ZEBRA_COMMON_H

#include <zebra.h>

#include <lib/version.h>
#include "getopt.h"
#include "command.h"
#include "thread.h"
#include "filter.h"
#include "memory.h"
#include "prefix.h"
#include "log.h"
#include "plist.h"
#include "privs.h"
#include "sigevent.h"
#include "vrf.h"
#include "libfrr.h"
#include "routemap.h"
#include "routing_nb.h"

#include "zebra/zebra_router.h"
#include "zebra/zebra_errors.h"
#include "zebra/rib.h"
#include "zebra/zserv.h"
#include "zebra/debug.h"
#include "zebra/router-id.h"
#include "zebra/irdp.h"
#include "zebra/rtadv.h"
#include "zebra/zebra_ptm.h"
#include "zebra/zebra_ns.h"
#include "zebra/redistribute.h"
#include "zebra/zebra_mpls.h"
#include "zebra/label_manager.h"
#include "zebra/zebra_netns_notify.h"
#include "zebra/zebra_rnh.h"
#include "zebra/zebra_pbr.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/zebra_routemap.h"
#include "zebra/zebra_nb.h"
#include "zebra/zebra_opaque.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ZEBRA_PTM_SUPPORT

/* process id. */
pid_t pid;

/* Pacify zclient.o in libfrr, which expects this variable. */
struct thread_master *master;

/* Route retain mode flag. */
int retain_mode = 0;

/* BGP Route preserve mode flag. */
int preserve_bgp = 0;

/* Allow non-frr entities to delete frr routes */
int allow_delete = 0;

int graceful_restart;

int ZEBRA_TABLE_FIB_MAX = 51200;
unsigned long zebra_config_fib_max = 0;

bool v6_rr_semantics = false;

bool fpm_pic_nexthop = true;

/* Receive buffer size for kernel control sockets */
#ifdef HAVE_NETLINK
uint32_t rcvbufsize = 8388608;
#else
uint32_t rcvbufsize = 128 * 1024;
#endif

#define OPTION_V6_RR_SEMANTICS 2000
#define OPTION_ASIC_OFFLOAD    2001

/* Command line options. */
const struct option longopts[] = {
	{"batch", no_argument, NULL, 'b'},
	{"allow_delete", no_argument, NULL, 'a'},
	{"large_fib", required_argument, NULL, 'L'},
	{"socket", required_argument, NULL, 'z'},
	{"ecmp", required_argument, NULL, 'e'},
	{"retain", no_argument, NULL, 'r'},
	{"graceful_restart", required_argument, NULL, 'K'},
	{"asic-offload", optional_argument, NULL, OPTION_ASIC_OFFLOAD},
	{"preserve_bgp", no_argument, NULL, 'p'},
#ifdef HAVE_NETLINK
	{"vrfwnetns", no_argument, NULL, 'n'},
	{"nl-bufsize", required_argument, NULL, 's'},
	{"v6-rr-semantics", no_argument, NULL, OPTION_V6_RR_SEMANTICS},
#endif /* HAVE_NETLINK */
	{0}};

zebra_capabilities_t _caps_p[] = {
	ZCAP_NET_ADMIN, ZCAP_SYS_ADMIN, ZCAP_NET_RAW,
};

/* zebra privileges to run with */
struct zebra_privs_t zserv_privs = {
#if defined(FRR_USER) && defined(FRR_GROUP)
	.user = FRR_USER,
	.group = FRR_GROUP,
#endif
#ifdef VTY_GROUP
	.vty_group = VTY_GROUP,
#endif
	.caps_p = _caps_p,
	.cap_num_p = array_size(_caps_p),
	.cap_num_i = 0};


static const struct frr_yang_module_info *const zebra_yang_modules[] = {
	&frr_filter_info,
	&frr_interface_info,
	&frr_route_map_info,
	&frr_zebra_info,
	&frr_vrf_info,
	&frr_routing_info,
	&frr_zebra_route_map_info,
};

int zebra_finalize(struct thread *dummy);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_COMMON_H */