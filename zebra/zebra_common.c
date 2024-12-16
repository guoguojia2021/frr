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

#include <zebra.h>
#include "libfrr.h"
#include "log.h"

#include "zebra/zebra_router.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_dplane.h"

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

/*
 * Final shutdown step for the zebra main thread. This is run after all
 * async update processing has completed.
 */
int zebra_finalize(struct thread *dummy)
{
	zlog_info("Zebra final shutdown");

	/* Final shutdown of ns resources */
	ns_walk_func(zebra_ns_final_shutdown, NULL, NULL);

	/* Stop dplane thread and finish any cleanup */
	zebra_dplane_shutdown();

	zebra_router_terminate();

	frr_fini();
	exit(0);
}
