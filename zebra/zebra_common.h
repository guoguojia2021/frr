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

#define OPTION_V6_RR_SEMANTICS 2000
#define OPTION_ASIC_OFFLOAD    2001

int zebra_finalize(struct thread *dummy);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_COMMON_H */