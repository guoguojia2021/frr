/**
 * bgp_bfd.c: BGP BFD handling routines
 *
 * @copyright Copyright (C) 2015 Cumulus Networks, Inc.
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

#include "command.h"
#include "linklist.h"
#include "memory.h"
#include "lib/prefix.h"
#include "lib/thread.h"
#include "lib/buffer.h"
#include "lib/stream.h"
#include "lib/vrf.h"
#include "lib/zclient.h"
#include "lib/bfd.h"
#include "lib/table.h"
#include "lib/json.h"
#include "static_vrf.h"
#include "static_routes.h"

#include "static_bfd.h"

extern struct zclient *zclient;;
static void static_bfd_state_change_process(char *bfd_name,int state, struct static_vrf *svrf, struct route_table *stable, afi_t afi, safi_t safi)
{
	struct route_node *rn;
	struct static_nexthop *nh;
	struct interface *ifp;
	struct static_path *pn;
	struct static_route_info *si;
	for (rn = route_top(stable); rn; rn = route_next(rn)) {
		si = static_route_info_from_rnode(rn);
		if (!si)
			continue;
		frr_each(static_path_list, &si->path_list, pn) {
			frr_each(static_nexthop_list, &pn->nexthop_list, nh) {
				if (nh->ifindex) {
					ifp = if_lookup_by_name(nh->ifname,
								nh->nh_vrf_id);
					if (ifp)
						nh->ifindex = ifp->ifindex;
					else
						continue;
				}
				if (nh->nh_vrf_id == VRF_UNKNOWN)
					continue;
				if  ((!nh->bfd_name[0])|| (strcmp(bfd_name, nh->bfd_name) != 0))
					continue;
				if ((int)nh->bfd_status.state == state)
						continue;
				nh->bfd_status.previous_state = nh->bfd_status.state;
				nh->bfd_status.state = state;
				if (nh->bfd_status.state == BFD_STATUS_UP) {
					static_install_path(pn);
				}else {
					static_uninstall_path(pn);
				}
			}
		}
	}
}
static int static_bfd_state_change(char *bfd_name, int state, int remote_cbit)
{
	struct route_table *stable = NULL;
	struct vrf *vrf = NULL;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		struct static_vrf *svrf;

		svrf = vrf->info;

		stable = static_vrf_static_table(AFI_IP, SAFI_UNICAST, svrf);
		if (!stable)
			continue;
		static_bfd_state_change_process(bfd_name, state, svrf, stable, AFI_IP, SAFI_UNICAST);
		stable = static_vrf_static_table(AFI_IP6, SAFI_UNICAST, svrf);
		if (!stable)
			continue;
		static_bfd_state_change_process(bfd_name, state, svrf, stable, AFI_IP6, SAFI_UNICAST);
	}
	return 0;
}
void static_bfd_init(struct thread_master *tm)
{
	bfd_protocol_integration_init(zclient, tm);
	hook_register(bfd_state_change_hook, static_bfd_state_change);
}
