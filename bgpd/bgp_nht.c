/* BGP Nexthop tracking
 * Copyright (C) 2013 Cumulus Networks, Inc.
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
#include "thread.h"
#include "prefix.h"
#include "zclient.h"
#include "stream.h"
#include "network.h"
#include "log.h"
#include "memory.h"
#include "nexthop.h"
#include "vrf.h"
#include "filter.h"
#include "nexthop_group.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_flowspec_util.h"
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_rd.h"
#include "bgpd/bgp_conditional_adv.h"

extern struct zclient *zclient;

static int make_prefix(int afi, struct bgp_path_info *pi, struct prefix *p);
static int bgp_nht_ifp_initial(struct thread *thread);

int bgp_isvalid_nexthop(struct bgp_nexthop_cache *bnc)
{
	return (bgp_zebra_num_connects() == 0
		|| (bnc && CHECK_FLAG(bnc->flags, BGP_NEXTHOP_VALID)
		    && bnc->nexthop_num > 0));
}

static int bgp_isvalid_labeled_nexthop(struct bgp_nexthop_cache *bnc)
{
	/*
	 * In the case of MPLS-VPN, the label is learned from LDP or other
	 * protocols, and nexthop tracking is enabled for the label.
	 * The value is recorded as BGP_NEXTHOP_LABELED_VALID.
	 * In the case of SRv6-VPN, we need to track the reachability to the
	 * SID (in other words, IPv6 address). As in MPLS, we need to record
	 * the value as BGP_NEXTHOP_SID_VALID. However, this function is
	 * currently not implemented, and this function assumes that all
	 * Transit routes for SRv6-VPN are valid.
	 */
	return (bgp_zebra_num_connects() == 0
		|| (bnc && bnc->nexthop_num > 0
		    && (CHECK_FLAG(bnc->flags, BGP_NEXTHOP_LABELED_VALID)
			|| bnc->bgp->srv6_enabled)));
}

static void bgp_unlink_nexthop_check(struct bgp_nexthop_cache *bnc)
{
	if (LIST_EMPTY(&(bnc->paths)) && LIST_EMPTY(&(bnc->backup_paths)) && !bnc->nht_info) {
		if (BGP_DEBUG(nht, NHT)) {
			char buf[PREFIX2STR_BUFFER];
			zlog_debug("%s: freeing bnc %s(%u)(%s)", __func__,
				   bnc_str(bnc, buf, PREFIX2STR_BUFFER),
				   bnc->srte_color, bnc->bgp->name_pretty);
		}
		/* only unregister if this is the last nh for this prefix*/
		if (!bnc_existing_for_prefix(bnc))
			unregister_zebra_rnh(bnc);
		bnc_free(bnc);
	}
}

const char *bgp_path_info_nht_debug(struct bgp_path_info *path, char *str, int size)
{
	char buf[PREFIX2STR_BUFFER];
	char peer_buf[SU_ADDRSTRLEN] = "null";

	if ((path == NULL) || (path->net == NULL)) {
		snprintf(str, size, "NHT path info error, path or path->net is null.");
		return str;
	}

	if (path->peer && path->peer->su_remote) {
		sockunion2str(path->peer->su_remote, peer_buf, sizeof(peer_buf));
	}

	snprintf(str, size, "NHT path info %s (id: %d) from %s.", 
			 prefix2str(bgp_dest_get_prefix(path->net), buf, sizeof(buf)), path->addpath_rx_id, peer_buf);

	return str;
}

void bgp_unlink_nexthop(struct bgp_path_info *path)
{
	struct bgp_nexthop_cache *bnc = path->nexthop;

	if (!bnc)
		return;

	path_nh_map(path, NULL, false);

	bgp_unlink_nexthop_check(bnc);
}

void bgp_unlink_te_nexthop(struct bgp_path_info *path)
{
	struct bgp_nexthop_cache *bnc = path->te_nexthop;

	if (!bnc)
		return;

	path_tenh_map(path, NULL, false);

	bgp_unlink_nexthop_check(bnc);
}

void bgp_unlink_tebk_nexthop(struct bgp_path_info *path)
{
	struct bgp_nexthop_cache *bnc = path->te_backup_nexthop;

	if (!bnc)
		return;

	path_tebk_nh_map(path, NULL, false);

	bgp_unlink_nexthop_check(bnc);
}

void bgp_replace_nexthop_by_peer(struct peer *from, struct peer *to)
{
	struct prefix pp;
	struct prefix pt;
	struct bgp_nexthop_cache *bncp, *bnct;
	afi_t afi;

	if (!sockunion2hostprefix(&from->connection->su, &pp))
		return;

	afi = family2afi(pp.family);
	bncp = bnc_find(&from->bgp->nexthop_cache_table[afi], &pp, 0, 0);

	if (!sockunion2hostprefix(&to->connection->su, &pt))
		return;

	bnct = bnc_find(&to->bgp->nexthop_cache_table[afi], &pt, 0, 0);

	if (bnct != bncp)
		return;

	if (bnct)
		bnct->nht_info = to;
}

void bgp_unlink_nexthop_by_peer(struct peer *peer)
{
	struct prefix p;
	struct bgp_nexthop_cache *bnc;
	afi_t afi = family2afi(peer->connection->su.sa.sa_family);

	if (!sockunion2hostprefix(&peer->connection->su, &p))
		return;

	bnc = bnc_find(&peer->bgp->nexthop_cache_table[afi], &p, 0, 0);
	if (!bnc)
		return;

	/* cleanup the peer reference */
	bnc->nht_info = NULL;

	bgp_unlink_nexthop_check(bnc);
}

/*
 * A route and its nexthop might belong to different VRFs. Therefore,
 * we need both the bgp_route and bgp_nexthop pointers.
 */
int bgp_find_or_add_nexthop(struct bgp *bgp_route, struct bgp *bgp_nexthop,
			    afi_t afi, safi_t safi, struct bgp_path_info *pi,
			    struct peer *peer, int connected,
			    const struct prefix *orig_prefix)
{
	struct bgp_nexthop_cache_head *tree = NULL;
	struct bgp_nexthop_cache *bnc;
	struct bgp_nexthop_cache *te_bnc = NULL;
	struct bgp_nexthop_cache *te_bnc_backup = NULL;
	struct prefix p;
	uint32_t srte_color = 0;
	uint8_t  srte_color_flag = 0;
	uint32_t srte_color_backup = 0;
	uint8_t  srte_color_backup_flag = 0;
	int is_bgp_static_route = 0;
	ifindex_t ifindex = 0;
	bool isServiceRoute = false;

	// if we need print nht log for prefix, format msg here
	bool nht_debug_print = false;
	char nht_debug_buf[PREFIX2STR_BUFFER * 4] = "";

	if (pi && pi->net) {
		nht_debug_print = bgp_debug_nht_per_prefix(bgp_dest_get_prefix(pi->net));
		if (nht_debug_print) {
			bgp_path_info_nht_debug(pi, nht_debug_buf, sizeof(nht_debug_buf));
		}
	}

	if (pi && (pi->attr->srv6_l3vpn || pi->attr->srv6_vpn))
		isServiceRoute = true;

	if (pi) {
		is_bgp_static_route = ((pi->type == ZEBRA_ROUTE_BGP)
				       && (pi->sub_type == BGP_ROUTE_STATIC))
					      ? 1
					      : 0;

		/* Since Extended Next-hop Encoding (RFC5549) support, we want
		   to derive
		   address-family from the next-hop. */
		if (!is_bgp_static_route)
			afi = BGP_ATTR_NEXTHOP_AFI_IP6(pi->attr) ? AFI_IP6
								 : AFI_IP;

		/* Validation for the ipv4 mapped ipv6 nexthop. */
		if (IS_MAPPED_IPV6(&pi->attr->mp_nexthop_global)) {
			afi = AFI_IP;
		}

		/* This will return true if the global IPv6 NH is a link local
		 * addr */
		if (make_prefix(afi, pi, &p) < 0)
			return 1;

		ecommunity_select_color(
			pi->attr->ecommunity, &srte_color, &srte_color_flag, &srte_color_backup, &srte_color_backup_flag);

		if (!is_bgp_static_route && orig_prefix
		    && prefix_same(&p, orig_prefix)) {
			if (BGP_DEBUG(nht, NHT)) {
				zlog_debug(
					"%s(%pFX): prefix loops through itself",
					__func__, &p);
			}
			return 0;
		}

	} else if (peer) {
		/*
		 * Gather the ifindex for if up/down events to be
		 * tagged into this fun
		 */
		if (afi == AFI_IP6
		    && IN6_IS_ADDR_LINKLOCAL(&peer->connection->su.sin6.sin6_addr))
			ifindex = peer->connection->su.sin6.sin6_scope_id;

		if (!sockunion2hostprefix(&peer->connection->su, &p)) {
			if (nht_debug_print) {
				zlog_debug(
					"%s: %s Attempting to register with unknown AFI %d (not %d or %d)",
					__func__, nht_debug_buf, afi, AFI_IP, AFI_IP6);
			}
			return 0;
		}
	} else
		return 0;

	if (is_bgp_static_route)
		tree = &bgp_nexthop->import_check_table[afi];
	else
		tree = &bgp_nexthop->nexthop_cache_table[afi];

	bnc = bnc_find(tree, &p, 0, 0);
	if (!bnc) {
		bnc = bnc_new(tree, &p, 0, 0);
		bnc->bgp = bgp_nexthop;
		bnc->ifindex = ifindex;
		if (nht_debug_print) {
			char buf[PREFIX2STR_BUFFER];

			zlog_debug("%s: %s Allocated bnc %s(%u)(%s) peer %p",
				   __func__, nht_debug_buf, 
				   bnc_str(bnc, buf, PREFIX2STR_BUFFER),
				   bnc->srte_color, bnc->bgp->name_pretty,
				   peer);
		}
	} else {
		if (nht_debug_print) {
			char buf[PREFIX2STR_BUFFER];

			zlog_debug(
				"%s: %s Found existing bnc %s(%s) flags 0x%x ifindex %d #paths %d peer %p",
				__func__, nht_debug_buf,
				bnc_str(bnc, buf, PREFIX2STR_BUFFER),
				bnc->bgp->name_pretty, bnc->flags, bnc->ifindex,
				bnc->path_count, bnc->nht_info);
		}
	}
#if 1
	if (srte_color != 0)
	{
		te_bnc = bnc_find(tree, &p, srte_color, srte_color_flag);
		if (!te_bnc) {
			te_bnc = bnc_new(tree, &p, srte_color, srte_color_flag);
			te_bnc->bgp = bgp_nexthop;
			if (nht_debug_print) {
				char buf[PREFIX2STR_BUFFER];

				zlog_debug("%s: %s Allocated bnc %s(%u)(%s) peer %p",
						__func__, nht_debug_buf, 
						bnc_str(te_bnc, buf, PREFIX2STR_BUFFER),
						te_bnc->srte_color, te_bnc->bgp->name_pretty,
						peer);
			}
		} else {
			if (nht_debug_print) {
				char buf[PREFIX2STR_BUFFER];
				zlog_debug(
					"%s: %s Found existing bnc %s(%s) flags 0x%x ifindex %d #paths %d peer %p, color %d",
					__func__, nht_debug_buf,
					bnc_str(te_bnc, buf, PREFIX2STR_BUFFER),
					te_bnc->bgp->name_pretty, te_bnc->flags, te_bnc->ifindex,
					te_bnc->path_count, te_bnc->nht_info, te_bnc->srte_color);
			}
		}
	}
	if (srte_color_backup != 0)
	{
		te_bnc_backup = bnc_find(tree, &p, srte_color_backup, srte_color_backup_flag);
		if (!te_bnc_backup) {
			te_bnc_backup = bnc_new(tree, &p, srte_color_backup, srte_color_backup_flag);
			te_bnc_backup->bgp = bgp_nexthop;
			if (nht_debug_print) {
				char buf[PREFIX2STR_BUFFER];

				zlog_debug("%s: %s Allocated bnc %s(%u)(%s) peer %p",
						__func__, nht_debug_buf,
						bnc_str(te_bnc_backup, buf, PREFIX2STR_BUFFER),
						te_bnc_backup->srte_color, te_bnc_backup->bgp->name_pretty,
						peer);
			}
		} else {
			if (nht_debug_print) {
				char buf[PREFIX2STR_BUFFER];
				zlog_debug(
					"%s: %s Found existing bnc %s(%s) flags 0x%x ifindex %d #paths %d peer %p, color %d",
					__func__, nht_debug_buf,
					bnc_str(te_bnc_backup, buf, PREFIX2STR_BUFFER),
					te_bnc_backup->bgp->name_pretty, te_bnc_backup->flags, te_bnc_backup->ifindex,
					te_bnc_backup->path_count, te_bnc_backup->nht_info, te_bnc_backup->srte_color);
			}
		}
	}
#endif
	if (pi && is_route_parent_evpn(pi))
		bnc->is_evpn_gwip_nexthop = true;

	if (is_bgp_static_route) {
		SET_FLAG(bnc->flags, BGP_STATIC_ROUTE);

		/* If we're toggling the type, re-register */
		if ((CHECK_FLAG(bgp_route->flags, BGP_FLAG_IMPORT_CHECK))
		    && !CHECK_FLAG(bnc->flags, BGP_STATIC_ROUTE_EXACT_MATCH)) {
			SET_FLAG(bnc->flags, BGP_STATIC_ROUTE_EXACT_MATCH);
			UNSET_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED);
			UNSET_FLAG(bnc->flags, BGP_NEXTHOP_VALID);
		} else if ((!CHECK_FLAG(bgp_route->flags,
					BGP_FLAG_IMPORT_CHECK))
			   && CHECK_FLAG(bnc->flags,
					 BGP_STATIC_ROUTE_EXACT_MATCH)) {
			UNSET_FLAG(bnc->flags, BGP_STATIC_ROUTE_EXACT_MATCH);
			UNSET_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED);
			UNSET_FLAG(bnc->flags, BGP_NEXTHOP_VALID);
		}
	}
	/* When nexthop is already known, but now requires 'connected'
	 * resolution,
	 * re-register it. The reverse scenario where the nexthop currently
	 * requires
	 * 'connected' resolution does not need a re-register (i.e., we treat
	 * 'connected-required' as an override) except in the scenario where
	 * this
	 * is actually a case of tracking a peer for connectivity (e.g., after
	 * disable connected-check).
	 * NOTE: We don't track the number of paths separately for 'connected-
	 * required' vs 'connected-not-required' as this change is not a common
	 * scenario.
	 */
	else if (connected && !CHECK_FLAG(bnc->flags, BGP_NEXTHOP_CONNECTED)) {
		SET_FLAG(bnc->flags, BGP_NEXTHOP_CONNECTED);
		UNSET_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED);
		UNSET_FLAG(bnc->flags, BGP_NEXTHOP_VALID);
	} else if (peer && !connected
		   && CHECK_FLAG(bnc->flags, BGP_NEXTHOP_CONNECTED)) {
		UNSET_FLAG(bnc->flags, BGP_NEXTHOP_CONNECTED);
		UNSET_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED);
		UNSET_FLAG(bnc->flags, BGP_NEXTHOP_VALID);
	}
	if (peer && (bnc->ifindex != ifindex)) {
		UNSET_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED);
		UNSET_FLAG(bnc->flags, BGP_NEXTHOP_VALID);
		bnc->ifindex = ifindex;
	}
	if (bgp_route->inst_type == BGP_INSTANCE_TYPE_VIEW) {
		SET_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED);
		SET_FLAG(bnc->flags, BGP_NEXTHOP_VALID);
	}
    else if (!CHECK_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED)
		   && !is_default_host_route(&bnc->prefix))
    {
		register_zebra_rnh(bnc);
	}
#if 1
    if (te_bnc && !CHECK_FLAG(te_bnc->flags, BGP_NEXTHOP_REGISTERED)) {
        register_zebra_rnh(te_bnc);
    }
	if (te_bnc_backup && !CHECK_FLAG(te_bnc_backup->flags, BGP_NEXTHOP_REGISTERED)) {
        register_zebra_rnh(te_bnc_backup);
    }
#endif
	if (pi && pi->nexthop != bnc) {
		/* Unlink from existing nexthop cache, if any. This will also
		 * free
		 * the nexthop cache entry, if appropriate.
		 */
		bgp_unlink_nexthop(pi);

		/* updates NHT pi list reference */
		path_nh_map(pi, bnc, true);

		if (CHECK_FLAG(bnc->flags, BGP_NEXTHOP_VALID) && bnc->metric)
			(bgp_path_info_extra_get(pi))->igpmetric = bnc->metric;
		else if (pi->extra)
			pi->extra->igpmetric = 0;
	} else if (peer) {
		/*
		 * Let's not accidently save the peer data for a peer
		 * we are going to throw away in a second or so.
		 * When we come back around we'll fix up this
		 * data properly in replace_nexthop_by_peer
		 */
		if (CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE))
			bnc->nht_info = (void *)peer; /* NHT peer reference */
	}
#if 1

	if (pi && pi->te_nexthop != te_bnc) {
		bgp_unlink_te_nexthop(pi);
		/* updates NHT pi list reference */
		if (te_bnc)
			path_tenh_map(pi, te_bnc, true);
	}
	if (pi && pi->te_backup_nexthop != te_bnc_backup) {
		bgp_unlink_tebk_nexthop(pi);
		/* updates NHT pi list reference */
		if (te_bnc_backup)
			path_tebk_nh_map(pi, te_bnc_backup, true);
	}
#endif
	/*
	 * We are cheating here.  Views have no associated underlying
	 * ability to detect nexthops.  So when we have a view
	 * just tell everyone the nexthop is valid
	 */

	if (bgp_route->inst_type == BGP_INSTANCE_TYPE_VIEW)
		return 1;
	else if (safi == SAFI_UNICAST && pi
		 && pi->sub_type == BGP_ROUTE_IMPORTED && pi->extra
		 && pi->extra->num_labels && !bnc->is_evpn_gwip_nexthop && !isServiceRoute) {
		 if (!CHECK_FLAG(bgp_nexthop->flags, BGP_FLAG_BESTPATH_NH_RESOLVED_TUNNEL))
			return (bgp_isvalid_labeled_nexthop(bnc));
		 else {
			return ((bgp_isvalid_labeled_nexthop(bnc)) || (bgp_isvalid_nexthop(te_bnc)));
		 }
	} else {
		if (!CHECK_FLAG(bgp_nexthop->flags, BGP_FLAG_BESTPATH_NH_RESOLVED_TUNNEL))
			return (bgp_isvalid_nexthop(bnc));
		else {
			return ((bgp_isvalid_nexthop(bnc)) || (bgp_isvalid_nexthop(te_bnc)));
		}
	}

}

void bgp_delete_connected_nexthop(afi_t afi, struct peer *peer)
{
	struct bgp_nexthop_cache *bnc;
	struct prefix p;

	if (!peer)
		return;

	if (!sockunion2hostprefix(&peer->connection->su, &p))
		return;

	bnc = bnc_find(&peer->bgp->nexthop_cache_table[family2afi(p.family)],
		       &p, 0, 0);
	if (!bnc) {
		if (BGP_DEBUG(nht, NHT))
			zlog_debug(
				"Cannot find connected NHT node for peer %s(%s)",
				peer->host, peer->bgp->name_pretty);
		return;
	}

	if (bnc->nht_info != peer) {
		if (BGP_DEBUG(nht, NHT))
			zlog_debug(
				"Connected NHT %p node for peer %s(%s) points to %p",
				bnc, peer->host, bnc->bgp->name_pretty,
				bnc->nht_info);
		return;
	}

	bnc->nht_info = NULL;

	if (LIST_EMPTY(&(bnc->paths))) {
		if (BGP_DEBUG(nht, NHT))
			zlog_debug(
				"Freeing connected NHT node %p for peer %s(%s)",
				bnc, peer->host, bnc->bgp->name_pretty);
		unregister_zebra_rnh(bnc);
		bnc_free(bnc);
	}
}

static void bgp_process_nexthop_update(struct bgp_nexthop_cache *bnc,
				       struct zapi_route *nhr,
				       bool import_check)
{
	struct nexthop *nexthop;
	struct nexthop *oldnh;
	struct nexthop *nhlist_head = NULL;
	struct nexthop *nhlist_tail = NULL;
	int i;
	bool evpn_resolved = false;
    struct peer *peer = bnc->nht_info;

	bnc->last_update = bgp_clock();
	bnc->change_flags = 0;

	/* debug print the input */
	if (BGP_DEBUG(nht, NHT)) {
		char bnc_buf[BNC_FLAG_DUMP_SIZE];

		zlog_debug(
			"%s(%u): Rcvd NH update %pFX(%u) - metric %u/%u #nhops %d/%d flags %s type %d",
			bnc->bgp->name_pretty, bnc->bgp->vrf_id, &nhr->prefix,
			bnc->srte_color, nhr->metric, bnc->metric,
			nhr->nexthop_num, bnc->nexthop_num,
			bgp_nexthop_dump_bnc_flags(bnc, bnc_buf,sizeof(bnc_buf)),
            nhr->type);
	}

	if (nhr->metric != bnc->metric)
		bnc->change_flags |= BGP_NEXTHOP_METRIC_CHANGED;

	if (nhr->nexthop_num != bnc->nexthop_num) {
		if (nhr->nexthop_num != 0 && bnc->nexthop_num != 0)
			bnc->change_flags |= BGP_NEXTHOP_COUNT_UNCHANGED;
        bnc->change_flags |= BGP_NEXTHOP_CHANGED;
	}
	if (import_check && (nhr->type == ZEBRA_ROUTE_BGP ||
				 !prefix_same(&bnc->prefix, &nhr->prefix))) {
		SET_FLAG(bnc->change_flags, BGP_NEXTHOP_CHANGED);
		UNSET_FLAG(bnc->flags, BGP_NEXTHOP_VALID);
		UNSET_FLAG(bnc->flags, BGP_NEXTHOP_LABELED_VALID);
		UNSET_FLAG(bnc->flags, BGP_NEXTHOP_EVPN_INCOMPLETE);

		bnc_nexthop_free(bnc);
		bnc->nexthop = NULL;

		if (BGP_DEBUG(nht, NHT))
			zlog_debug(
				"%s: Import Check does not resolve to the same prefix for %pFX received %pFX or matching route is BGP",
				__func__, &bnc->prefix, &nhr->prefix);
	}else if (nhr->nexthop_num) {
		/* notify bgp fsm if nbr ip goes from invalid->valid */
		if (!bnc->nexthop_num)
			UNSET_FLAG(bnc->flags, BGP_NEXTHOP_PEER_NOTIFIED);

		if (!bnc->is_evpn_gwip_nexthop)
			bnc->flags |= BGP_NEXTHOP_VALID;
		if (nhr->type == ZEBRA_ROUTE_SRTE) 
			SET_FLAG(bnc->flags, BGP_NEXTHOP_SRV6TE_VALID);
		else
			UNSET_FLAG(bnc->flags, BGP_NEXTHOP_SRV6TE_VALID);
		bnc->resolve_prefix = nhr->prefix;
		bnc->metric = nhr->metric;
		bnc->nexthop_num = nhr->nexthop_num;

		bnc->flags &= ~BGP_NEXTHOP_LABELED_VALID; /* check below */

		for (i = 0; i < nhr->nexthop_num; i++) {
			int num_labels = 0;

			nexthop = nexthop_from_zapi_nexthop(&nhr->nexthops[i]);

			/*
				* Turn on RA for the v6 nexthops
				* we receive from bgp.  This is to allow us
				* to work with v4 routing over v6 nexthops
				*/
			if (peer && !peer->ifp
				&& CHECK_FLAG(peer->flags,
						PEER_FLAG_CAPABILITY_ENHE)
				&& nhr->prefix.family == AF_INET6
				&& nexthop->type != NEXTHOP_TYPE_BLACKHOLE) {
				struct interface *ifp;

				ifp = if_lookup_by_index(nexthop->ifindex,
								nexthop->vrf_id);
				if (ifp)
					zclient_send_interface_radv_req(
						zclient, nexthop->vrf_id, ifp,
						true,
						BGP_UNNUM_DEFAULT_RA_INTERVAL);
			}
			/* There is at least one label-switched path */
			if (nexthop->nh_label &&
				nexthop->nh_label->num_labels) {

				bnc->flags |= BGP_NEXTHOP_LABELED_VALID;
				num_labels = nexthop->nh_label->num_labels;
			}

			if (BGP_DEBUG(nht, NHT)) {
				char buf[NEXTHOP_STRLEN];
				zlog_debug(
					"    nhop via %s (%d labels, %s sidlist)",
					nexthop2str(nexthop, buf, sizeof(buf)),
					num_labels, nexthop->sidlist_name);
			}

			if (nhlist_tail) {
				nhlist_tail->next = nexthop;
				nhlist_tail = nexthop;
			} else {
				nhlist_tail = nexthop;
				nhlist_head = nexthop;
			}

			/* No need to evaluate the nexthop if we have already
				* determined
				* that there has been a change.
				*/
			if (bnc->change_flags & BGP_NEXTHOP_CHANGED)
				continue;

			for (oldnh = bnc->nexthop; oldnh; oldnh = oldnh->next)
				if (nexthop_same(oldnh, nexthop))
					break;

			if (!oldnh)
				bnc->change_flags |= BGP_NEXTHOP_CHANGED;
		}
		bnc_nexthop_free(bnc);
		bnc->nexthop = nhlist_head;

		/*
		 * Gateway IP nexthop is L3 reachable. Mark it as
		 * BGP_NEXTHOP_VALID only if it is recursively resolved with a
		 * remote EVPN RT-2.
		 * Else, mark it as BGP_NEXTHOP_EVPN_INCOMPLETE.
		 * When its mapping with EVPN RT-2 is established, unset
		 * BGP_NEXTHOP_EVPN_INCOMPLETE and set BGP_NEXTHOP_VALID.
		 */
		if (bnc->is_evpn_gwip_nexthop) {
			evpn_resolved = bgp_evpn_is_gateway_ip_resolved(bnc);

			if (BGP_DEBUG(nht, NHT)) {
				char buf2[PREFIX2STR_BUFFER];

				prefix2str(&bnc->prefix, buf2, sizeof(buf2));
				zlog_debug(
					"EVPN gateway IP %s recursive MAC/IP lookup %s",
					buf2,
					(evpn_resolved ? "successful"
						       : "failed"));
			}

			if (evpn_resolved) {
				bnc->flags |= BGP_NEXTHOP_VALID;
				bnc->flags &= ~BGP_NEXTHOP_EVPN_INCOMPLETE;
				bnc->change_flags |= BGP_NEXTHOP_MACIP_CHANGED;
			} else {
				bnc->flags |= BGP_NEXTHOP_EVPN_INCOMPLETE;
				bnc->flags &= ~BGP_NEXTHOP_VALID;
			}
		}
	} else {
		bnc->flags &= ~BGP_NEXTHOP_EVPN_INCOMPLETE;
		bnc->flags &= ~BGP_NEXTHOP_VALID;
		bnc->flags &= ~BGP_NEXTHOP_LABELED_VALID;
        UNSET_FLAG(bnc->flags, BGP_NEXTHOP_SRV6TE_VALID);
		bnc->nexthop_num = nhr->nexthop_num;

		/* notify bgp fsm if nbr ip goes from valid->invalid */
		UNSET_FLAG(bnc->flags, BGP_NEXTHOP_PEER_NOTIFIED);

		bnc_nexthop_free(bnc);
		bnc->nexthop = NULL;

	}

	evaluate_paths(bnc);
}

static void bgp_process_cond_nexthop_update(struct bgp_nexthop_cache *bnc,
				       struct zapi_route *nhr)
{
	struct nexthop *nexthop;
	struct nexthop *nhlist_head = NULL;
	struct nexthop *nhlist_tail = NULL;
	int i;

	bnc->last_update = bgp_clock();
	bnc->change_flags = 0;

	/* debug print the input */
	if (BGP_DEBUG(nht, NHT)) {
		char bnc_buf[BNC_FLAG_DUMP_SIZE];

		zlog_debug(
			"%s(%u): Rcvd cond NH update %pFX(flag:%d, color:%u) - metric %d/%d #nhops %d/%d flags %s",
			bnc->bgp->name_pretty, bnc->bgp->vrf_id, &nhr->prefix,
			bnc->srte_color, bnc->srte_color_flag, nhr->metric, bnc->metric,
			nhr->nexthop_num, bnc->nexthop_num,
			bgp_nexthop_dump_bnc_flags(bnc, bnc_buf,
						   sizeof(bnc_buf)));
	}

	if (nhr->nexthop_num != bnc->nexthop_num && (nhr->nexthop_num == 0 || bnc->nexthop_num == 0))
		bnc->change_flags |= BGP_NEXTHOP_CHANGED;

	if (nhr->nexthop_num) {
		bnc->flags |= BGP_NEXTHOP_VALID;
		bnc->metric = nhr->metric;
		bnc->nexthop_num = nhr->nexthop_num;

		for (i = 0; i < nhr->nexthop_num; i++) {
			nexthop = nexthop_from_zapi_nexthop(&nhr->nexthops[i]);

			if (BGP_DEBUG(nht, NHT)) {
				char buf[NEXTHOP_STRLEN];
				zlog_debug(
					"    nhop via %s ",
					nexthop2str(nexthop, buf, sizeof(buf)));
			}

			if (nhlist_tail) {
				nhlist_tail->next = nexthop;
				nhlist_tail = nexthop;
			} else {
				nhlist_tail = nexthop;
				nhlist_head = nexthop;
			}
		}
		bnc_nexthop_free(bnc);
		bnc->nexthop = nhlist_head;

	} else {
		bnc->flags &= ~BGP_NEXTHOP_VALID;
		bnc->nexthop_num = nhr->nexthop_num;

		bnc_nexthop_free(bnc);
		bnc->nexthop = NULL;
	}

	bgp_notify_condition_peer(bnc);
}

static void bgp_nht_ifp_table_handle(struct bgp *bgp,
				     struct bgp_nexthop_cache_head *table,
				     struct interface *ifp, bool up)
{
	struct bgp_nexthop_cache *bnc;

	frr_each (bgp_nexthop_cache, table, bnc) {
		if (bnc->ifindex != ifp->ifindex)
			continue;

		bnc->last_update = bgp_clock();
		bnc->change_flags = 0;

		/*
		 * For interface based routes ( ala the v6 LL routes
		 * that this was written for ) the metric received
		 * for the connected route is 0 not 1.
		 */
		bnc->metric = 0;
		if (up) {
			SET_FLAG(bnc->flags, BGP_NEXTHOP_VALID);
			SET_FLAG(bnc->change_flags, BGP_NEXTHOP_CHANGED);
			bnc->nexthop_num = 1;
		} else {
			UNSET_FLAG(bnc->flags, BGP_NEXTHOP_PEER_NOTIFIED);
			UNSET_FLAG(bnc->flags, BGP_NEXTHOP_VALID);
			SET_FLAG(bnc->change_flags, BGP_NEXTHOP_CHANGED);
			bnc->nexthop_num = 0;
		}

		evaluate_paths(bnc);
	}
}
static void bgp_nht_ifp_handle(struct interface *ifp, bool up)
{
	struct bgp *bgp;

	bgp = ifp->vrf->info;
	if (!bgp)
		return;

	if (!up)
		bgp_clearing_batch_begin(bgp);

	bgp_nht_ifp_table_handle(bgp, &bgp->nexthop_cache_table[AFI_IP6], ifp,
				 up);
	bgp_nht_ifp_table_handle(bgp, &bgp->import_check_table[AFI_IP6], ifp,
				 up);

	if (!up)
		bgp_clearing_batch_end_event_start(bgp);
}

void bgp_nht_ifp_up(struct interface *ifp)
{
	bgp_nht_ifp_handle(ifp, true);
}

void bgp_nht_ifp_down(struct interface *ifp)
{
	bgp_nht_ifp_handle(ifp, false);
}

static int bgp_nht_ifp_initial(struct thread *thread)
{
	ifindex_t ifindex = THREAD_VAL(thread);
	struct bgp *bgp = THREAD_ARG(thread);
	struct interface *ifp = if_lookup_by_index(ifindex, bgp->vrf_id);

	if (!ifp)
		return 0;

	if (BGP_DEBUG(nht, NHT))
		zlog_debug(
			"Handle NHT initial update for Intf %s(%d) status %s",
			ifp->name, ifp->ifindex, if_is_up(ifp) ? "up" : "down");

	if (if_is_up(ifp))
		bgp_nht_ifp_up(ifp);
	else
		bgp_nht_ifp_down(ifp);

	return 0;
}

/*
 * So the bnc code has the ability to handle interface up/down
 * events to properly handle v6 LL peering.
 * What is happening here:
 * The event system for peering expects the nht code to
 * report on the tracking events after we move to active
 * So let's give the system a chance to report on that event
 * in a manner that is expected.
 */
void bgp_nht_interface_events(struct peer *peer)
{
	struct bgp *bgp = peer->bgp;
	struct bgp_nexthop_cache_head *table;
	struct bgp_nexthop_cache *bnc;
	struct prefix p;

	if (!IN6_IS_ADDR_LINKLOCAL(&peer->connection->su.sin6.sin6_addr))
		return;

	if (!sockunion2hostprefix(&peer->connection->su, &p))
		return;

	table = &bgp->nexthop_cache_table[AFI_IP6];
	bnc = bnc_find(table, &p, 0, 0);
	if (!bnc)
		return;

	if (bnc->ifindex)
		thread_add_event(bm->master, bgp_nht_ifp_initial, bnc->bgp,
				 bnc->ifindex, NULL);
}

void bgp_parse_nexthop_update(int command, vrf_id_t vrf_id)
{
	struct bgp_nexthop_cache_head *tree = NULL;
	struct bgp_nexthop_cache *bnc_nhc, *bnc_import, *bnc_cond;
	struct bgp *bgp;
	struct prefix match;
	struct zapi_route nhr;
	afi_t afi;

	bgp = bgp_lookup_by_vrf_id(vrf_id);
	if (!bgp) {
		flog_err(
			EC_BGP_NH_UPD,
			"parse nexthop update: instance not found for vrf_id %u",
			vrf_id);
		return;
	}

	if (!zapi_nexthop_update_decode(zclient->ibuf, &match, &nhr)) {
		zlog_err("%s[%s]: Failure to decode nexthop update", __func__,
			 bgp->name_pretty);
		return;
	}

	afi = family2afi(match.family);
	tree = &bgp->nexthop_cache_table[afi];

	bnc_nhc = bnc_find(tree, &match, nhr.srte_color, nhr.srte_color_flag);
	if (!bnc_nhc) {
		if (BGP_DEBUG(nht, NHT))
			zlog_debug(
				"parse nexthop update(%pFX(%u)(%s)): bnc info not found for nexthop cache",
				&nhr.prefix, nhr.srte_color, bgp->name_pretty);
	} else
		bgp_process_nexthop_update(bnc_nhc, &nhr, false);

	tree = &bgp->condition_track_table[afi];
	bnc_cond = bnc_find(tree, &match, nhr.srte_color, nhr.srte_color_flag);
	if (bnc_cond) {
		bgp_process_cond_nexthop_update(bnc_cond, &nhr);
	}

	tree = &bgp->import_check_table[afi];
	bnc_import = bnc_find(tree, &match, nhr.srte_color, nhr.srte_color_flag);
	if (!bnc_import) {
		if (BGP_DEBUG(nht, NHT))
			zlog_debug(
				"parse nexthop update(%pFX(%u)(%s)): bnc info not found for import check",
				&nhr.prefix, nhr.srte_color, bgp->name_pretty);
	} else {
		bgp_process_nexthop_update(bnc_import, &nhr, true);
	}

#if 0
	/*
	 * HACK: if any BGP route is dependant on an SR-policy that doesn't
	 * exist, zebra will never send NH updates relative to that policy. In
	 * that case, whenever we receive an update about a colorless NH, update
	 * the corresponding colorful NHs that share the same endpoint but that
	 * are inactive. This ugly hack should work around the problem at the
	 * cost of a performance pernalty. Long term, what should be done is to
	 * make zebra's RNH subsystem aware of SR-TE colors (like bgpd is),
	 * which should provide a better infrastructure to solve this issue in
	 * a more efficient and elegant way.
	 */
	if (bnc_nhc && ((nhr.srte_color == 0) || (nhr.srte_color == bnc_nhc->srte_color))) {
		struct bgp_nexthop_cache *bnc_iter;

		frr_each (bgp_nexthop_cache, &bgp->nexthop_cache_table[afi],
			  bnc_iter) {
			if (!prefix_same(&bnc_import->prefix, &bnc_iter->prefix)
			    || bnc_iter->srte_color == 0
			    || CHECK_FLAG(bnc_iter->flags, BGP_NEXTHOP_VALID))
				continue;

			bgp_process_nexthop_update(bnc_iter, &nhr);
		}
	}
#endif
}

/*
 * Cleanup nexthop registration and status information for BGP nexthops
 * pertaining to this VRF. This is invoked upon VRF deletion.
 */
void bgp_cleanup_nexthops(struct bgp *bgp)
{
	for (afi_t afi = AFI_IP; afi < AFI_MAX; afi++) {
		struct bgp_nexthop_cache *bnc;

		frr_each (bgp_nexthop_cache, &bgp->nexthop_cache_table[afi],
			  bnc) {
			/* Clear relevant flags. */
			UNSET_FLAG(bnc->flags, BGP_NEXTHOP_VALID);
			UNSET_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED);
			UNSET_FLAG(bnc->flags, BGP_NEXTHOP_PEER_NOTIFIED);
			UNSET_FLAG(bnc->flags, BGP_NEXTHOP_EVPN_INCOMPLETE);
		}
	}
}

/**
 * make_prefix - make a prefix structure from the path (essentially
 * path's node.
 */
static int make_prefix(int afi, struct bgp_path_info *pi, struct prefix *p)
{

	int is_bgp_static = ((pi->type == ZEBRA_ROUTE_BGP)
			     && (pi->sub_type == BGP_ROUTE_STATIC))
				    ? 1
				    : 0;
	struct bgp_dest *net = pi->net;
	const struct prefix *p_orig = bgp_dest_get_prefix(net);
	struct in_addr ipv4;

	if (p_orig->family == AF_FLOWSPEC) {
		if (!pi->peer)
			return -1;
		return bgp_flowspec_get_first_nh(pi->peer->bgp,
						 pi, p, afi);
	}
	memset(p, 0, sizeof(struct prefix));
	switch (afi) {
	case AFI_IP:
		p->family = AF_INET;
		if (is_bgp_static) {
			p->u.prefix4 = p_orig->u.prefix4;
			p->prefixlen = p_orig->prefixlen;
		} else {
			if (IS_MAPPED_IPV6(&pi->attr->mp_nexthop_global)) {
				ipv4_mapped_ipv6_to_ipv4(
					&pi->attr->mp_nexthop_global, &ipv4);
				p->u.prefix4 = ipv4;
				p->prefixlen = IPV4_MAX_BITLEN;
			} else {
				p->u.prefix4 = pi->attr->nexthop;
				p->prefixlen = IPV4_MAX_BITLEN;
			}
		}
		break;
	case AFI_IP6:
		p->family = AF_INET6;

		if (is_bgp_static) {
			p->u.prefix6 = p_orig->u.prefix6;
			p->prefixlen = p_orig->prefixlen;
		} else {
			/* If we receive MP_REACH nexthop with ::(LL)
			 * or LL(LL), use LL address as nexthop cache.
			 */
			if (pi->attr->mp_nexthop_len
				    == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL
			    && (IN6_IS_ADDR_UNSPECIFIED(
					&pi->attr->mp_nexthop_global)
				|| IN6_IS_ADDR_LINKLOCAL(
					&pi->attr->mp_nexthop_global)))
				p->u.prefix6 = pi->attr->mp_nexthop_local;
			/* If we receive MR_REACH with (GA)::(LL)
			 * then check for route-map to choose GA or LL
			 */
			else if (pi->attr->mp_nexthop_len
				 == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL) {
				if (pi->attr->mp_nexthop_prefer_global)
					p->u.prefix6 =
						pi->attr->mp_nexthop_global;
				else
					p->u.prefix6 =
						pi->attr->mp_nexthop_local;
			} else
				p->u.prefix6 = pi->attr->mp_nexthop_global;
			p->prefixlen = IPV6_MAX_BITLEN;
		}
		break;
	default:
		{
			// If we need print nht log for prefix, format msg here
			char nht_debug_buf[PREFIX2STR_BUFFER * 4] = "";
			if ((pi && pi->net)) {
				if (bgp_debug_nht_per_prefix(bgp_dest_get_prefix(pi->net))) {
					bgp_path_info_nht_debug(pi, nht_debug_buf, sizeof(nht_debug_buf));
					zlog_debug(
						"%s: %s Attempting to make prefix with unknown AFI %d (not %d or %d)",
						__func__, nht_debug_buf, afi, AFI_IP, AFI_IP6);
				}
			}
		}
		break;
	}
	return 0;
}

/**
 * sendmsg_zebra_rnh -- Format and send a nexthop register/Unregister
 *   command to Zebra.
 * ARGUMENTS:
 *   struct bgp_nexthop_cache *bnc -- the nexthop structure.
 *   int command -- command to send to zebra
 * RETURNS:
 *   void.
 */
static void sendmsg_zebra_rnh(struct bgp_nexthop_cache *bnc, int command)
{
	bool exact_match = false;
	int ret;

    if (!zclient)
        return;

    /* Don't try to register if Zebra doesn't know of this instance. */
    if (!IS_BGP_INST_KNOWN_TO_ZEBRA(bnc->bgp)) {
        if (BGP_DEBUG(zebra, ZEBRA))
            zlog_debug(
                "%s: No zebra instance to talk to, not installing NHT entry",
                __func__);
        return;
    }

	if (!bgp_zebra_num_connects()) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug(
				"%s: We have not connected yet, cannot send nexthops",
				__func__);
	}
	if (command == ZEBRA_NEXTHOP_REGISTER) {
		if (CHECK_FLAG(bnc->flags, BGP_NEXTHOP_CONNECTED))
			exact_match = true;
	}

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("%s: sending cmd %s for %pFX (vrf %s color %d)", __func__,
			   zserv_command_string(command), &bnc->prefix,
			   bnc->bgp->name_pretty, bnc->srte_color);

	if (bnc->srte_color) {
		struct zapi_color_para tmp = {0};
		tmp.srte_color = bnc->srte_color;
		tmp.srte_color_flag = bnc->srte_color_flag;
		ret = zclient_send_rnh(zclient, command, &bnc->prefix, exact_match,
					   false, bnc->bgp->vrf_id, NEXTHOP_REGISTER_TYPE_COLOR, &tmp);
	}
	else if (CHECK_FLAG(bnc->flags, BGP_STATIC_ROUTE_EXACT_MATCH))
		ret = zclient_send_rnh(zclient, command, &bnc->prefix, exact_match,
					   false, bnc->bgp->vrf_id, NEXTHOP_REGISTER_TYPE_IMPORTCHECK, NULL);
	else if (CHECK_FLAG(bnc->flags, BGP_CONDITION_TRACK_ROUTE))
		ret = zclient_send_rnh(zclient, command, &bnc->prefix, exact_match,
					   false, bnc->bgp->vrf_id, NEXTHOP_REGISTER_TYPE_TRACK, NULL);
	else
		ret = zclient_send_rnh(zclient, command, &bnc->prefix, exact_match,
					   false, bnc->bgp->vrf_id, NEXTHOP_REGISTER_TYPE_DEFAULT, NULL);
	/* TBD: handle the failure */
	if (ret == ZCLIENT_SEND_FAILURE) {
		flog_warn(EC_BGP_ZEBRA_SEND,
			  "sendmsg_nexthop: zclient_send_message() failed");
		return;
	}

	if (command == ZEBRA_NEXTHOP_REGISTER)
		SET_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED);
	else if (command == ZEBRA_NEXTHOP_UNREGISTER)
		UNSET_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED);
	return;
}

/**
 * register_zebra_rnh - register a NH/route with Zebra for notification
 *    when the route or the route to the nexthop changes.
 * ARGUMENTS:
 *   struct bgp_nexthop_cache *bnc
 * RETURNS:
 *   void.
 */
void register_zebra_rnh(struct bgp_nexthop_cache *bnc)
{
	/* Check if we have already registered */
	if (bnc->flags & BGP_NEXTHOP_REGISTERED)
		return;

	if (bnc->ifindex) {
		SET_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED);
		return;
	}

	sendmsg_zebra_rnh(bnc, ZEBRA_NEXTHOP_REGISTER);
}

/**
 * unregister_zebra_rnh -- Unregister the route/nexthop from Zebra.
 * ARGUMENTS:
 *   struct bgp_nexthop_cache *bnc
 * RETURNS:
 *   void.
 */
void unregister_zebra_rnh(struct bgp_nexthop_cache *bnc)
{
	/* Check if we have already registered */
	if (!CHECK_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED))
		return;

	if (bnc->ifindex) {
		UNSET_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED);
		return;
	}

	sendmsg_zebra_rnh(bnc, ZEBRA_NEXTHOP_UNREGISTER);
}

void bgp_process_nexthop_change(struct bgp_nexthop_cache *bnc, struct bgp_path_info *path)
{
	struct bgp_dest *dest;
	int afi;
	struct bgp_table *table;
	safi_t safi;
	struct bgp *bgp_path;
	const struct prefix *p;
	bool isServiceRoute = false;
	bool isSrv6TeBnc = false;
	bool valid_nexthop = false;
	struct bgp_nexthop_cache *ip_bnc = NULL;
	struct bgp_nexthop_cache *te_bnc = NULL;

	dest = path->net;
	assert(dest && bgp_dest_table(dest));
	p = bgp_dest_get_prefix(dest);
	afi = family2afi(p->family);
	table = bgp_dest_table(dest);
	safi = table->safi;

	// If we need print nht log for prefix, format msg here
	bool nht_debug_print = false;
	char nht_debug_buf[PREFIX2STR_BUFFER * 4] = "";
	nht_debug_buf[0] = '\0';
	if (path && path->net) {
		nht_debug_print = bgp_debug_nht_per_prefix(bgp_dest_get_prefix(path->net));
		if (nht_debug_print) {
			bgp_path_info_nht_debug(path, nht_debug_buf, sizeof(nht_debug_buf));
		}
	}

	/*
		* handle routes from other VRFs (they can have a
		* nexthop in THIS VRF). bgp_path is the bgp instance
		* that owns the route referencing this nexthop.
		*/
	bgp_path = table->bgp;

	/*
		* Path becomes valid/invalid depending on whether the nexthop
		* reachable/unreachable.
		*
		* In case of unicast routes that were imported from vpn
		* and that have labels, they are valid only if there are
		* nexthops with labels
		*
		* If the nexthop is EVPN gateway-IP,
		* do not check for a valid label.
		*/
	if (bnc == path->te_backup_nexthop 
		&& path->te_nexthop 
		&& CHECK_FLAG(path->te_nexthop->flags, BGP_NEXTHOP_SRV6TE_VALID))
		return;
	if (bnc->srte_color != 0)
		isSrv6TeBnc = true;

	bool ip_bnc_is_valid_nexthop = false;
	bool path_valid = false;
	if (path && ((path->attr->srv6_l3vpn || path->attr->srv6_vpn)
		 || (path->te_nexthop && CHECK_FLAG(path->te_nexthop->flags, BGP_NEXTHOP_SRV6TE_VALID))))
		isServiceRoute = true;
	else
		isServiceRoute = false;

	ip_bnc = path->nexthop;
	te_bnc = path->te_nexthop;

	if (safi == SAFI_UNICAST && path->sub_type == BGP_ROUTE_IMPORTED
		&& path->extra && path->extra->num_labels
		&& (path->attr->evpn_overlay.type != OVERLAY_INDEX_GATEWAY_IP)
		&& (!path->attr || !path->attr->vni || is_zero_mac(&path->attr->rmac))){
			if (isServiceRoute)
				ip_bnc_is_valid_nexthop =
					bgp_isvalid_nexthop(ip_bnc) ? true : false;
			else
				ip_bnc_is_valid_nexthop =
					bgp_isvalid_labeled_nexthop(ip_bnc) ? true : false;
	} else if (safi == SAFI_MPLS_VPN &&
			path->sub_type != BGP_ROUTE_IMPORTED) {
		/* avoid not redistributing mpls vpn routes */
		ip_bnc_is_valid_nexthop =
			bgp_isvalid_nexthop(ip_bnc) ? true : false;
	} else {
		if (bgp_update_martian_nexthop(
				ip_bnc->bgp, afi, safi, path->type,
				path->sub_type, path->attr, dest)) {
			if (nht_debug_print)
				zlog_debug(
					"%s: %s prefix %pBD (vrf %s), ignoring path due to martian or self-next-hop",
					__func__, nht_debug_buf, dest, bgp_path->name);
		} else {
			ip_bnc_is_valid_nexthop =
				bgp_isvalid_nexthop(ip_bnc) ? true : false;
		}
	}

	if (nht_debug_print) {
		char buf1[RD_ADDRSTRLEN];

		if (dest->pdest) {
			prefix_rd2str((struct prefix_rd *)bgp_dest_get_prefix(dest->pdest),
				buf1, sizeof(buf1));
			zlog_debug(
				"%s: %s ... eval path %d/%d %pBD RD %s %s flags 0x%x chgflags 0x%x subtype%d bnc %s serviceroute %s te %s",
				__func__, nht_debug_buf,
				afi, safi, dest, buf1,
				bgp_path->name_pretty, path->flags, bnc->change_flags, path->sub_type,
				ip_bnc_is_valid_nexthop ? "valid" : "invalid",
				isServiceRoute ? "yes" : "no", isSrv6TeBnc ? "yes" : "no");
		} else
			zlog_debug(
				"%s: %s ... eval path %d/%d %pBD %s flags 0x%x chgflags 0x%x subtype%d bnc %s serviceroute %s te %s",
				__func__, nht_debug_buf,
				afi, safi, dest, bgp_path->name_pretty,
				path->flags, bnc->change_flags, path->sub_type,
				ip_bnc_is_valid_nexthop ? "valid" : "invalid",
				isServiceRoute ? "yes" : "no", isSrv6TeBnc ? "yes" : "no");
	}

	/* Skip paths marked for removal or as history. */
	if (CHECK_FLAG(path->flags, BGP_PATH_REMOVED)
		|| CHECK_FLAG(path->flags, BGP_PATH_HISTORY))
		return;

	/* Copy the metric to the path. Will be used for bestpath
		* computation */
	if (bgp_isvalid_nexthop(bnc) && bnc->metric)
		(bgp_path_info_extra_get(path))->igpmetric =
			bnc->metric;
	else if (path->extra)
		path->extra->igpmetric = 0;

	if (CHECK_FLAG(bnc->change_flags, BGP_NEXTHOP_METRIC_CHANGED)
		|| isSrv6TeBnc)
		SET_FLAG(path->flags, BGP_PATH_IGP_CHANGED);
	if (CHECK_FLAG(bnc->change_flags, BGP_NEXTHOP_CHANGED) 
		&& (!isServiceRoute || !CHECK_FLAG(bnc->change_flags, BGP_NEXTHOP_COUNT_UNCHANGED)))
		SET_FLAG(path->flags, BGP_PATH_IGP_CHANGED);

	/* valid path and invalid bnc */
	/* For ip bnc(invalid), whether the path should be invalid depending on configuration,
	 *	if nexthop-resolved tunnel ON:
	 *		only if te bnc is invalid either, path becomes invalid;
	 *	if nexthop-resolved tunnel OFF:
	 *		path becomes invalid directly;
	 */
	/* If te bnc(invalid), no matter what configuration is, if the corresponding ip bnc is invalid,
	 * the path should become invalid.
	 */
	if (CHECK_FLAG(bnc->bgp->flags, BGP_FLAG_BESTPATH_NH_RESOLVED_TUNNEL))
		valid_nexthop = ip_bnc_is_valid_nexthop || bgp_isvalid_nexthop(te_bnc);
	else
		valid_nexthop = ip_bnc_is_valid_nexthop;

	path_valid = CHECK_FLAG(path->flags, BGP_PATH_VALID);
	if (path_valid != valid_nexthop) {
		if (path_valid) {
			/* No longer valid, clear flag; also for EVPN
				* routes, unimport from VRFs if needed.
				*/
			bgp_aggregate_decrement(bgp_path, p, path, afi,
						safi);
			bgp_path_info_unset_flag(dest, path,
							BGP_PATH_VALID);
			if (safi == SAFI_EVPN &&
				bgp_evpn_is_prefix_nht_supported(bgp_dest_get_prefix(dest)))
				bgp_evpn_unimport_route(bgp_path,
					afi, safi, bgp_dest_get_prefix(dest), path);
		} else if (!CHECK_FLAG(path->flags, BGP_PATH_SUPERNET)) {
			/* invalid path and valid bnc */
			/* Path becomes valid, set flag; also for EVPN
				* routes, import from VRFs if needed.
				*/
			bgp_path_info_set_flag(dest, path,
							BGP_PATH_VALID);
			bgp_aggregate_increment(bgp_path, p, path, afi,
						safi);
			if (safi == SAFI_EVPN &&
				bgp_evpn_is_prefix_nht_supported(bgp_dest_get_prefix(dest)))
				bgp_evpn_import_route(bgp_path,
					afi, safi, bgp_dest_get_prefix(dest), path);
		}
	}
	else if (CHECK_FLAG(path->flags, BGP_PATH_IGP_CHANGED) && path_valid)
	{
		if (safi == SAFI_EVPN &&
			bgp_evpn_is_prefix_nht_supported(bgp_dest_get_prefix(dest)))
			bgp_evpn_import_route(bgp_path,
				afi, safi, bgp_dest_get_prefix(dest), path);

		if (BGP_DEBUG(nht, NHT)) 
		{
			char buf1[RD_ADDRSTRLEN];
			if (dest->pdest) {
				prefix_rd2str((struct prefix_rd *)bgp_dest_get_prefix(dest->pdest),
					buf1, sizeof(buf1));
				zlog_debug(
					"... igp chenge eval path %d/%d %pBD RD %s %s flags 0x%x",
					afi, safi, dest, buf1,
					bgp_path->name_pretty, path->flags);
			} else
				zlog_debug(
					"... igp chenge eval path %d/%d %pBD %s flags 0x%x",
					afi, safi, dest, bgp_path->name_pretty,
					path->flags);
		}
	}

	bgp_process(bgp_path, dest, afi, safi);
}
/**
 * evaluate_paths - Evaluate the paths/nets associated with a nexthop.
 * ARGUMENTS:
 *   struct bgp_nexthop_cache *bnc -- the nexthop structure.
 * RETURNS:
 *   void.
 */
void evaluate_paths(struct bgp_nexthop_cache *bnc)
{
	struct bgp_path_info *path;
	struct peer *peer = (struct peer *)bnc->nht_info;

	if (BGP_DEBUG(nht, NHT)) {
		char buf[PREFIX2STR_BUFFER];
		char bnc_buf[BNC_FLAG_DUMP_SIZE];
		char chg_buf[BNC_FLAG_DUMP_SIZE];

		bnc_str(bnc, buf, PREFIX2STR_BUFFER);
		zlog_debug(
			"NH update for %s(%u)(%s) - flags %s chgflags %s- evaluate paths",
			buf, bnc->srte_color, bnc->bgp->name_pretty,
			bgp_nexthop_dump_bnc_flags(bnc, bnc_buf,
						   sizeof(bnc_buf)),
			bgp_nexthop_dump_bnc_change_flags(bnc, chg_buf,
							  sizeof(bnc_buf)));
	}

	if (bnc->srte_color == 0) {
		LIST_FOREACH (path, &(bnc->paths), nh_thread) {
			if (!(path->type == ZEBRA_ROUTE_BGP
				&& ((path->sub_type == BGP_ROUTE_NORMAL)
				|| (path->sub_type == BGP_ROUTE_STATIC)
				|| (path->sub_type == BGP_ROUTE_IMPORTED))))
				continue;
			bgp_process_nexthop_change(bnc, path);
		}
		bgp_process(bgp_path, dest, path, afi, safi);
	} else {
		LIST_FOREACH (path, &(bnc->paths), te_nh_thread) {
			if (!(path->type == ZEBRA_ROUTE_BGP
				&& ((path->sub_type == BGP_ROUTE_NORMAL)
				|| (path->sub_type == BGP_ROUTE_STATIC)
				|| (path->sub_type == BGP_ROUTE_IMPORTED))))
				continue;
			bgp_process_nexthop_change(bnc, path);
		}
		LIST_FOREACH (path, &(bnc->backup_paths), tebk_nh_thread) {
			if (!(path->type == ZEBRA_ROUTE_BGP
				&& ((path->sub_type == BGP_ROUTE_NORMAL)
				|| (path->sub_type == BGP_ROUTE_STATIC)
				|| (path->sub_type == BGP_ROUTE_IMPORTED))))
				continue;
			bgp_process_nexthop_change(bnc, path);
		}
	}

	if (peer) {
		int valid_nexthops = bgp_isvalid_nexthop(bnc);

		if (valid_nexthops) {
			/*
			 * Peering cannot occur across a blackhole nexthop
			 */
			if (bnc->nexthop_num == 1 && bnc->nexthop
			    && bnc->nexthop->type == NEXTHOP_TYPE_BLACKHOLE) {
				peer->last_reset = PEER_DOWN_WAITING_NHT;
				valid_nexthops = 0;
			} else
				peer->last_reset = PEER_DOWN_WAITING_OPEN;
			BGP_TIMER_OFF(peer->t_tracking_delay);
		} else
			peer->last_reset = PEER_DOWN_WAITING_NHT;

		if (!CHECK_FLAG(bnc->flags, BGP_NEXTHOP_PEER_NOTIFIED)) {
			if (BGP_DEBUG(nht, NHT))
				zlog_debug(
					"%s: Updating peer (%s(%s)) status with NHT nexthops %d",
					__func__, peer->host,
					peer->bgp->name_pretty,
					!!valid_nexthops);
			bgp_fsm_nht_update(peer->connection, !!valid_nexthops);
			SET_FLAG(bnc->flags, BGP_NEXTHOP_PEER_NOTIFIED);
		}
	}

	RESET_FLAG(bnc->change_flags);
}

/**
 * bgp_nht_update_paths_from_bnc - handle paths from each bnc
 * ARGUMENTS:
 * 	 bgp - pointer to the bgp structure
 *   table - pointer to the tree for nexthop lookup cache
 */
static void bgp_nht_update_paths_from_bnc(struct bgp *bgp,
						struct bgp_nexthop_cache_head *table)
{
	struct bgp_nexthop_cache *bnc;

	frr_each (bgp_nexthop_cache, table, bnc) {
		evaluate_paths(bnc);
	}
}

/**
 * bgp_nht_update_paths - update the existing path from bnc
 * ARGUMENTS:
 *   bgp - pointer to the bgp structure
 */
void bgp_nht_update_paths(struct bgp *bgp)
{
	if (!bgp)
		return;

	bgp_nht_update_paths_from_bnc(bgp, &bgp->nexthop_cache_table[AFI_IP]);
	bgp_nht_update_paths_from_bnc(bgp, &bgp->nexthop_cache_table[AFI_IP6]);
}

/**
 * path_nh_map - make or break path-to-nexthop association.
 * ARGUMENTS:
 *   path - pointer to the path structure
 *   bnc - pointer to the nexthop structure
 *   make - if set, make the association. if unset, just break the existing
 *          association.
 */
void path_nh_map(struct bgp_path_info *path, struct bgp_nexthop_cache *bnc,
		 bool make)
{
	if (path->nexthop) {
		LIST_REMOVE(path, nh_thread);
		path->nexthop->path_count--;
		path->nexthop = NULL;
	}
	if (make) {
		LIST_INSERT_HEAD(&(bnc->paths), path, nh_thread);
		path->nexthop = bnc;
		path->nexthop->path_count++;
	}
}

void path_tenh_map(struct bgp_path_info *path, struct bgp_nexthop_cache *te_bnc,
		 bool make)
{
	if (path->te_nexthop) {
		LIST_REMOVE(path, te_nh_thread);
		path->te_nexthop->path_count--;
		path->te_nexthop = NULL;
	}
	if (make) {
		LIST_INSERT_HEAD(&(te_bnc->paths), path, te_nh_thread);
		path->te_nexthop = te_bnc;
		path->te_nexthop->path_count++;
	}
}

void path_tebk_nh_map(struct bgp_path_info *path, struct bgp_nexthop_cache *te_bnc,
		 bool make)
{
	if (path->te_backup_nexthop) {
		LIST_REMOVE(path, tebk_nh_thread);
		path->te_backup_nexthop->path_count--;
		path->te_backup_nexthop = NULL;
	}
	if (make) {
		LIST_INSERT_HEAD(&(te_bnc->backup_paths), path, tebk_nh_thread);
		path->te_backup_nexthop = te_bnc;
		path->te_backup_nexthop->backup_path_count++;
	}
}

void peer_nh_map(struct peer *peer, struct bgp_nexthop_cache *bnc, afi_t afi, safi_t safi,
		 bool make)
{
    struct bgp_filter *filter;

	filter = &peer->filter[afi][safi];
	if (filter->advmap.condition_nexthop) {
		LIST_REMOVE(filter, nh_thread);
		filter->advmap.condition_nexthop->peerfilters_count--;
		filter->advmap.condition_nexthop = NULL;
        filter->peer = NULL;
	}
	if (make) {
		LIST_INSERT_HEAD(&(bnc->peer_filters), filter, nh_thread);
		filter->advmap.condition_nexthop = bnc;
		filter->advmap.condition_nexthop->peerfilters_count++;
        filter->peer = peer;
        filter->afi = afi;
        filter->safi = safi;
	}
}

/*
 * This function is called to register nexthops to zebra
 * as that we may have tried to install the nexthops
 * before we actually have a zebra connection
 */
void bgp_nht_register_nexthops(struct bgp *bgp)
{

	for (afi_t afi = AFI_IP; afi < AFI_MAX; afi++) {
		struct bgp_nexthop_cache *bic;

		frr_each (bgp_nexthop_cache, &bgp->import_check_table[afi],
			  bic) {
			register_zebra_rnh(bic);
		}
	}

	for (afi_t afi = AFI_IP; afi < AFI_MAX; afi++) {
		struct bgp_nexthop_cache *bnc;

		frr_each (bgp_nexthop_cache, &bgp->nexthop_cache_table[afi],
			  bnc) {
			register_zebra_rnh(bnc);
		}
	}

	for (afi_t afi = AFI_IP; afi < AFI_MAX; afi++) {
		struct bgp_nexthop_cache *bnc;

		frr_each (bgp_nexthop_cache, &bgp->condition_track_table[afi],
			  bnc) {
			register_zebra_rnh(bnc);
		}
	}
}

void bgp_nht_reg_enhe_cap_intfs(struct peer *peer)
{
	struct bgp *bgp;
	struct bgp_nexthop_cache *bnc;
	struct nexthop *nhop;
	struct interface *ifp;
	struct prefix p;

	if (peer->ifp)
		return;

	bgp = peer->bgp;
	if (!sockunion2hostprefix(&peer->connection->su, &p)) {
		zlog_warn("%s: Unable to convert sockunion to prefix for %s",
			  __func__, peer->host);
		return;
	}

	if (p.family != AF_INET6)
		return;

	bnc = bnc_find(&bgp->nexthop_cache_table[AFI_IP6], &p, 0, 0);
	if (!bnc)
		return;

	if (peer != bnc->nht_info)
		return;

	for (nhop = bnc->nexthop; nhop; nhop = nhop->next) {
		ifp = if_lookup_by_index(nhop->ifindex, nhop->vrf_id);

		if (!ifp)
			continue;

		zclient_send_interface_radv_req(zclient,
						nhop->vrf_id,
						ifp, true,
						BGP_UNNUM_DEFAULT_RA_INTERVAL);
	}
}

void bgp_nht_dereg_enhe_cap_intfs(struct peer *peer)
{
	struct bgp *bgp;
	struct bgp_nexthop_cache *bnc;
	struct nexthop *nhop;
	struct interface *ifp;
	struct prefix p;

	if (peer->ifp)
		return;

	bgp = peer->bgp;

	if (!sockunion2hostprefix(&peer->connection->su, &p)) {
		zlog_warn("%s: Unable to convert sockunion to prefix for %s",
			  __func__, peer->host);
		return;
	}

	if (p.family != AF_INET6)
		return;

	bnc = bnc_find(&bgp->nexthop_cache_table[AFI_IP6], &p, 0, 0);
	if (!bnc)
		return;

	if (peer != bnc->nht_info)
		return;

	for (nhop = bnc->nexthop; nhop; nhop = nhop->next) {
		ifp = if_lookup_by_index(nhop->ifindex, nhop->vrf_id);

		if (!ifp)
			continue;

		zclient_send_interface_radv_req(zclient, nhop->vrf_id, ifp, 0,
						0);
	}
}

/****************************************************************************
 * L3 NHGs are used for fast failover of nexthops in the dplane. These are
 * the APIs for allocating L3 NHG ids. Management of the L3 NHG itself is
 * left to the application using it.
 * PS: Currently EVPN host routes is the only app using L3 NHG for fast
 * failover of remote ES links.
 ***************************************************************************/
static bitfield_t bgp_nh_id_bitmap;
static uint32_t bgp_l3nhg_start;

/* XXX - currently we do nothing on the callbacks */
static void bgp_l3nhg_add_cb(const char *name)
{
}
static void bgp_l3nhg_add_nexthop_cb(const struct nexthop_group_cmd *nhgc,
				     const struct nexthop *nhop)
{
}
static void bgp_l3nhg_del_nexthop_cb(const struct nexthop_group_cmd *nhgc,
				     const struct nexthop *nhop)
{
}
static void bgp_l3nhg_del_cb(const char *name)
{
}

static void bgp_l3nhg_zebra_init(void)
{
	static bool bgp_l3nhg_zebra_inited;
	if (bgp_l3nhg_zebra_inited)
		return;

	bgp_l3nhg_zebra_inited = true;
	bgp_l3nhg_start = zclient_get_nhg_start(ZEBRA_ROUTE_BGP);
	nexthop_group_init(bgp_l3nhg_add_cb, bgp_l3nhg_add_nexthop_cb,
			   bgp_l3nhg_del_nexthop_cb, bgp_l3nhg_del_cb);
}


void bgp_l3nhg_init(void)
{
	uint32_t id_max;

	id_max = MIN(ZEBRA_NHG_PROTO_SPACING - 1, 16 * 1024);
	bf_init(bgp_nh_id_bitmap, id_max);
	bf_assign_zero_index(bgp_nh_id_bitmap);

	if (BGP_DEBUG(nht, NHT) || BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("bgp l3_nhg range %u - %u", bgp_l3nhg_start + 1,
			   bgp_l3nhg_start + id_max);
}

void bgp_l3nhg_finish(void)
{
	bf_free(bgp_nh_id_bitmap);
}

uint32_t bgp_l3nhg_id_alloc(void)
{
	uint32_t nhg_id = 0;

	bgp_l3nhg_zebra_init();
	bf_assign_index(bgp_nh_id_bitmap, nhg_id);
	if (nhg_id)
		nhg_id += bgp_l3nhg_start;

	return nhg_id;
}

void bgp_l3nhg_id_free(uint32_t nhg_id)
{
	if (!nhg_id || (nhg_id <= bgp_l3nhg_start))
		return;

	nhg_id -= bgp_l3nhg_start;

	bf_release_index(bgp_nh_id_bitmap, nhg_id);
}
