/*
 * Zebra connect code.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include "thread.h"
#include "command.h"
#include "network.h"
#include "prefix.h"
#include "routemap.h"
#include "table.h"
#include "srcdest_table.h"
#include "stream.h"
#include "memory.h"
#include "zclient.h"
#include "filter.h"
#include "plist.h"
#include "log.h"
#include "nexthop.h"
#include "nexthop_group.h"
#include "hash.h"
#include "jhash.h"

#include "static_vrf.h"
#include "static_routes.h"
#include "static_zebra.h"
#include "static_nht.h"
#include "static_vty.h"
#include "static_debug.h"

#define in6_is_addr_linklocal(a)        \
       (((a)->s6_addr[0] == 0xfe) && (((a)->s6_addr[1] & 0xc0) == 0x80))

/* Zebra structure to hold current status. */
struct zclient *zclient;
static struct hash *static_nht_hash;
uint32_t zebra_ecmp_count = MULTIPATH_NUM;

/* Inteface addition message from zebra. */
static int static_ifp_create(struct interface *ifp)
{
	static_ifindex_update(ifp, true);

	return 0;
}

static int static_ifp_destroy(struct interface *ifp)
{
	static_ifindex_update(ifp, false);
	return 0;
}

static int interface_address_add(ZAPI_CALLBACK_ARGS)
{
	zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);

	return 0;
}

static int interface_address_delete(ZAPI_CALLBACK_ARGS)
{
	struct connected *c;

	c = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);

	if (!c)
		return 0;

	connected_free(&c);
	return 0;
}

static int static_ifp_up(struct interface *ifp)
{
	/* Install any static reliant on this interface coming up */
	static_install_intf_nh(ifp);
	static_ifindex_update(ifp, true);

	return 0;
}

static int static_ifp_down(struct interface *ifp)
{
	static_ifindex_update(ifp, false);

	return 0;
}

static int route_notify_owner(ZAPI_CALLBACK_ARGS)
{
	struct prefix p;
	enum zapi_route_notify_owner note;
	uint32_t table_id;

	if (!zapi_route_notify_decode(zclient->ibuf, &p, &table_id, &note,
				      NULL, NULL))
		return -1;

	switch (note) {
	case ZAPI_ROUTE_FAIL_INSTALL:
		static_nht_mark_state(&p, vrf_id, STATIC_NOT_INSTALLED);
		zlog_warn("%s: Route %pFX failed to install for table: %u",
			  __func__, &p, table_id);
		break;
	case ZAPI_ROUTE_BETTER_ADMIN_WON:
		static_nht_mark_state(&p, vrf_id, STATIC_NOT_INSTALLED);
		zlog_warn(
			"%s: Route %pFX over-ridden by better route for table: %u",
			__func__, &p, table_id);
		break;
	case ZAPI_ROUTE_INSTALLED:
		static_nht_mark_state(&p, vrf_id, STATIC_INSTALLED);
		break;
	case ZAPI_ROUTE_REMOVED:
		static_nht_mark_state(&p, vrf_id, STATIC_NOT_INSTALLED);
		break;
	case ZAPI_ROUTE_REMOVE_FAIL:
		static_nht_mark_state(&p, vrf_id, STATIC_INSTALLED);
		zlog_warn("%s: Route %pFX failure to remove for table: %u",
			  __func__, &p, table_id);
		break;
	}

	return 0;
}
void static_zebra_register_neigh(vrf_id_t vrf_id, afi_t afi, bool reg)
{
	struct stream *s;

	if (!zclient || zclient->sock < 0)
		return;

	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s, reg ? ZEBRA_NHRP_NEIGH_REGISTER :
			      ZEBRA_NHRP_NEIGH_UNREGISTER,
			      vrf_id);
	stream_putw(s, afi);
	stream_putw_at(s, 0, stream_get_endp(s));
	zclient_send_message(zclient);
}

static void zebra_connected(struct zclient *zclient)
{
	zclient_send_reg_requests(zclient, VRF_DEFAULT);
	static_zebra_register_neigh(VRF_DEFAULT, AFI_IP, true);
	static_zebra_register_neigh(VRF_DEFAULT, AFI_IP6, true);
}

struct static_nht_data {
	struct prefix *nh;

	vrf_id_t nh_vrf_id;

	uint32_t refcount;
	uint8_t type;
	uint8_t nh_num;
	uint32_t color;
};

/* API to check whether the configured nexthop address is
 * one of its local connected address or not.
 */
static bool
static_nexthop_is_local(vrf_id_t vrfid, struct prefix *addr, int family)
{
	if (family == AF_INET) {
		if (if_address_is_local(&addr->u.prefix4, AF_INET, vrfid))
			return true;
	} else if (family == AF_INET6) {
		if (if_address_is_local(&addr->u.prefix6, AF_INET6, vrfid))
			return true;
	}
	return false;
}
static void static_gateway_update_nh(struct interface *ifp, 
				     struct route_node *rn,
				     struct static_path *pn,
				     struct static_nexthop *nh,
				     struct static_vrf *svrf, safi_t safi, bool add)
{
	ifindex_t tmp = 0;
	if(add)
	    tmp = ifp->ifindex;
	else
	    tmp = IFINDEX_INTERNAL;
	
	if (nh->ifindex != tmp){
		nh->ifindex = tmp;
		static_install_path(pn);
	}
}


static int static_neighbor_operation(ZAPI_CALLBACK_ARGS)
{
	union sockunion addr = {};
	struct interface *ifp;
	struct zapi_neigh_ip api = {};
	struct route_table *stable;
	struct route_node *rn;
	struct static_nexthop *nh;
	struct static_path *pn;
	struct vrf *vrf;
	struct static_route_info *si;
	safi_t safi;
	afi_t  afi; 
	bool add;

	zclient_neigh_ip_decode(zclient->ibuf, &api);
	if (api.ip_in.ipa_type != IPADDR_V6)
	{
		return 0;
	}

	ifp = if_lookup_by_index(api.index, vrf_id);
	if (!ifp)
		return 0;

	sockunion_family(&addr) = api.ip_in.ipa_type;
	memcpy((uint8_t *)sockunion_get_addr(&addr), &api.ip_in.ip.addr,
	       family2addrsize(api.ip_in.ipa_type));

	if (!in6_is_addr_linklocal(&addr.sin6.sin6_addr))
		return 0;

	afi  =  AFI_IP6;
	safi =  SAFI_UNICAST;

	if (api.ndm_state == NUD_FAILED || api.ndm_state == NUD_INCOMPLETE ) {
		add = false;
	}else {
		add = true;
	}

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		struct static_vrf *svrf;
		svrf = vrf->info;
		stable = static_vrf_static_table(afi, safi, svrf);
		if (!stable)
			continue;
		for (rn = route_top(stable); rn; rn = srcdest_route_next(rn)) {
			si = static_route_info_from_rnode(rn);
			if (!si)
				continue;
			frr_each(static_path_list, &si->path_list, pn) {
				frr_each(static_nexthop_list,
					  &pn->nexthop_list, nh) {
						if(nh->type == STATIC_IPV6_GATEWAY_IFNAME)
							if (memcmp(&addr.sin6.sin6_addr, &nh->addr.ipv6, 16) == 0)
					        		static_gateway_update_nh(ifp, rn,pn, nh, svrf,safi,add);
				}
			}
		}
	}
	return 0;
}

static int static_zebra_nexthop_update(ZAPI_CALLBACK_ARGS)
{
	struct static_nht_data *nhtd, lookup;
	struct zapi_route nhr;
	struct prefix matched;
	afi_t afi = AFI_IP;
	bool set_etag = false;

	if (!zapi_nexthop_update_decode(zclient->ibuf, &matched, &nhr)) {
		zlog_err("Failure to decode nexthop update message");
		return 1;
	}

	if (matched.family == AF_INET6)
		afi = AFI_IP6;

	if (nhr.type == ZEBRA_ROUTE_CONNECT) {
		if (static_nexthop_is_local(vrf_id, &matched,
					    nhr.prefix.family))
			nhr.nexthop_num = 0;
	} else if (nhr.type == ZEBRA_ROUTE_BGP){
		// it assume it is type 2 route as  nh. we set tag to let routemap to process 
		set_etag = true;
	}

	memset(&lookup, 0, sizeof(lookup));
	lookup.nh = &matched;
	lookup.nh_vrf_id = vrf_id;
	lookup.color = nhr.srte_color;

	nhtd = hash_lookup(static_nht_hash, &lookup);

	if (nhtd) {
		nhtd->nh_num = nhr.nexthop_num;
		/*
		* nexthop update event can't appear later. 
		* we should save nhr.type to nhtd for recognizing nexthop type
		*/
		nhtd->type = nhr.type;
		DEBUGD(&static_dbg_route,
		        "update nexthop(%pFX) nh_num %d  type %u", nhtd->nh,
		        nhtd->nh_num, nhtd->type);
		static_nht_reset_start(&matched, afi, nhtd->nh_vrf_id);
		static_nht_update(NULL, &matched, nhr.nexthop_num, afi,
				  nhtd->nh_vrf_id, set_etag, nhr.srte_color);
		if (afi == AFI_IP6) {
			static_nht_reset_start(&matched, AFI_IP, nhtd->nh_vrf_id);
			static_nht_update(NULL, &matched, nhr.nexthop_num, AFI_IP,
					  nhtd->nh_vrf_id, set_etag, nhr.srte_color);
		}
	} else
		zlog_err("No nhtd?");

	return 1;
}

static void static_zebra_capabilities(struct zclient_capabilities *cap)
{
	mpls_enabled = cap->mpls_enabled;
	zebra_ecmp_count = cap->ecmp;
}

static unsigned int static_nht_hash_key(const void *data)
{
	const struct static_nht_data *nhtd = data;
	unsigned int key = 0;

	key = prefix_hash_key(nhtd->nh);
	key = jhash_1word(nhtd->color, key);
	return jhash_1word(nhtd->nh_vrf_id, key);
}

static bool static_nht_hash_cmp(const void *d1, const void *d2)
{
	const struct static_nht_data *nhtd1 = d1;
	const struct static_nht_data *nhtd2 = d2;

	if (nhtd1->nh_vrf_id != nhtd2->nh_vrf_id)
		return false;
	if (nhtd1->color != nhtd2->color)
		return false;

	return prefix_same(nhtd1->nh, nhtd2->nh);
}

static void *static_nht_hash_alloc(void *data)
{
	struct static_nht_data *copy = data;
	struct static_nht_data *new;

	new = XMALLOC(MTYPE_TMP, sizeof(*new));

	new->nh = prefix_new();
	prefix_copy(new->nh, copy->nh);
	new->refcount = 0;
	new->nh_num = 0;
	new->nh_vrf_id = copy->nh_vrf_id;
	new->color = copy->color;

	return new;
}

static void static_nht_hash_free(void *data)
{
	struct static_nht_data *nhtd = data;

	prefix_free(&nhtd->nh);
	XFREE(MTYPE_TMP, nhtd);
}

void static_zebra_nht_register(struct static_nexthop *nh, bool reg)
{
	struct static_path *pn = nh->pn;
	struct route_node *rn = pn->rn;
	struct static_nht_data *nhtd, lookup;
	uint32_t cmd;
	struct prefix p;
	afi_t afi = AFI_IP;
	bool set_etag = false;

	cmd = (reg) ?
		ZEBRA_NEXTHOP_REGISTER : ZEBRA_NEXTHOP_UNREGISTER;

	if (nh->nh_registered && reg)
		return;

	if (!nh->nh_registered && !reg)
		return;

	memset(&p, 0, sizeof(p));
	switch (nh->type) {
	case STATIC_IFNAME:
	case STATIC_BLACKHOLE:
	case STATIC_IPV4_GATEWAY_EVPN:
	case STATIC_IPV6_GATEWAY_EVPN:
		return;
	case STATIC_IPV4_GATEWAY:
	case STATIC_IPV4_GATEWAY_IFNAME:
	case STATIC_IPV4_SEGMENTLIST:
		p.family = AF_INET;
		p.prefixlen = IPV4_MAX_BITLEN;
		p.u.prefix4 = nh->addr.ipv4;
		afi = AFI_IP;
		break;
	case STATIC_IPV6_GATEWAY:
	case STATIC_IPV6_GATEWAY_IFNAME:
	case STATIC_IPV6_SEGMENTLIST:
		p.family = AF_INET6;
		p.prefixlen = IPV6_MAX_BITLEN;
		p.u.prefix6 = nh->addr.ipv6;
		afi = AFI_IP6;
		break;
	}

	memset(&lookup, 0, sizeof(lookup));
	lookup.nh = &p;
	lookup.nh_vrf_id = nh->nh_vrf_id;
	lookup.color = nh->color;

	nh->nh_registered = reg;

	if (reg) {
		nhtd = hash_get(static_nht_hash, &lookup,
				static_nht_hash_alloc);
		nhtd->refcount++;

		DEBUGD(&static_dbg_route,
		        "Registered nexthop(%pFX) for %pRN %d ref %u type %u", &p, rn,
		        nhtd->nh_num, nhtd->refcount, nhtd->type);
		if (nhtd->type == ZEBRA_ROUTE_BGP)
			set_etag = true;
		if (nhtd->refcount > 1 && nhtd->nh_num) {
            if (nh->state == STATIC_NOT_INSTALLED ||
			    nh->state == STATIC_SENT_TO_ZEBRA)
				nh->state = STATIC_START;
			static_nht_update(&rn->p, nhtd->nh, nhtd->nh_num, afi,
					  nh->nh_vrf_id, set_etag, nh->color);
			if (afi == AFI_IP6) {
				static_nht_update(&rn->p, nhtd->nh, nhtd->nh_num, AFI_IP,
						  nhtd->nh_vrf_id, set_etag, nh->color);
			}
			return;
		}
	} else {
		nhtd = hash_lookup(static_nht_hash, &lookup);
		if (!nhtd)
			return;

		nhtd->refcount--;
		if (nhtd->refcount >= 1)
			return;

		hash_release(static_nht_hash, nhtd);
		static_nht_hash_free(nhtd);
	}
	if (nh->color) {
		struct zapi_color_para tmp = {0};
		tmp.srte_color = nh->color;
		tmp.srte_color_flag = 1;
		if (zclient_send_rnh(zclient, cmd, &p, false, false, nh->nh_vrf_id, NEXTHOP_REGISTER_TYPE_COLOR, &tmp)
		    == ZCLIENT_SEND_FAILURE)
			zlog_warn("%s: Failure to send nexthop to zebra", __func__);
	}
	else {
		if (zclient_send_rnh(zclient, cmd, &p, false, false, nh->nh_vrf_id, NEXTHOP_REGISTER_TYPE_DEFAULT, NULL)
		    == ZCLIENT_SEND_FAILURE)
			zlog_warn("%s: Failure to send nexthop to zebra", __func__);
	}
}


void get_static_nht_nh_rttype(struct route_node *rn, struct static_nexthop *nh, uint8_t *rttype)
{
	struct static_nht_data *nhtd, lookup;
	struct prefix p;

	DEBUGD(&static_dbg_route, "%pRN nh_type %u", rn, nh->type);

	memset(&p, 0, sizeof(p));
	switch (nh->type) {
	case STATIC_IFNAME:
	case STATIC_BLACKHOLE:
	case STATIC_IPV4_GATEWAY_EVPN:
	case STATIC_IPV6_GATEWAY_EVPN:
		return;
	case STATIC_IPV4_GATEWAY:
	case STATIC_IPV4_GATEWAY_IFNAME:
	case STATIC_IPV4_SEGMENTLIST:
		p.family = AF_INET;
		p.prefixlen = IPV4_MAX_BITLEN;
		p.u.prefix4 = nh->addr.ipv4;
		break;
	case STATIC_IPV6_GATEWAY:
	case STATIC_IPV6_GATEWAY_IFNAME:
	case STATIC_IPV6_SEGMENTLIST:
		p.family = AF_INET6;
		p.prefixlen = IPV6_MAX_BITLEN;
		p.u.prefix6 = nh->addr.ipv6;
		break;
	}

	memset(&lookup, 0, sizeof(lookup));
	lookup.nh = &p;
	lookup.nh_vrf_id = nh->nh_vrf_id;
	lookup.color = nh->color;


	nhtd = hash_get(static_nht_hash, &lookup,
			static_nht_hash_alloc);
	DEBUGD(&static_dbg_route,
		" get registered nexthop(%pFX) for %pRN %d ref %u type %u", &p, rn,
		nhtd->nh_num, nhtd->refcount, nhtd->type);
	*rttype = nhtd->type;
	return;
}
/*
 * When nexthop gets updated via configuration then use the
 * already registered NH and resend the route to zebra
 */
int static_zebra_nh_update(struct static_nexthop *nh)
{
	struct static_path *pn = nh->pn;
	struct route_node *rn = pn->rn;
	struct static_nht_data *nhtd, lookup = {};
	struct prefix p = {};
	afi_t afi = AFI_IP;
	bool set_etag = false;

	if (!nh->nh_registered)
		return 0;

	switch (nh->type) {
	case STATIC_IFNAME:
	case STATIC_BLACKHOLE:
    case STATIC_IPV4_GATEWAY_EVPN:
    case STATIC_IPV6_GATEWAY_EVPN:
		return 0;
	case STATIC_IPV4_GATEWAY:
	case STATIC_IPV4_GATEWAY_IFNAME:
	case STATIC_IPV4_SEGMENTLIST:
		p.family = AF_INET;
		p.prefixlen = IPV4_MAX_BITLEN;
		p.u.prefix4 = nh->addr.ipv4;
		afi = AFI_IP;
		break;
	case STATIC_IPV6_GATEWAY:
	case STATIC_IPV6_GATEWAY_IFNAME:
	case STATIC_IPV6_SEGMENTLIST:
		p.family = AF_INET6;
		p.prefixlen = IPV6_MAX_BITLEN;
		p.u.prefix6 = nh->addr.ipv6;
		afi = AFI_IP6;
		break;
	}

	lookup.nh = &p;
	lookup.nh_vrf_id = nh->nh_vrf_id;
	lookup.color = nh->color;

	nhtd = hash_lookup(static_nht_hash, &lookup);
	if (nhtd && nhtd->nh_num) {
		nh->state = STATIC_START;
		if (nhtd->type == ZEBRA_ROUTE_BGP)
		{
			set_etag = true;
		}
		static_nht_update(&rn->p, nhtd->nh, nhtd->nh_num, afi,
				  nh->nh_vrf_id, set_etag, nh->color);
		if (afi == AFI_IP6) {
			static_nht_update(&rn->p, nhtd->nh, nhtd->nh_num, AFI_IP,
					  nhtd->nh_vrf_id, set_etag, nh->color);
		}
		return 1;
	}
	return 0;
}

extern void static_zebra_route_add(struct static_path *pn, bool install, bool set_etag)

{
	struct route_node *rn = pn->rn;
	struct static_route_info *si = rn->info;
	struct static_nexthop *nh;
	const struct prefix *p, *src_pp;
	struct zapi_nexthop *api_nh;
	struct zapi_route api;
	uint32_t nh_num = 0;

	p = src_pp = NULL;
	srcdest_rnode_prefixes(rn, &p, &src_pp);

	memset(&api, 0, sizeof(api));
	api.vrf_id = si->svrf->vrf->vrf_id;
	api.type = ZEBRA_ROUTE_STATIC;
	api.safi = si->safi;
	memcpy(&api.prefix, p, sizeof(api.prefix));

	if (src_pp) {
		SET_FLAG(api.message, ZAPI_MESSAGE_SRCPFX);
		memcpy(&api.src_prefix, src_pp, sizeof(api.src_prefix));
	}
	SET_FLAG(api.flags, ZEBRA_FLAG_RR_USE_DISTANCE);
	SET_FLAG(api.flags, ZEBRA_FLAG_ALLOW_RECURSION);
	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
	if (pn->distance) {
		SET_FLAG(api.message, ZAPI_MESSAGE_DISTANCE);
		api.distance = pn->distance;
	}
	if (pn->tag) {
		SET_FLAG(api.message, ZAPI_MESSAGE_TAG);
		api.tag = pn->tag;
	}
	// if etag valid and set_flag is set, we set api tag to routemap process later.
	if (pn->etag && set_etag) {
		SET_FLAG(api.message, ZAPI_MESSAGE_TAG);
		api.tag = pn->etag;
	}
	if (pn->table_id != 0) {
		SET_FLAG(api.message, ZAPI_MESSAGE_TABLEID);
		api.tableid = pn->table_id;
	}
	frr_each(static_nexthop_list, &pn->nexthop_list, nh) {
		/* Don't overrun the nexthop array */
		if (nh_num == zebra_ecmp_count)
			break;

		api_nh = &api.nexthops[nh_num];
		if (nh->nh_vrf_id == VRF_UNKNOWN)
			continue;

		if ((install) && (nh->bfd_name[0])) {
			if ((nh->bfd_status.state == BFD_STATUS_DOWN) || (nh->bfd_status.state == BFD_STATUS_ADMIN_DOWN))
				continue;
		}

		if (pn->valid_srv6_nh && nh->type != STATIC_IPV4_SEGMENTLIST
			&& nh->type != STATIC_IPV6_SEGMENTLIST)
			continue;

		if (!pn->valid_srv6_nh && (nh->type == STATIC_IPV4_SEGMENTLIST
			|| nh->type == STATIC_IPV6_SEGMENTLIST))
			continue;

		api_nh->vrf_id = nh->nh_vrf_id;
		if (nh->onlink)
			SET_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_ONLINK);
		if (nh->color != 0) {
			SET_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_SRTE);
			api_nh->srte_color = nh->color;
			api_nh->srte_color_flag = 1;
		}

		nh->state = STATIC_SENT_TO_ZEBRA;

		switch (nh->type) {
		case STATIC_IFNAME:
			if (nh->ifindex == IFINDEX_INTERNAL)
				continue;
			api_nh->ifindex = nh->ifindex;
			api_nh->type = NEXTHOP_TYPE_IFINDEX;
			break;
		case STATIC_IPV4_GATEWAY:
			if (!nh->nh_valid)
				continue;
			api_nh->type = NEXTHOP_TYPE_IPV4;
			api_nh->gate = nh->addr;
			break;
		case STATIC_IPV4_GATEWAY_EVPN:
			if (nh->ifindex == IFINDEX_INTERNAL)
				continue;
			api_nh->ifindex = nh->ifindex;
			api_nh->type = NEXTHOP_TYPE_IPV4_IFINDEX;
			api_nh->gate = nh->addr;
			memcpy(&api_nh->rmac, &(nh->nh_rmac),
				sizeof(struct ethaddr));
			api_nh->vni = nh->nh_vni;
			SET_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_VNI);
			break;
		case STATIC_IPV4_GATEWAY_IFNAME:
			if (nh->ifindex == IFINDEX_INTERNAL)
				continue;
			api_nh->ifindex = nh->ifindex;
			api_nh->type = NEXTHOP_TYPE_IPV4_IFINDEX;
			api_nh->gate = nh->addr;
			break;
		case STATIC_IPV6_GATEWAY:
			if (!nh->nh_valid)
				continue;
			api_nh->type = NEXTHOP_TYPE_IPV6;
			api_nh->gate = nh->addr;
			break;
		case STATIC_IPV6_GATEWAY_EVPN:
			if (nh->ifindex == IFINDEX_INTERNAL)
				continue;
			api_nh->ifindex = nh->ifindex;
			api_nh->type = NEXTHOP_TYPE_IPV6_IFINDEX;
			api_nh->gate = nh->addr;
			memcpy(&api_nh->rmac, &(nh->nh_rmac),
				sizeof(struct ethaddr));
			api_nh->vni = nh->nh_vni;
			SET_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_VNI);
			break;
		case STATIC_IPV6_GATEWAY_IFNAME:
			if (nh->ifindex == IFINDEX_INTERNAL)
				continue;
			api_nh->type = NEXTHOP_TYPE_IPV6_IFINDEX;
			api_nh->ifindex = nh->ifindex;
			api_nh->gate = nh->addr;
			break;
		case STATIC_BLACKHOLE:
			api_nh->type = NEXTHOP_TYPE_BLACKHOLE;
			switch (nh->bh_type) {
			case STATIC_BLACKHOLE_DROP:
			case STATIC_BLACKHOLE_NULL:
				api_nh->bh_type = BLACKHOLE_NULL;
				break;
			case STATIC_BLACKHOLE_REJECT:
				api_nh->bh_type = BLACKHOLE_REJECT;
			}
			break;
		case STATIC_IPV6_SEGMENTLIST:
			if (!nh->nh_valid)
				continue;
			api_nh->type = NEXTHOP_TYPE_IPV6_SEGMENTLIST;
			api_nh->gate = nh->addr;
			break;
		case STATIC_IPV4_SEGMENTLIST:
			if (!nh->nh_valid)
				continue;
			api_nh->type = NEXTHOP_TYPE_IPV4_SEGMENTLIST;
			api_nh->gate = nh->addr;
			break;
		}


		if (nh->snh_label.num_labels) {
			int i;

			SET_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_LABEL);
			api_nh->label_num = nh->snh_label.num_labels;
			for (i = 0; i < api_nh->label_num; i++)
				api_nh->labels[i] = nh->snh_label.label[i];
		}
		nh_num++;
	}

	api.nexthop_num = nh_num;

	/*
	 * If we have been given an install but nothing is valid
	 * go ahead and delete the route for double plus fun
	 */
	if (!nh_num && install)
		install = false;
	DEBUGD(&static_dbg_route,
		        "route send prefix(%pFX) nh_num %d tag %u", &api.prefix,
		        api.nexthop_num, api.tag);

	zclient_route_send(install ?
			   ZEBRA_ROUTE_ADD : ZEBRA_ROUTE_DELETE,
			   zclient, &api);
}

static zclient_handler *const static_handlers[] = {
	[ZEBRA_INTERFACE_ADDRESS_ADD] = interface_address_add,
	[ZEBRA_INTERFACE_ADDRESS_DELETE] = interface_address_delete,
	[ZEBRA_ROUTE_NOTIFY_OWNER] = route_notify_owner,
	[ZEBRA_NEXTHOP_UPDATE] = static_zebra_nexthop_update,
	[ZEBRA_NHRP_NEIGH_ADDED] = static_neighbor_operation,
	[ZEBRA_NHRP_NEIGH_REMOVED] = static_neighbor_operation,
};

void static_zebra_init(void)
{
	struct zclient_options opt = { .receive_notify = true };

	hook_register_prio(if_real, 0, static_ifp_create);
	hook_register_prio(if_up, 0, static_ifp_up);
	hook_register_prio(if_down, 0, static_ifp_down);
	hook_register_prio(if_unreal, 0, static_ifp_destroy);

	zclient = zclient_new(master, &opt, static_handlers,
			      array_size(static_handlers));

	zclient_init(zclient, ZEBRA_ROUTE_STATIC, 0, &static_privs);
	zclient->zebra_capabilities = static_zebra_capabilities;
	zclient->zebra_connected = zebra_connected;

	static_nht_hash = hash_create(static_nht_hash_key,
				      static_nht_hash_cmp,
				      "Static Nexthop Tracking hash");
}

/* static_zebra_stop used by tests/lib/test_grpc.cpp */
void static_zebra_stop(void)
{
	if (!zclient)
		return;
	zclient_stop(zclient);
	zclient_free(zclient);
	zclient = NULL;
}

void static_zebra_vrf_register(struct vrf *vrf)
{
	if (vrf->vrf_id == VRF_DEFAULT)
		return;
	zclient_send_reg_requests(zclient, vrf->vrf_id);
}

void static_zebra_vrf_unregister(struct vrf *vrf)
{
	if (vrf->vrf_id == VRF_DEFAULT)
		return;
	zclient_send_dereg_requests(zclient, vrf->vrf_id);
}

static void show_static_nexthop_tracking_info(struct vty *vty, struct static_nht_data *nht)
{
	char buf[PREFIX_STRLEN];
	vty_out(vty, "Prefix: %s\n", prefix2str(nht->nh, buf, sizeof(buf)));
	vty_out(vty, "  Color: %d", nht->color);
	vty_out(vty, "  Nexthop Num: %d", nht->nh_num);
	vty_out(vty, "  RefCnt: %u", nht->refcount);
	vty_out(vty, "  Type: %u", nht->type);
	vty_out(vty, "  VRF: %s\n", vrf_id_to_name(nht->nh_vrf_id));
}

static int nht_show_walker(struct hash_bucket *bucket, void *arg)
{
	struct static_nht_show_context *ctx = arg;
	struct static_nht_data  *nht;

	nht = bucket->data; /* We won't be offered NULL buckets */

	if(!nht || !ctx){
		goto done;
	}

	if (ctx->afi && ( nht->nh->family != afi2family(ctx->afi))){
		goto done;
	}

	show_static_nexthop_tracking_info(ctx->vty, nht);

done:
	return HASHWALK_CONTINUE;
}

void show_static_nht_cmd_helper(struct vty *vty, afi_t afi)
{
	struct static_nht_show_context ctx;

	ctx.vty = vty;
	ctx.afi = afi;

	hash_walk(static_nht_hash, nht_show_walker, &ctx);
}

