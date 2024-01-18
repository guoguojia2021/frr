/* Zebra SR-TE code
 * Copyright (C) 2020  NetDEF, Inc.
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

#include "lib/zclient.h"
#include "lib/lib_errors.h"
#include "lib/nexthop.h"

#include "zebra/zebra_router.h"
#include "zebra/zebra_srte.h"
#include "zebra/zebra_mpls.h"
#include "zebra/zebra_rnh.h"
#include "zebra/zapi_msg.h"
#include "zebra/debug.h"
#include "zebra/zebra_nhg.h"
#include "zebra/zebra_nhg_private.h"

DEFINE_MTYPE_STATIC(ZEBRA, ZEBRA_SR_POLICY, "SR Policy");

static void zebra_sr_policy_deactivate(struct zebra_sr_policy *policy);

/* Generate rb-tree of SR Policy instances. */
static inline int
zebra_sr_policy_instance_compare(const struct zebra_sr_policy *a,
				 const struct zebra_sr_policy *b)
{
	return sr_policy_compare(&a->endpoint, &b->endpoint, a->color,
				 b->color);
}
RB_GENERATE(zebra_sr_policy_instance_head, zebra_sr_policy, entry,
	    zebra_sr_policy_instance_compare)

struct zebra_sr_policy_instance_head zebra_sr_policy_instances =
	RB_INITIALIZER(&zebra_sr_policy_instances);

struct zebra_sr_policy *zebra_sr_policy_add(uint32_t color,
					    struct ipaddr *endpoint, char *name)
{
	struct zebra_sr_policy *policy;

	policy = XCALLOC(MTYPE_ZEBRA_SR_POLICY, sizeof(*policy));
	policy->color = color;
	policy->endpoint = *endpoint;
	strlcpy(policy->name, name, sizeof(policy->name));
	policy->status = ZEBRA_SR_POLICY_UP;
	RB_INSERT(zebra_sr_policy_instance_head, &zebra_sr_policy_instances,
		  policy);

	return policy;
}

void zebra_sr_policy_del(struct zebra_sr_policy *policy)
{
	if (policy->status == ZEBRA_SR_POLICY_UP)
		zebra_sr_policy_deactivate(policy);
	RB_REMOVE(zebra_sr_policy_instance_head, &zebra_sr_policy_instances,
		  policy);
	XFREE(MTYPE_ZEBRA_SR_POLICY, policy);
}

struct zebra_sr_policy *zebra_sr_policy_find(uint32_t color,
					     struct ipaddr *endpoint)
{
	struct zebra_sr_policy policy = {};

	policy.color = color;
	policy.endpoint = *endpoint;
	return RB_FIND(zebra_sr_policy_instance_head,
		       &zebra_sr_policy_instances, &policy);
}

struct zebra_sr_policy *zebra_sr_policy_find_by_name(char *name)
{
	struct zebra_sr_policy *policy;

	// TODO: create index for policy names
	RB_FOREACH (policy, zebra_sr_policy_instance_head,
		    &zebra_sr_policy_instances) {
		if (strcmp(policy->name, name) == 0)
			return policy;
	}

	return NULL;
}

struct zebra_sr_policy *zebra_sr_policy_find_by_rnh(struct rnh *rnh)
{
    struct ipaddr ip = {0};
    if (!prefix2ipaddr(&rnh->node->p, &ip))
    {
        return zebra_sr_policy_find(rnh->srte_color, &ip);
    }
    return NULL;
}

static struct nhg_hash_entry *zebra_srv6_find_pic_nhe_by_policy(struct zebra_sr_policy *policy)
{
	vrf_id_t vrf_id = 0;
	bool ret = false;
	struct nexthop *nh = NULL;
	struct nhg_hash_entry lookup = {0};
	struct nhg_hash_entry *pic_nhe = NULL;

	vrf_id = policy->zvrf->vrf->vrf_id;

	/* Use a temporary nhe to find pic nh */
	lookup.type = ZEBRA_ROUTE_NHG;
	lookup.vrf_id = vrf_id;

	SET_FLAG(lookup.flags, NEXTHOP_GROUP_PIC_NHT);
	SET_FLAG(lookup.flags, NEXTHOP_GROUP_SEGMENTLIST);

    /* the nhg.nexthop is sorted */
	switch (policy->endpoint.ipa_type) {
	case IPADDR_V4:
		nh = nexthop_from_ipv4_segment_list(&policy->endpoint.ipaddr_v4, vrf_id);
		lookup.afi = AFI_IP;
		break;
	case IPADDR_V6:
		nh = nexthop_from_ipv6_segment_list(&policy->endpoint.ipaddr_v6, vrf_id);
		lookup.afi = AFI_IP6;
		break;
	default:
		return NULL;
	}

	nh->srte_color = policy->color;
	SET_FLAG(nh->flags, NEXTHOP_FLAG_ACTIVE);

	ret = nexthop_group_add_sorted_nodup(&lookup.nhg, nh);
	if (!ret) {
		nexthop_free(nh);
		return NULL;
	}
	pic_nhe = hash_lookup(zrouter.nhgs, &lookup);
	if (lookup.nhg.nexthop)
		nexthops_free(lookup.nhg.nexthop);

	return pic_nhe;
}

static struct nexthop *zebra_nhg_seg_update_nexthop(struct nexthop *nexthop,
	char *sidlist_name, bool add)
{
	struct nexthop *resolved_hop;
	struct nexthop *delete_hop;

	resolved_hop = nexthop_new();
	nexthop_copy_no_recurse(resolved_hop, nexthop, nexthop);

	memcpy(resolved_hop->sidlist_name, sidlist_name,
		SRTE_SEGMENTLIST_NAME_MAX_LENGTH);

	resolved_hop->flags = 0;
	SET_FLAG(resolved_hop->flags, NEXTHOP_FLAG_ACTIVE);

	if (add)
		_nexthop_add_sorted(&nexthop->resolved, resolved_hop);
	else {
		delete_hop = nexthop_exists_in_list(nexthop->resolved, resolved_hop);

		if (delete_hop)
			nexthop_del(&nexthop->resolved, resolved_hop);
		return delete_hop;
	}

	return resolved_hop;
}

static void zebra_nhg_seg_add_sidlist(struct nhg_hash_entry *nhe, struct zebra_sr_policy *policy,
	struct nexthop *nexthop, bool skip_update_depend)
{
	struct nexthop *add_hop = NULL;
	char *policy_sid_name = NULL;
	uint8_t path_num = 0;

	for(path_num = 0; path_num < policy->srv6_segment_list.path_num; path_num++) {
		if (!CHECK_FLAG(policy->srv6_segment_list.sidlists[path_num].type, SRV6_SID_LIST_ADD))
			continue;

		policy_sid_name = policy->srv6_segment_list.sidlists[path_num].sidlist_name;
		add_hop = zebra_nhg_seg_update_nexthop(nexthop, policy_sid_name, true);

		if (skip_update_depend) {
			if (IS_ZEBRA_DEBUG_NHG_DETAIL)
				zlog_debug("%s: nhe id %d add nexthop skip:%s", __func__,
					nhe->id, skip_update_depend ? "true":"false");
			continue;
		}

		if (add_hop->type == NEXTHOP_TYPE_IPV4_SEGMENTLIST)
			handle_recursive_segdepend(&nhe->nhg_segdepends, add_hop, AFI_IP, nhe->type, true);
		else
			handle_recursive_segdepend(&nhe->nhg_segdepends, add_hop, AFI_IP6, nhe->type, true);

		zebra_nhg_segment_depends(nhe, &nhe->nhg_segdepends);
	}
	return;
}

static void zebra_nhg_seg_del_sidlist(struct nhg_hash_entry *nhe, struct zebra_sr_policy *policy,
	struct nexthop *nexthop, bool skip_update_depend)
{
	struct nexthop *del_hop = NULL;
	struct nhg_segment *rb_node_dep = NULL;
	char *policy_sid_name = NULL;
	char *node_sid_name = NULL;
	uint8_t path_num = 0;

	for(path_num = 0; path_num < policy->srv6_segment_list.path_num_old; path_num++) {

		if (!CHECK_FLAG(policy->srv6_segment_list.sidlists_old[path_num].type, SRV6_SID_LIST_DEL))
			continue;

		policy_sid_name = policy->srv6_segment_list.sidlists_old[path_num].sidlist_name;
		del_hop = zebra_nhg_seg_update_nexthop(nexthop, policy_sid_name, false);

		if (del_hop == NULL)
			continue;

		if (IS_ZEBRA_DEBUG_NHG_DETAIL) {
			if (del_hop->type == NEXTHOP_TYPE_IPV4_SEGMENTLIST)
				zlog_debug("%s:nhe id %d delete nexthop %pI4 color %d", __func__, nhe->id,
					&del_hop->gate.ipv4, nexthop->srte_color);
			else
				zlog_debug("%s:nhe id %d delete nexthop %pI6 color %d", __func__, nhe->id,
					&del_hop->gate.ipv6, nexthop->srte_color);
		}

		if (skip_update_depend) {
			if (IS_ZEBRA_DEBUG_NHG_DETAIL)
				zlog_debug("%s: nhe id %d del nexthop skip:%s", __func__,
					nhe->id, skip_update_depend ? "true":"false");
			continue;
		}

		frr_each_safe(nhg_segment_tree, &nhe->nhg_segdepends, rb_node_dep) {
			node_sid_name = rb_node_dep->nhe->nhg.nexthop->sidlist_name;

			if (memcmp(node_sid_name, policy_sid_name, SRTE_SEGMENTLIST_NAME_MAX_LENGTH) == 0)
				zebra_nhg_seg_release(rb_node_dep->nhe);
		}
	}

	return;
}

static void zebra_nhg_seg_update_nhe(struct nhg_hash_entry *nhe,
	struct zebra_sr_policy *policy)
{

	struct nexthop *nexthop = NULL;
	bool skip_update_depend = false;
	int ret = 0;

	for (nexthop = nhe->nhg.nexthop; nexthop; nexthop = nexthop->next) {

		switch (policy->endpoint.ipa_type) {
		case IPADDR_V4:
			ret = memcmp(&nexthop->gate.ipv4, &policy->endpoint.ip._v4_addr, sizeof(struct in_addr));
			break;
		case IPADDR_V6:
			ret = memcmp(&nexthop->gate.ipv6, &policy->endpoint.ip._v6_addr, sizeof(struct in6_addr));
			break;
		default:
			continue;
		}
		if (ret != 0)
			continue;

		if (nexthop->next != NULL || nexthop->prev != NULL) {
			skip_update_depend = true;
		}
		if (IS_ZEBRA_DEBUG_NHG_DETAIL) {
			if (policy->endpoint.ipa_type == IPADDR_V4)
				zlog_debug("%s: update nhe id:%d gate:%pI4 color:%d", __func__, nhe->id,
					&nexthop->gate.ipv4, nexthop->srte_color);
			else
				zlog_debug("%s: update nhe id:%d gate:%pI6 color:%d", __func__, nhe->id,
					&nexthop->gate.ipv6, nexthop->srte_color);
		}

		zebra_nhg_seg_add_sidlist(nhe, policy, nexthop, skip_update_depend);
		zebra_nhg_seg_del_sidlist(nhe, policy, nexthop, skip_update_depend);

	}
}

static void zebra_nhg_install_nhe(struct nhg_hash_entry *nhe)
{
	UNSET_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED);
	zebra_nhg_seg_install_kernel(nhe);
}

static void zebra_nhe_seg_update(struct zebra_sr_policy *policy)
{
	struct nhg_hash_entry *picnhe = NULL;
	struct nhg_segment *rb_node_dep = NULL;

	if (policy == NULL)
		return;

	picnhe = zebra_srv6_find_pic_nhe_by_policy(policy);
	if (!picnhe) {
		return;
	}

	zebra_nhg_seg_update_nhe(picnhe, policy);
	zebra_nhg_install_nhe(picnhe);

	frr_each_safe(nhg_segment_tree, &picnhe->nhg_segdependents, rb_node_dep) {
		zebra_nhg_seg_update_nhe(rb_node_dep->nhe, policy);
		zebra_nhg_install_nhe(rb_node_dep->nhe);
	}

}

static void zebra_srv6_policy_down_update_pic_nhe(struct zebra_sr_policy *policy)
{
	struct nhg_hash_entry *picnhe = NULL;
	struct nhg_segment *rb_node_dep = NULL;

	picnhe = zebra_srv6_find_pic_nhe_by_policy(policy);
	if (!picnhe) {
		return;
	}

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: nhe id=%d flags=0x%x", __func__,
			picnhe->id, picnhe->flags);

	UNSET_FLAG(picnhe->flags, NEXTHOP_GROUP_VALID);

	frr_each_safe(nhg_segment_tree, &picnhe->nhg_segdepends, rb_node_dep) {
		UNSET_FLAG(rb_node_dep->nhe->flags, NEXTHOP_GROUP_VALID);
	}

	frr_each_safe(nhg_segment_tree, &picnhe->nhg_segdependents, rb_node_dep) {
		zebra_nhg_install_nhe(rb_node_dep->nhe);
	}
}

int zebra_sr_policy_notify_update_client(struct zebra_sr_policy *policy,
						struct zserv *client)
{
	const struct zebra_nhlfe *nhlfe;
	struct stream *s;
	uint32_t message = 0;
	unsigned long nump = 0;
	uint8_t num;
	struct zapi_nexthop znh;
	int ret;
	struct nexthop nh = {0};

	/* Get output stream. */
	s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, ZEBRA_NEXTHOP_UPDATE, zvrf_id(policy->zvrf));

	/* Message flags. */
	SET_FLAG(message, ZAPI_MESSAGE_SRTE);
	stream_putl(s, message);

	stream_putw(s, SAFI_UNICAST);
	/*
	 * The prefix is copied twice because the ZEBRA_NEXTHOP_UPDATE
	 * code was modified to send back both the matched against
	 * as well as the actual matched.  There does not appear to
	 * be an equivalent here so just send the same thing twice.
	 */
	switch (policy->endpoint.ipa_type) {
	case IPADDR_V4:
		stream_putw(s, AF_INET);
		stream_putc(s, IPV4_MAX_BITLEN);
		stream_put_in_addr(s, &policy->endpoint.ipaddr_v4);
		stream_putw(s, AF_INET);
		stream_putc(s, IPV4_MAX_BITLEN);
		stream_put_in_addr(s, &policy->endpoint.ipaddr_v4);
		break;
	case IPADDR_V6:
		stream_putw(s, AF_INET6);
		stream_putc(s, IPV6_MAX_BITLEN);
		stream_put(s, &policy->endpoint.ipaddr_v6, IPV6_MAX_BYTELEN);
		stream_putw(s, AF_INET6);
		stream_putc(s, IPV6_MAX_BITLEN);
		stream_put(s, &policy->endpoint.ipaddr_v6, IPV6_MAX_BYTELEN);
		break;
	default:
		flog_warn(EC_LIB_DEVELOPMENT,
			  "%s: unknown policy endpoint address family: %u",
			  __func__, policy->endpoint.ipa_type);
		exit(1);
	}
	stream_putl(s, policy->color);

    num = 0;
    if (policy->type == ZEBRA_SR_POLICY_TYPE_LSP)
    {
    	frr_each (nhlfe_list_const, &policy->lsp->nhlfe_list, nhlfe) {
    		if (!CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_SELECTED)
    		    || CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_DELETED))
    			continue;

    		if (num == 0) {
    			stream_putc(s, re_type_from_lsp_type(nhlfe->type));
    			stream_putw(s, 0); /* instance - not available */
    			stream_putc(s, nhlfe->distance);
    			stream_putl(s, 0); /* metric - not available */
    			nump = stream_get_endp(s);
    			stream_putc(s, 0);
    		}

    		zapi_nexthop_from_nexthop(&znh, nhlfe->nexthop);
    		ret = zapi_nexthop_encode(s, &znh, 0, message);
    		if (ret < 0)
    			goto failure;

    		num++;
    	}
    	stream_putc_at(s, nump, num);
    }
    else if (policy->type == ZEBRA_SR_POLICY_TYPE_SRV6)
    {
		stream_putc(s, ZEBRA_ROUTE_SRTE);
		stream_putw(s, 0); /* instance - not available */
		stream_putc(s, 0);/* distance - not available */
		stream_putl(s, 0); /* metric - not available */
		if (policy->status == ZEBRA_SR_POLICY_UP) {
			stream_putc(s, 1);
			memset(&nh, 0, sizeof(struct nexthop));
			nh.vrf_id = policy->zvrf->vrf->vrf_id;

			switch (policy->endpoint.ipa_type) {
				case IPADDR_V4:
					memcpy(&nh.gate.ipv4, &policy->endpoint.ipaddr_v4, sizeof(struct in_addr));
					nh.type = NEXTHOP_TYPE_IPV4_SEGMENTLIST;
					break;
				case IPADDR_V6:
					memcpy(&nh.gate.ipv6, &policy->endpoint.ipaddr_v6, sizeof(struct in6_addr));
					nh.type = NEXTHOP_TYPE_IPV6_SEGMENTLIST;
					break;
				default:
					flog_warn(EC_LIB_DEVELOPMENT,
						"%s: unknown policy endpoint address family: %u",
						__func__, policy->endpoint.ipa_type);
					exit(1);
			}
			zapi_nexthop_from_nexthop(&znh, &nh);
			ret = zapi_nexthop_encode(s, &znh, 0, message);
			if (ret < 0)
				goto failure;
		}
		else
			stream_putc(s, 0);
	}

    stream_putw_at(s, 0, stream_get_endp(s));
	client->nh_last_upd_time = monotime(NULL);
	return zserv_send_message(client, s);

failure:

	stream_free(s);
	return -1;
}

void zebra_sr_policy_notify_update(struct zebra_sr_policy *policy,
	struct zserv *zclient)
{
	struct rnh *rnh;
	struct prefix p = {};
	struct zebra_vrf *zvrf;
	struct listnode *node;
	struct zserv *client;

	zvrf = policy->zvrf;
	switch (policy->endpoint.ipa_type) {
	case IPADDR_V4:
		p.family = AF_INET;
		p.prefixlen = IPV4_MAX_BITLEN;
		p.u.prefix4 = policy->endpoint.ipaddr_v4;
		break;
	case IPADDR_V6:
		p.family = AF_INET6;
		p.prefixlen = IPV6_MAX_BITLEN;
		p.u.prefix6 = policy->endpoint.ipaddr_v6;
		break;
	default:
		flog_warn(EC_LIB_DEVELOPMENT,
			"%s: unknown policy endpoint address family: %u",
			__func__, policy->endpoint.ipa_type);
		exit(1);
	}

    rnh = zebra_lookup_rnh(&p, zvrf_id(zvrf), SAFI_UNICAST);
    if (!rnh)
        return;

    /* check color */
	for (; rnh; rnh = rnh->next)
		if (rnh->srte_color == policy->color)
			break;
	if (!rnh)
		return;

    if (zclient) {
		zebra_sr_policy_notify_update_client(policy, zclient);
	}

	if (policy->status == rnh->srp_status) {
		if (policy->status == ZEBRA_SR_POLICY_UP)
			zebra_nhe_seg_update(policy);

		return;
	}

	rnh->srp_status = policy->status;

	for (ALL_LIST_ELEMENTS_RO(rnh->client_list, node, client)) {
		zebra_sr_policy_notify_update_client(policy, client);
	}
}

int zebra_sr_policy_notify_unknown(struct rnh *rnh,
						struct zserv *client)
{
	struct stream *s;
	uint32_t message = 0;
    struct route_node *rn;

    rn = rnh->node;

	/* Get output stream. */
	s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, ZEBRA_NEXTHOP_UPDATE, rnh->vrf_id);

	/* Message flags. */
	SET_FLAG(message, ZAPI_MESSAGE_SRTE);
	stream_putl(s, message);
	stream_putw(s, rnh->safi);

	switch (rn->p.family) {
	case AF_INET:
		stream_putw(s, AF_INET);
		stream_putc(s, IPV4_MAX_BITLEN);
		stream_put_in_addr(s, &rn->p.u.prefix4);
		stream_putw(s, AF_INET);
		stream_putc(s, IPV4_MAX_BITLEN);
		stream_put_in_addr(s, &rn->p.u.prefix4);
		break;
	case AF_INET6:
		stream_putw(s, AF_INET6);
		stream_putc(s, IPV6_MAX_BITLEN);
		stream_put(s, &rn->p.u.prefix6, IPV6_MAX_BYTELEN);
		stream_putw(s, AF_INET6);
		stream_putc(s, IPV6_MAX_BITLEN);
		stream_put(s, &rn->p.u.prefix6, IPV6_MAX_BYTELEN);
		break;
	default:
		flog_warn(EC_LIB_DEVELOPMENT,
			  "%s: unknown policy endpoint address family: %u",
			  __func__, rn->p.family);
		exit(1);
	}

	stream_putl(s, rnh->srte_color);

    stream_putc(s, ZEBRA_ROUTE_SRTE);
	stream_putw(s, 0); /* instance - not available */
	stream_putc(s, 0);/* distance - not available */
	stream_putl(s, 0); /* metric - not available */
    /*set nexthop num to 0 */
    stream_putc(s, 0);

    stream_putw_at(s, 0, stream_get_endp(s));
	client->nh_last_upd_time = monotime(NULL);
	client->last_write_cmd = ZEBRA_NEXTHOP_UPDATE;
	return zserv_send_message(client, s);

}



static void zebra_sr_policy_activate(struct zebra_sr_policy *policy,
				     struct zebra_lsp *lsp)
{
	policy->status = ZEBRA_SR_POLICY_UP;
	policy->lsp = lsp;
	(void)zebra_sr_policy_bsid_install(policy);
	zsend_sr_policy_notify_status(policy->color, &policy->endpoint,
				      policy->name, ZEBRA_SR_POLICY_UP);
	zebra_sr_policy_notify_update(policy, NULL);
}

static void zebra_sr_policy_update(struct zebra_sr_policy *policy,
				   struct zebra_lsp *lsp,
				   struct zapi_srte_tunnel *old_tunnel)
{
	bool bsid_changed;
	bool segment_list_changed;

	policy->lsp = lsp;
    policy->type = ZEBRA_SR_POLICY_TYPE_LSP;

	bsid_changed =
		policy->segment_list.local_label != old_tunnel->local_label;
	segment_list_changed =
		policy->segment_list.label_num != old_tunnel->label_num
		|| memcmp(policy->segment_list.labels, old_tunnel->labels,
			  sizeof(mpls_label_t)
				  * policy->segment_list.label_num);

	/* Re-install label stack if necessary. */
	if (bsid_changed || segment_list_changed) {
		zebra_sr_policy_bsid_uninstall(policy, old_tunnel->local_label);
		(void)zebra_sr_policy_bsid_install(policy);
	}

	zsend_sr_policy_notify_status(policy->color, &policy->endpoint,
				      policy->name, ZEBRA_SR_POLICY_UP);

	/* Handle segment-list update. */
	if (segment_list_changed)
		zebra_sr_policy_notify_update(policy, NULL);
}

static bool zebra_srv6_policy_set_sidlist_type(struct zapi_srv6te_tunnel *te_tunnel,
	char *sidlist_name, uint32_t weight)
{
	for (uint32_t i = 0; i < te_tunnel->path_num_old; i++) {
		if (sidlist_name != NULL && strcmp(te_tunnel->sidlists_old[i].sidlist_name, sidlist_name) == 0) {
			if (te_tunnel->sidlists_old[i].weight != weight)
				SET_FLAG(te_tunnel->sidlists_old[i].type, SRV6_SID_LIST_UPDATE);
			UNSET_FLAG(te_tunnel->sidlists_old[i].type, SRV6_SID_LIST_DEL);
			return true;
		}
	}
	return false;
}

static bool zebra_srv6_policy_check_update(struct zapi_srv6te_tunnel *new_tunnel)
{
	uint8_t path_num = 0;
	uint8_t path_num_old = 0;
	bool segment_list_changed = false;
	bool find = false;

	for (path_num = 0; path_num < new_tunnel->path_num; path_num++) {
		find = zebra_srv6_policy_set_sidlist_type(new_tunnel, new_tunnel->sidlists[path_num].sidlist_name,
			new_tunnel->sidlists[path_num].weight);
		if (find == false) {
			SET_FLAG(new_tunnel->sidlists[path_num].type, SRV6_SID_LIST_ADD);
			segment_list_changed = true;
		}
	}
	if (segment_list_changed)
		return true;

	for(path_num_old = 0; path_num_old < new_tunnel->path_num_old; path_num_old++) {
		if (new_tunnel->sidlists_old[path_num_old].type != 0)
			return true;
	}

	return segment_list_changed;
}

static void zebra_srv6_clear_old_sidlist(struct zapi_srv6te_tunnel *new_tunnel)
{
	if (new_tunnel == NULL)
		return;

	memset(&new_tunnel->sidlists_old, 0,
		ZEBRA_SID_LIST_MAX_NUM * sizeof(struct zapi_srv6_active_sidlist));
	new_tunnel->path_num_old = 0;
}

void zebra_srv6_policy_validate(struct zebra_sr_policy *policy,
			     struct zapi_srv6te_tunnel *new_tunnel, bool new)
{
	uint8_t path_num = 0;
	bool segment_list_changed = false;

	zebra_srv6_clear_old_sidlist(new_tunnel);

	if (new == false) {
		for (path_num = 0; path_num < policy->srv6_segment_list.path_num; path_num++) {
			strlcpy(new_tunnel->sidlists_old[path_num].sidlist_name, policy->srv6_segment_list.sidlists[path_num].sidlist_name,
				sizeof(policy->srv6_segment_list.sidlists[path_num].sidlist_name));
			new_tunnel->sidlists_old[path_num].weight = policy->srv6_segment_list.sidlists[path_num].weight;
			SET_FLAG(new_tunnel->sidlists_old[path_num].type, SRV6_SID_LIST_DEL);
		}

		new_tunnel->path_num_old = policy->srv6_segment_list.path_num;
		segment_list_changed = zebra_srv6_policy_check_update(new_tunnel);
	}
	else
		segment_list_changed = true;

    policy->srv6_segment_list = *new_tunnel;
    policy->type = ZEBRA_SR_POLICY_TYPE_SRV6;

	/* Handle segment-list update. */
	if (segment_list_changed)
		zebra_sr_policy_notify_update(policy, NULL);
}


static void zebra_sr_policy_deactivate(struct zebra_sr_policy *policy)
{
	policy->status = ZEBRA_SR_POLICY_DOWN;
	policy->lsp = NULL;
    if (policy->type == ZEBRA_SR_POLICY_TYPE_LSP)
    {
        zebra_sr_policy_bsid_uninstall(policy, policy->segment_list.local_label);
    }

	if (policy->type == ZEBRA_SR_POLICY_TYPE_SRV6)
		zebra_srv6_policy_down_update_pic_nhe(policy);

	zsend_sr_policy_notify_status(policy->color, &policy->endpoint,
				      policy->name, ZEBRA_SR_POLICY_DOWN);
	zebra_sr_policy_notify_update(policy, NULL);
}

int zebra_sr_policy_validate(struct zebra_sr_policy *policy,
			     struct zapi_srte_tunnel *new_tunnel)
{
	struct zapi_srte_tunnel old_tunnel = policy->segment_list;
	struct zebra_lsp *lsp;

	if (new_tunnel)
		policy->segment_list = *new_tunnel;

	/* Try to resolve the Binding-SID nexthops. */
	lsp = mpls_lsp_find(policy->zvrf, policy->segment_list.labels[0]);
	if (!lsp || !lsp->best_nhlfe
	    || lsp->addr_family != ipaddr_family(&policy->endpoint)) {
		if (policy->status == ZEBRA_SR_POLICY_UP)
			zebra_sr_policy_deactivate(policy);
		return -1;
	}

	/* First label was resolved successfully. */
	if (policy->status == ZEBRA_SR_POLICY_DOWN)
		zebra_sr_policy_activate(policy, lsp);
	else
		zebra_sr_policy_update(policy, lsp, &old_tunnel);

	return 0;
}

int zebra_sr_policy_bsid_install(struct zebra_sr_policy *policy)
{
	struct zapi_srte_tunnel *zt = &policy->segment_list;
	struct zebra_nhlfe *nhlfe;

	if (zt->local_label == MPLS_LABEL_NONE)
		return 0;

	frr_each_safe (nhlfe_list, &policy->lsp->nhlfe_list, nhlfe) {
		uint8_t num_out_labels;
		mpls_label_t *out_labels;
		mpls_label_t null_label = MPLS_LABEL_IMPLICIT_NULL;

		if (!CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_SELECTED)
		    || CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_DELETED))
			continue;

		/*
		 * Don't push the first SID if the corresponding action in the
		 * LFIB is POP.
		 */
		if (!nhlfe->nexthop->nh_label
		    || !nhlfe->nexthop->nh_label->num_labels
		    || nhlfe->nexthop->nh_label->label[0]
			       == MPLS_LABEL_IMPLICIT_NULL) {
			if (zt->label_num > 1) {
				num_out_labels = zt->label_num - 1;
				out_labels = &zt->labels[1];
			} else {
				num_out_labels = 1;
				out_labels = &null_label;
			}
		} else {
			num_out_labels = zt->label_num;
			out_labels = zt->labels;
		}

		if (mpls_lsp_install(
			    policy->zvrf, zt->type, zt->local_label,
			    num_out_labels, out_labels, nhlfe->nexthop->type,
			    &nhlfe->nexthop->gate, nhlfe->nexthop->ifindex)
		    < 0)
			return -1;
	}

	return 0;
}

void zebra_sr_policy_bsid_uninstall(struct zebra_sr_policy *policy,
				    mpls_label_t old_bsid)
{
	struct zapi_srte_tunnel *zt = &policy->segment_list;

	mpls_lsp_uninstall_all_vrf(policy->zvrf, zt->type, old_bsid);
}

int zebra_sr_policy_label_update(mpls_label_t label,
				 enum zebra_sr_policy_update_label_mode mode)
{
	struct zebra_sr_policy *policy;

	RB_FOREACH (policy, zebra_sr_policy_instance_head,
		    &zebra_sr_policy_instances) {
		mpls_label_t next_hop_label;

		next_hop_label = policy->segment_list.labels[0];
		if (next_hop_label != label)
			continue;

		switch (mode) {
		case ZEBRA_SR_POLICY_LABEL_CREATED:
		case ZEBRA_SR_POLICY_LABEL_UPDATED:
		case ZEBRA_SR_POLICY_LABEL_REMOVED:
			zebra_sr_policy_validate(policy, NULL);
			break;
		}
	}

	return 0;
}

void zebra_srte_init(void)
{
}
