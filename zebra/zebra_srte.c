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

#include "lib/prefix.h"
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

struct hash *srte_table_hash = NULL;

#if 0
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
					    struct prefix *endpoint, char *name)
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

#endif

struct zebra_sr_policy *zebra_sr_policy_add_by_prefix(struct prefix *p, uint32_t color, char *name)
{
	struct route_node *rn;
	struct zebra_sr_policy *policy;
	struct srte_table_key srte_key = {0};
	struct srte_table_key *srte_key_table = NULL;

	srte_key.afi = family2afi(p->family);
	srte_key.color = color;

	srte_key_table = hash_get(srte_table_hash, &srte_key, srte_table_alloc);

	if (!srte_key_table || !srte_key_table->table) {
		return NULL;
	}

	/* Make it sure prefixlen is applied to the prefix. */
	apply_mask(p);

	/* Lookup (or add) route node.*/
	rn = route_node_get(srte_key_table->table, p);
	policy = rn->info;

	if (!policy) {
		policy = XCALLOC(MTYPE_ZEBRA_SR_POLICY, sizeof(struct zebra_sr_policy));
		route_lock_node(rn);
		policy->node = rn;
		policy->color = color;
		strlcpy(policy->name, name, sizeof(policy->name));
		rnh_srte_list_init(&policy->nht);
		rnh_backup_srte_list_init(&policy->backup_nht);
		rn->info = policy;
	}
	policy->status = ZEBRA_SR_POLICY_UP;

	route_unlock_node(rn);
	return policy;
}

struct zebra_sr_policy *zebra_sr_policy_lookup_by_prefix(struct prefix *p, uint32_t color)
{
	struct route_node *rn;
	struct srte_table_key srte_key = {0};
	struct srte_table_key *srte_key_table = NULL;

	srte_key.afi = family2afi(p->family);
	srte_key.color = color;

	srte_key_table = hash_lookup(srte_table_hash, &srte_key);
	if (!srte_key_table || !srte_key_table->table)
		return NULL;

	/* Make it sure prefixlen is applied to the prefix. */
	apply_mask(p);

	/* Lookup route node.*/
	rn = route_node_lookup(srte_key_table->table, p);
	if (!rn || !rn->info)
		return NULL;
	route_unlock_node(rn);
	return rn->info;
}

struct zebra_sr_policy *zebra_sr_policy_match_by_prefix(struct prefix *p, uint32_t color)
{
	struct route_node *rn;
	struct srte_table_key srte_key = {0};
	struct zebra_sr_policy *policy = NULL;
	struct srte_table_key *srte_key_table = NULL;

	srte_key.afi = family2afi(p->family);
	srte_key.color = color;

	srte_key_table = hash_lookup(srte_table_hash, &srte_key);
	if (!srte_key_table || !srte_key_table->table)
		return NULL;
	/* Make it sure prefixlen is applied to the prefix. */
	apply_mask(p);

	/* Lookup route node.*/
	rn = route_node_match(srte_key_table->table, p);
	if (!rn || !rn->info)
		return NULL;

	route_unlock_node(rn);
	while(rn) {
		policy = rn->info;
		if (policy && policy->status != ZEBRA_SR_POLICY_DOWN) {
			return policy;
		}
		rn = rn->parent;
	}

	return NULL;
}

void zebra_free_sr_table(struct route_table *table)
{
	struct route_node *rn;
	struct srte_table_key *srte_key_table = NULL;
	struct srte_table_key srte_key = {0};
	struct zebra_sr_policy *policyRoot = NULL;

	rn = route_top(table);
	policyRoot = rn->info;
	if (!policyRoot) {
		zlog_err("error sr-te table node!");
		return;
	}
	if (route_table_count(table) == 1 
		&& rnh_srte_list_count(&policyRoot->nht) == 0
		&& rnh_backup_srte_list_count(&policyRoot->backup_nht) == 0
		&& policyRoot->status == ZEBRA_SR_POLICY_INIT)
	{
		rnh_srte_list_fini(&policyRoot->nht);
		rnh_backup_srte_list_fini(&policyRoot->backup_nht);
		rn->info = NULL;
		srte_key.afi = family2afi(rn->p.family);
		srte_key.color = policyRoot->color;
		srte_key_table = hash_release(srte_table_hash, &srte_key);
		route_unlock_node(rn);
		route_table_finish(table);
		XFREE(MTYPE_ZEBRA_SR_POLICY, policyRoot);
		XFREE(MTYPE_ZEBRA_SR_POLICY, srte_key_table);
	}
}

void zebra_sr_policy_delete_by_prefix(struct zebra_sr_policy *policy)
{
	struct route_node *rn;
	struct route_table *table;

	if (policy->status == ZEBRA_SR_POLICY_UP)
		zebra_sr_policy_deactivate(policy);
	table = policy->node->table;

	if (!is_default_prefix(&policy->node->p)) {
		rn = policy->node;
		rnh_srte_list_fini(&policy->nht);
		rnh_backup_srte_list_fini(&policy->backup_nht);
		rn->info = NULL;
		XFREE(MTYPE_ZEBRA_SR_POLICY, policy);
		route_unlock_node(rn);
	}
	else {
		policy->type = 0;
		memset(&policy->binding_sid, 0, sizeof(mpls_label_t));
		memset(&policy->binding_v6_sid, 0, sizeof(struct zapi_srte_binding_sid));
		memset(&policy->segment_list, 0, sizeof(struct zapi_srte_tunnel));
		memset(&policy->srv6_segment_list, 0, sizeof(struct zapi_srv6te_tunnel));
	}
	zebra_free_sr_table(table);
}

static struct nexthop *zebra_nhg_seg_add_del_nexthop(struct nexthop *nexthop,
	char *sidlist_name, uint32_t discriminator, bool add,
	bool *skip_depend, bool is_backup, bool is_hidden)
{
	struct nexthop *resolved_hop = NULL;
	struct nexthop *exist_hop = NULL;
	char buf[NEXTHOP_STRLEN];

	if (IS_ZEBRA_DEBUG_SRV6)
		zlog_debug("%s: nexthop %s add %s sidlist_name %s(%u)", __func__,
			nexthop2str(nexthop, buf, sizeof(buf)),
			add ? "true" : "false", sidlist_name, discriminator);

	resolved_hop = nexthop_new();
	nexthop_copy_no_recurse(resolved_hop, nexthop, nexthop);

	strlcpy(resolved_hop->sidlist_name, sidlist_name,
		sizeof(resolved_hop->sidlist_name));

	exist_hop = nexthop_exists_in_list(nexthop->resolved, resolved_hop);

	if (add) {
		if (exist_hop) {
			if (IS_ZEBRA_DEBUG_NHT)
				zlog_debug("nexthop %s already exists", nexthop2str(resolved_hop, buf, sizeof(buf)));
			*skip_depend = true;
			nexthop_free(resolved_hop);
		} else {
			resolved_hop->my_discriminator = discriminator;
			resolved_hop->flags = 0;
			SET_FLAG(resolved_hop->flags, NEXTHOP_FLAG_ACTIVE);
			SET_FLAG(resolved_hop->flags, NEXTHOP_FLAG_SRV6_TUNNEL);
			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_DUPLICATE))
				SET_FLAG(resolved_hop->flags, NEXTHOP_FLAG_DUPLICATE);
			if (is_backup)
				SET_FLAG(resolved_hop->flags, NEXTHOP_FLAG_IS_BACKUP);
			if (is_hidden)
				SET_FLAG(resolved_hop->flags, NEXTHOP_FLAG_IS_HIDDEN);

			_nexthop_add_sorted(&nexthop->resolved, resolved_hop);
		}
	}
	else {
		if (exist_hop)
			nexthop_del(&nexthop->resolved, resolved_hop);
		return exist_hop;
	}

	return resolved_hop;
}

static void zebra_nhg_seg_add_sidlist(struct nhg_hash_entry *nhe, struct zebra_sr_policy *policy,
	uint8_t path_num, struct nexthop *nexthop, bool skip_update_depend)
{
	uint32_t discriminator = 0;
	bool is_backup = false;
	bool is_hidden = false;
	struct nexthop *add_hop = NULL;
	char *policy_sid_name = NULL;
	bool color_only = false;

	policy_sid_name = policy->srv6_segment_list.sidlists[path_num].sidlist_name;
	discriminator = policy->srv6_segment_list.sidlists[path_num].my_discriminator;
	if (CHECK_FLAG(policy->srv6_segment_list.sidlists[path_num].flags, SRV6_SID_LIST_BACKUP))
		is_backup = true;
	if (CHECK_FLAG(policy->srv6_segment_list.sidlists[path_num].flags, SRV6_SID_LIST_HIDDEN))
		is_hidden = true;

	add_hop = zebra_nhg_seg_add_del_nexthop(nexthop, policy_sid_name, discriminator,
		true, &skip_update_depend, is_backup, is_hidden);

	if (skip_update_depend) {
		if (IS_ZEBRA_DEBUG_SRV6)
			zlog_debug("%s: nhe id %d add nexthop skip:%s", __func__,
				nhe->id, skip_update_depend ? "true":"false");
		return;
	}
	if (CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_COLOR_ONLY))
		color_only = true;

	if (add_hop->type == NEXTHOP_TYPE_IPV4_SEGMENTLIST)
		handle_recursive_segdepend(&nhe->nhg_segdepends, add_hop, AFI_IP, nhe->type, true, color_only);
	else
		handle_recursive_segdepend(&nhe->nhg_segdepends, add_hop, AFI_IP6, nhe->type, true, color_only);

	zebra_nhg_segment_depends(nhe, &nhe->nhg_segdepends);
	nhe->uptime = monotime(NULL);
	return;
}

static void zebra_nhg_seg_update_nexthop_content(struct nexthop *nexthop,
	uint32_t discriminator, bool is_backup, bool is_hidden)
{
	if (nexthop == NULL)
		return;

	if (IS_ZEBRA_DEBUG_SRV6) {
		if (nexthop->type == NEXTHOP_TYPE_IPV4_SEGMENTLIST)
			zlog_debug("%s:update nexthop %pI4 color %d sidlist %s backup %s",
				__func__, &nexthop->gate.ipv4, nexthop->srte_color, nexthop->sidlist_name,
				is_backup ? "true":"false");
		else
			zlog_debug("%s:update nexthop %pI6 color %d sidlist %s backup %s",
				__func__, &nexthop->gate.ipv6, nexthop->srte_color, nexthop->sidlist_name,
				is_backup ? "true":"false");
	}
	nexthop->my_discriminator = discriminator;
	if (is_backup)
		SET_FLAG(nexthop->flags, NEXTHOP_FLAG_IS_BACKUP);
	else
		UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_IS_BACKUP);

	if (is_hidden)
		SET_FLAG(nexthop->flags, NEXTHOP_FLAG_IS_HIDDEN);
	else
		UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_IS_HIDDEN);
	return;
}
static void zebra_nhg_seg_update_nexthop_resolved(struct nexthop *nexthop,
	char *sidlist_name, uint32_t discriminator, bool is_backup, bool is_hidden)
{
	struct nexthop *nh = NULL;
	for (nh = nexthop; nh; nh = nexthop_next_no_upward(nh)) {
		if (strncmp(nh->sidlist_name, sidlist_name, sizeof(nh->sidlist_name)) == 0) {
			zebra_nhg_seg_update_nexthop_content(nh, discriminator, is_backup, is_hidden);
		}
	}
}

static void zebra_nhg_seg_update_depend(struct nhg_hash_entry *nhe, struct nexthop *nexthop,
	char *policy_sid_name, uint32_t discriminator, bool is_backup, bool is_hidden)
{
	struct nexthop * nh = NULL;
	struct nhg_segment *rb_node_dep = NULL;
	frr_each_safe(nhg_segment_tree, &nhe->nhg_segdepends, rb_node_dep) {
		for (nh = rb_node_dep->nhe->nhg.nexthop; nh; nh = nh->next) {

			bool matches = false;

			if (nh->type == NEXTHOP_TYPE_IPV4_SEGMENTLIST) {
				matches = IPV4_ADDR_SAME(&nh->gate.ipv4, &nexthop->gate.ipv4);
			}
			else if (nh->type == NEXTHOP_TYPE_IPV6_SEGMENTLIST) {
				matches = IPV6_ADDR_SAME(&nh->gate.ipv6, &nexthop->gate.ipv6);
			}
			if (nh->srte_color != nexthop->srte_color)
				matches = false;

			if (!matches)
				continue;

			if (IS_ZEBRA_DEBUG_SRV6) {
				if (nh->type == NEXTHOP_TYPE_IPV4_SEGMENTLIST)
					zlog_debug("%s:nhe id %d update nexthop %pI4 color %d sidlist %s backup %s",
						__func__, nhe->id, &nh->gate.ipv4, nh->srte_color, policy_sid_name,
						is_backup ? "true":"false");
				else
					zlog_debug("%s:nhe id %d update nexthop %pI6 color %d sidlist %s backup %s",
						__func__, nhe->id, &nh->gate.ipv6, nh->srte_color, policy_sid_name,
						is_backup ? "true":"false");
			}
			if (strncmp(nh->sidlist_name, policy_sid_name, sizeof(nh->sidlist_name)) == 0) {
				zebra_nhg_seg_update_nexthop_content(nh, discriminator, is_backup, is_hidden);
				return;
			}
		}
	}
	return;
}

static void zebra_nhg_seg_update_dependent(struct nhg_hash_entry *nhe, struct nexthop *nexthop,
	char *policy_sid_name, uint32_t discriminator, bool is_backup, bool is_hidden)
{
	struct nexthop *nh = NULL;
	struct nexthop *nh_res = NULL;
	struct nhg_segment *rb_node_depent = NULL;

	frr_each_safe(nhg_segment_tree, &nhe->nhg_segdependents, rb_node_depent) {
		for (nh = rb_node_depent->nhe->nhg.nexthop; nh; nh = nh->next) {

			bool matches = false;
			if (nh->type == NEXTHOP_TYPE_IPV4_SEGMENTLIST) {
				matches = IPV4_ADDR_SAME(&nh->gate.ipv4, &nexthop->gate.ipv4);
			}
			else if (nh->type == NEXTHOP_TYPE_IPV6_SEGMENTLIST) {
				matches = IPV6_ADDR_SAME(&nh->gate.ipv6, &nexthop->gate.ipv6);
			}

			if (nh->srte_color != nexthop->srte_color)
				matches = false;

			if (!matches)
				continue;

			if (IS_ZEBRA_DEBUG_SRV6) {
				if (nh->type == NEXTHOP_TYPE_IPV4_SEGMENTLIST)
					zlog_debug("%s:nhe id %d update nexthop %pI4 color %d sidlist %s backup %s",
						__func__, nhe->id, &nh->gate.ipv4, nh->srte_color, policy_sid_name,
						is_backup ? "true":"false");
				else
					zlog_debug("%s:nhe id %d update nexthop %pI6 color %d sidlist %s backup %s",
						__func__, nhe->id, &nh->gate.ipv6, nh->srte_color, policy_sid_name,
						is_backup ? "true":"false");
			}

			for (nh_res = nh->resolved; nh_res; nh_res = nexthop_next_no_upward(nh_res)) {
				if (strncmp(nh_res->sidlist_name, policy_sid_name, sizeof(nh_res->sidlist_name)) == 0) {
					zebra_nhg_seg_update_nexthop_content(nh_res, discriminator, is_backup, is_hidden);
					continue;
				}
			}
		}
	}
}
static void zebra_nhg_seg_update_sidlist(struct nhg_hash_entry *nhe, struct zebra_sr_policy *policy,
	uint8_t path_num, struct nexthop *nexthop, bool skip_depend)
{
	uint32_t discriminator = 0;
	bool is_backup = false;
	bool is_hidden = false;
	char *policy_sid_name = NULL;

	policy_sid_name = policy->srv6_segment_list.sidlists[path_num].sidlist_name;
	discriminator = policy->srv6_segment_list.sidlists[path_num].my_discriminator;
	if (CHECK_FLAG(policy->srv6_segment_list.sidlists[path_num].flags, SRV6_SID_LIST_BACKUP))
		is_backup = true;
	if (CHECK_FLAG(policy->srv6_segment_list.sidlists[path_num].flags, SRV6_SID_LIST_HIDDEN))
		is_hidden = true;
	zebra_nhg_seg_update_nexthop_resolved(nexthop, policy_sid_name, discriminator, is_backup, is_hidden);

	if (skip_depend)
		return;
	/* update depends nhe*/
	zebra_nhg_seg_update_depend(nhe, nexthop, policy_sid_name, discriminator, is_backup, is_hidden);
	zebra_nhg_seg_update_dependent(nhe, nexthop, policy_sid_name, discriminator, is_backup, is_hidden);
	nhe->uptime = monotime(NULL);
}
static void zebra_nhg_seg_add_and_update_sidlist(struct nhg_hash_entry *nhe, struct zebra_sr_policy *policy,
	struct nexthop *nexthop, bool skip_depend)
{
	uint8_t path_num = 0;
	char endpoint[PREFIX_STRLEN];
	prefix2str(&policy->node->p, endpoint, sizeof(endpoint));

	for(path_num = 0; path_num < policy->srv6_segment_list.path_num; path_num++) {
		if (CHECK_FLAG(policy->srv6_segment_list.sidlists[path_num].flags, SRV6_SID_LIST_ADD)) {
			zebra_nhg_seg_add_sidlist(nhe, policy, path_num, nexthop, skip_depend);
			continue;
		}
		if (CHECK_FLAG(policy->srv6_segment_list.sidlists[path_num].flags, SRV6_SID_LIST_UPDATE)) {
			zebra_nhg_seg_update_sidlist(nhe, policy, path_num, nexthop, skip_depend);
			continue;
		}
		if (IS_ZEBRA_DEBUG_SRV6)
			zlog_debug("%s: nhe id %d endpoint %s color %u sidlist %s not change", __func__,
				nhe->id, endpoint, policy->color, policy->srv6_segment_list.sidlists[path_num].sidlist_name);
	}
	return;
}

static void zebra_nhg_seg_del_sidlist(struct nhg_hash_entry *nhe, struct zebra_sr_policy *policy,
	struct nexthop *nexthop, bool skip_depend)
{
	uint8_t path_num = 0;
	uint32_t discriminator = 0;
	char *node_sid_name = NULL;
	char *policy_sid_name = NULL;
	struct nexthop *del_hop = NULL;
	struct nhg_segment *rb_node_dep = NULL;
	char endpoint[PREFIX_STRLEN];
	prefix2str(&policy->node->p, endpoint, sizeof(endpoint));

	for(path_num = 0; path_num < policy->srv6_segment_list.path_num_old; path_num++) {

		if (!CHECK_FLAG(policy->srv6_segment_list.sidlists_old[path_num].flags, SRV6_SID_LIST_DEL))
			continue;

		policy_sid_name = policy->srv6_segment_list.sidlists_old[path_num].sidlist_name;
		discriminator = policy->srv6_segment_list.sidlists_old[path_num].my_discriminator;
		del_hop = zebra_nhg_seg_add_del_nexthop(nexthop, policy_sid_name, discriminator, false, &skip_depend, false, false);
		if (del_hop == NULL)
			continue;

		if (IS_ZEBRA_DEBUG_SRV6) {
			if (del_hop->type == NEXTHOP_TYPE_IPV4_SEGMENTLIST)
				zlog_debug("%s:nhe id %d delete nexthop %pI4 color %d", __func__, nhe->id,
					&del_hop->gate.ipv4, nexthop->srte_color);
			else
				zlog_debug("%s:nhe id %d delete nexthop %pI6 color %d", __func__, nhe->id,
					&del_hop->gate.ipv6, nexthop->srte_color);
		}
		nexthop_free(del_hop);
		if (skip_depend) {
			if (IS_ZEBRA_DEBUG_SRV6)
				zlog_debug("%s: nhe id %d del nexthop skip:%s", __func__,
					nhe->id, skip_depend ? "true":"false");
			continue;
		}

		frr_each_safe(nhg_segment_tree, &nhe->nhg_segdepends, rb_node_dep) {
			node_sid_name = rb_node_dep->nhe->nhg.nexthop->sidlist_name;

			if (strncmp(node_sid_name, policy_sid_name, sizeof(rb_node_dep->nhe->nhg.nexthop->sidlist_name)) == 0)
				zebra_nhg_seg_decrement_ref(rb_node_dep->nhe);
		}
		nhe->uptime = monotime(NULL);
	}

	return;
}

static void zebra_nhg_seg_update_nhe(struct nhg_hash_entry *nhe,
	struct rnh *rnh, struct zebra_sr_policy *policy,
	bool skip_depend, bool backup)
{
	struct nexthop *nexthop = NULL;
	struct prefix *p = &rnh->node->p;
	uint32_t color = 0;
	if (backup)
		color = rnh->srte_backup_color;
	else
		color = rnh->srte_color;

	for (nexthop = nhe->nhg.nexthop; nexthop; nexthop = nexthop->next) {
		/* Check if nexthop matches the prefix */
		bool matches = false;
		switch (p->family) {
		case AF_INET:
			matches = IPV4_ADDR_SAME(&nexthop->gate.ipv4, &p->u.prefix4);
			break;
		case AF_INET6:
			matches = IPV6_ADDR_SAME(&nexthop->gate.ipv6, &p->u.prefix6);
			break;
		default:
			continue;
		}

		if (nexthop->srte_color != color)
			matches = false;

		if (!matches)
			continue;

		/* Set skip_depend if there are multiple nexthops */
		bool local_skip_depend = skip_depend || (nexthop->next != NULL || nexthop->prev != NULL);

		if (IS_ZEBRA_DEBUG_SRV6) {
			if (p->family == AF_INET)
				zlog_debug("%s: update nhe id:%d gate:%pI4 color:%d", __func__, nhe->id,
					&nexthop->gate.ipv4, nexthop->srte_color);
			else
				zlog_debug("%s: update nhe id:%d gate:%pI6 color:%d", __func__, nhe->id,
					&nexthop->gate.ipv6, nexthop->srte_color);
		}

		zebra_nhg_seg_add_and_update_sidlist(nhe, policy, nexthop, local_skip_depend);
		zebra_nhg_seg_del_sidlist(nhe, policy, nexthop, local_skip_depend);
	}
}

static void zebra_nhg_install_nhe(struct nhg_hash_entry *nhe)
{
	UNSET_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED);
	zebra_nhg_seg_install_kernel(nhe);
}

static struct nhg_hash_entry *zebra_find_pic_nhe(struct zebra_sr_policy *policy, struct rnh *rnh)
{
    struct prefix *p = &rnh->node->p;
    struct nexthop *nh = NULL;
    struct nhg_hash_entry lookup = {0};
    struct nhg_hash_entry *pic_nhe = NULL;
    vrf_id_t vrf_id = policy->zvrf->vrf->vrf_id;
    int ret;

    /* Use a temporary nhe to find pic nh */
    lookup.type = ZEBRA_ROUTE_NHG;
    lookup.vrf_id = vrf_id;
    SET_FLAG(lookup.flags, NEXTHOP_GROUP_PIC_NHT);
    SET_FLAG(lookup.flags, NEXTHOP_GROUP_SEGMENTLIST);
	if (CHECK_FLAG(policy->flags, ZEBRA_SR_POLICY_FLAG_COLOR_ONLY))
		SET_FLAG(lookup.flags, NEXTHOP_GROUP_COLOR_ONLY);

    switch (p->family) {
    case AF_INET:
        nh = nexthop_from_ipv4_segment_list(&p->u.prefix4, vrf_id);
        lookup.afi = AFI_IP;
        break;
    case AF_INET6:
        nh = nexthop_from_ipv6_segment_list(&p->u.prefix6, vrf_id);
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

static void zebra_nhe_seg_update(struct zebra_sr_policy *policy)
{
    struct nhg_hash_entry *picnhe = NULL;
    struct nhg_segment *rb_node_dep = NULL;
    struct rnh *rnh = NULL;
    struct rnh *backup_rnh = NULL;

    if (!policy)
        return;

    frr_each_safe(rnh_srte_list, &policy->nht, rnh) {
        picnhe = zebra_find_pic_nhe(policy, rnh);
        if (!picnhe)
            continue;

        /* Update the main NHE */
        zebra_nhg_seg_update_nhe(picnhe, rnh, policy, false, false);

        /* Mark all dependent NHEs as not installed */
        frr_each_safe(nhg_segment_tree, &picnhe->nhg_segdepends, rb_node_dep) {
            UNSET_FLAG(rb_node_dep->nhe->flags, NEXTHOP_GROUP_INSTALLED);
        }

        /* Install the main NHE */
        zebra_nhg_install_nhe(picnhe);

        if (IS_ZEBRA_DEBUG_SRV6) {
            zlog_debug("%s: nhe id %d update flags 0x%x", __func__,
                picnhe->id, picnhe->flags);
        }

        /* pdate and install all dependent NHEs */
        frr_each_safe(nhg_segment_tree, &picnhe->nhg_segdependents, rb_node_dep) {
            zebra_nhg_seg_update_nhe(rb_node_dep->nhe, rnh, policy, true, false);
            zebra_nhg_install_nhe(rb_node_dep->nhe);
        }
    }
	/* process backup nht */
    frr_each_safe(rnh_backup_srte_list, &policy->backup_nht, backup_rnh) {
        picnhe = zebra_find_pic_nhe(policy, backup_rnh);
        if (!picnhe)
            continue;

        /* Update the main NHE */
        zebra_nhg_seg_update_nhe(picnhe, backup_rnh, policy, false, true);

        /* Mark all dependent NHEs as not installed */
        frr_each_safe(nhg_segment_tree, &picnhe->nhg_segdepends, rb_node_dep) {
            UNSET_FLAG(rb_node_dep->nhe->flags, NEXTHOP_GROUP_INSTALLED);
        }

        /* Install the main NHE */
        zebra_nhg_install_nhe(picnhe);

        if (IS_ZEBRA_DEBUG_SRV6) {
            zlog_debug("%s: nhe id %d update flags 0x%x", __func__,
                picnhe->id, picnhe->flags);
        }

        /* pdate and install all dependent NHEs */
        frr_each_safe(nhg_segment_tree, &picnhe->nhg_segdependents, rb_node_dep) {
            zebra_nhg_seg_update_nhe(rb_node_dep->nhe, backup_rnh, policy, true, true);
            zebra_nhg_install_nhe(rb_node_dep->nhe);
        }
    }
}

static void zebra_srv6_policy_down_update_pic_nhe(struct zebra_sr_policy *policy)
{
    struct nhg_hash_entry *picnhe = NULL;
    struct nhg_segment *rb_node_dep = NULL;
    struct rnh *rnh = NULL;
    struct rnh *backup_rnh = NULL;

    frr_each_safe(rnh_srte_list, &policy->nht, rnh) {
        picnhe = zebra_find_pic_nhe(policy, rnh);
        if (!picnhe)
            continue;

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
	/* process backup nht */
    frr_each_safe(rnh_backup_srte_list, &policy->backup_nht, backup_rnh) {
        picnhe = zebra_find_pic_nhe(policy, backup_rnh);
        if (!picnhe)
            continue;

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
}

static void zebra_sr_policy_activate(struct zebra_sr_policy *policy,
				     struct zebra_lsp *lsp)
{
	policy->status = ZEBRA_SR_POLICY_UP;
	policy->lsp = lsp;
	(void)zebra_sr_policy_bsid_install(policy);
	zsend_sr_policy_notify_status(policy->color, policy->node,
				      policy->name, ZEBRA_SR_POLICY_UP);
	zebra_srte_evaluate_rn_nexthops(policy, zebra_router_get_next_sequence(), false);
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

	zsend_sr_policy_notify_status(policy->color, policy->node,
				      policy->name, ZEBRA_SR_POLICY_UP);

	/* Handle segment-list update. */
	if (segment_list_changed)
		zebra_srte_evaluate_rn_nexthops(policy, zebra_router_get_next_sequence(), false);
}

static void zebra_srv6_policy_set_sidlist_type(struct zapi_srv6te_tunnel *te_tunnel, uint8_t path_num)
{
	uint8_t path_num_old = 0;
	bool find_flag = false;
	char sidlist_name_old[SRTE_SEGMENTLIST_NAME_MAX_LENGTH] = {0};

	for (path_num_old = 0; path_num_old < te_tunnel->path_num_old; path_num_old++) {

		strlcpy(sidlist_name_old, te_tunnel->sidlists_old[path_num_old].sidlist_name,
			sizeof(sidlist_name_old));

		if (strcmp(sidlist_name_old, te_tunnel->sidlists[path_num].sidlist_name) == 0) {
			UNSET_FLAG(te_tunnel->sidlists_old[path_num_old].flags, SRV6_SID_LIST_DEL);

			if (IS_ZEBRA_DEBUG_SRV6) {
				zlog_debug("%s: name %s, discriminator %u(%u), flags %x(%x), weight %u(%u)", __func__,
				te_tunnel->sidlists[path_num].sidlist_name, te_tunnel->sidlists[path_num].my_discriminator,
				te_tunnel->sidlists_old[path_num_old].my_discriminator, te_tunnel->sidlists[path_num].flags,
				te_tunnel->sidlists_old[path_num_old].flags, te_tunnel->sidlists[path_num].weight,
				te_tunnel->sidlists_old[path_num_old].weight);
			}

			if (te_tunnel->sidlists_old[path_num_old].weight != te_tunnel->sidlists[path_num].weight)
				SET_FLAG(te_tunnel->sidlists[path_num].flags, SRV6_SID_LIST_UPDATE);
			else if (te_tunnel->sidlists_old[path_num_old].my_discriminator != te_tunnel->sidlists[path_num].my_discriminator)
				SET_FLAG(te_tunnel->sidlists[path_num].flags, SRV6_SID_LIST_UPDATE);
			else if (te_tunnel->sidlists_old[path_num_old].flags != te_tunnel->sidlists[path_num].flags)
				SET_FLAG(te_tunnel->sidlists[path_num].flags, SRV6_SID_LIST_UPDATE);

			find_flag = true;
		}
	}
	if (find_flag == false)
		SET_FLAG(te_tunnel->sidlists[path_num].flags, SRV6_SID_LIST_ADD);
	return ;
}

static bool zebra_srv6_policy_check_update(struct zapi_srv6te_tunnel *new_tunnel)
{
	uint8_t path_num = 0;
	uint8_t path_num_old = 0;
	bool segment_list_changed = false;

	for (path_num = 0; path_num < new_tunnel->path_num; path_num++) {

		zebra_srv6_policy_set_sidlist_type(new_tunnel, path_num);

		if (CHECK_FLAG(new_tunnel->sidlists[path_num].flags, SRV6_SID_LIST_ADD)
			||CHECK_FLAG(new_tunnel->sidlists[path_num].flags, SRV6_SID_LIST_UPDATE))
			segment_list_changed = true;
	}

	for(path_num_old = 0; path_num_old < new_tunnel->path_num_old; path_num_old++) {
		if (CHECK_FLAG(new_tunnel->sidlists_old[path_num_old].flags, SRV6_SID_LIST_DEL))
			segment_list_changed = true;
	}

	if (IS_ZEBRA_DEBUG_SRV6) {
		zlog_debug("%s: segment list %s change", __func__, segment_list_changed ? "is":"not");
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

static void zebra_srv6_policy_copy_sidlist(struct zebra_sr_policy *policy, struct zapi_srv6te_tunnel *new_tunnel)
{
	uint8_t path_num = 0;

	if (policy == NULL || new_tunnel == NULL)
		return;

	zebra_srv6_clear_old_sidlist(new_tunnel);

	for (path_num = 0; path_num < policy->srv6_segment_list.path_num; path_num++) {
		strlcpy(new_tunnel->sidlists_old[path_num].sidlist_name, policy->srv6_segment_list.sidlists[path_num].sidlist_name,
			sizeof(policy->srv6_segment_list.sidlists[path_num].sidlist_name));
		new_tunnel->sidlists_old[path_num].weight = policy->srv6_segment_list.sidlists[path_num].weight;
		new_tunnel->sidlists_old[path_num].my_discriminator = policy->srv6_segment_list.sidlists[path_num].my_discriminator;
		new_tunnel->sidlists_old[path_num].flags = policy->srv6_segment_list.sidlists[path_num].flags;
		SET_FLAG(new_tunnel->sidlists_old[path_num].flags, SRV6_SID_LIST_DEL);
	}
	new_tunnel->path_num_old = policy->srv6_segment_list.path_num;
	return;
}
static bool zebra_srv6_binding_sid_equal(const struct zapi_srte_binding_sid *bs1,
			    const struct zapi_srte_binding_sid *bs2)
{
	/* Check for NULL pointers */
	if (!bs1 || !bs2)
		return false;

	if (bs1 == bs2)
		return true;

	/* Compare IP addresses */
	if (bs1->sid_v6.ipa_type != bs2->sid_v6.ipa_type)
		return false;

	switch (bs1->sid_v6.ipa_type) {
	case IPADDR_V4:
		if (memcmp(&bs1->sid_v6.ipaddr_v4, &bs2->sid_v6.ipaddr_v4,
			   sizeof(struct in_addr)))
			return false;
		break;
	case IPADDR_V6:
		if (memcmp(&bs1->sid_v6.ipaddr_v6, &bs2->sid_v6.ipaddr_v6,
			   sizeof(struct in6_addr)))
			return false;
		break;
	default:
		/* For IPADDR_NONE or unknown types, just check the type */
		break;
	}

	/* Compare SID format parameters */
	if (bs1->block_bits_length != bs2->block_bits_length)
		return false;

	if (bs1->node_bits_length != bs2->node_bits_length)
		return false;

	if (bs1->function_bits_length != bs2->function_bits_length)
		return false;

	if (bs1->argument_bits_length != bs2->argument_bits_length)
		return false;

	if (bs1->format != bs2->format)
		return false;

	if (bs1->compress != bs2->compress)
		return false;

	return true;
}

void zebra_srv6_policy_validate(struct zebra_sr_policy *policy,
			     struct zapi_sr_policy *zp,
				 bool new_flag)
{

	bool segment_list_changed = false;
	bool binding_sid_equal= false;
	struct zapi_sr_policy zp_old = { 0 };

	if (policy == NULL || zp == NULL)
		return;

	if (new_flag) {
		memcpy(&policy->srv6_segment_list, &zp->srv6_tunnel,
			sizeof(struct zapi_srv6te_tunnel));
		policy->type = ZEBRA_SR_POLICY_TYPE_SRV6;

		/* Evaluate next hops and notify related routes */
		zebra_srte_evaluate_rn_nexthops(policy, zebra_router_get_next_sequence(), false);

		/* Update binding SID information */
		memcpy(&policy->binding_v6_sid, &zp->bsid, sizeof(struct zapi_srte_binding_sid));

		/* Add binding SID route */
		zebra_binding_sid_route_add(policy, zp);
	} else {
		zebra_srv6_policy_copy_sidlist(policy, &zp->srv6_tunnel);

		/* Check if segment list has changed */
		segment_list_changed = zebra_srv6_policy_check_update(&zp->srv6_tunnel);
		memcpy(&policy->srv6_segment_list, &zp->srv6_tunnel,
			sizeof(struct zapi_srv6te_tunnel));
		policy->type = ZEBRA_SR_POLICY_TYPE_SRV6;

		/* Check if binding SID has changed */
		binding_sid_equal = zebra_srv6_binding_sid_equal(&policy->binding_v6_sid, &zp->bsid);
		/* If binding SID or segment list changed, update binding SID route */
		if (!binding_sid_equal || segment_list_changed) {
			if (!binding_sid_equal) {
				/* Delete old binding SID route */
				memcpy(&zp_old.bsid, &policy->binding_v6_sid, sizeof(struct zapi_srte_binding_sid));
				zebra_binding_sid_route_del(policy, &zp_old);
			}
			memcpy(&policy->binding_v6_sid, &zp->bsid, sizeof(struct zapi_srte_binding_sid));
			zebra_binding_sid_route_add(policy, zp);
		}

		/* If segment list changed, update NHE segment information */
		if (segment_list_changed)
			zebra_nhe_seg_update(policy);
	}
	return;
}

static void zebra_sr_policy_deactivate(struct zebra_sr_policy *policy)
{
	if (is_default_prefix(&policy->node->p))
		policy->status = ZEBRA_SR_POLICY_INIT;
	else
		policy->status = ZEBRA_SR_POLICY_DOWN;
	policy->lsp = NULL;
    if (policy->type == ZEBRA_SR_POLICY_TYPE_LSP)
    {
        zebra_sr_policy_bsid_uninstall(policy, policy->segment_list.local_label);
    }

	if (policy->type == ZEBRA_SR_POLICY_TYPE_SRV6)
		zebra_srv6_policy_down_update_pic_nhe(policy);

	zsend_sr_policy_notify_status(policy->color, policy->node,
				      policy->name, ZEBRA_SR_POLICY_DOWN);
	zebra_srte_evaluate_rn_nexthops(policy, zebra_router_get_next_sequence(), true);
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
	    || lsp->addr_family != policy->node->p.family) {
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

int zebra_sr_policy_label_update_walk(struct hash_bucket *hb, void *arg)
{
	struct zebra_sr_policy *policy;
	struct route_table *table;
	struct route_node *rn;
	struct zebra_sr_policy_label_para *para = arg;
	
	table = hb->data;
	if (!table) {
		return 0;
	}

	for (rn = route_top(table); rn; rn = route_next(rn)) {
		policy = rn->info;
		if (!policy)
			continue;
		mpls_label_t next_hop_label;

		next_hop_label = policy->segment_list.labels[0];
		if (next_hop_label != para->label)
			continue;

		switch (para->mode) {
		case ZEBRA_SR_POLICY_LABEL_CREATED:
		case ZEBRA_SR_POLICY_LABEL_UPDATED:
		case ZEBRA_SR_POLICY_LABEL_REMOVED:
			zebra_sr_policy_validate(policy, NULL);
			break;
		}
	}

	return 0;
}

int zebra_sr_policy_label_update(mpls_label_t label,
				 enum zebra_sr_policy_update_label_mode mode)
{
	struct zebra_sr_policy_label_para para = {0};
	para.label = label;
	para.mode = mode;
	hash_walk(srte_table_hash, zebra_sr_policy_label_update_walk, &para);

	return 0;
}
/*
 * Create a routing table for the specific AFI/SAFI in the given VRF.
 */
struct route_table *zebra_srte_table_create(afi_t afi, uint32_t color)
{
	struct route_node *rn;
	struct prefix p;
	struct route_table *table;
	struct zebra_sr_policy *policy;

	table = route_table_init();

	memset(&p, 0, sizeof(p));
	p.family = afi2family(afi);

	rn = route_node_get(table, &p);
	policy = rn->info;

	if (!policy) {
		policy = XCALLOC(MTYPE_ZEBRA_SR_POLICY, sizeof(struct zebra_sr_policy));
		route_lock_node(rn);
		policy->node = rn;
		policy->color = color;
		policy->status = ZEBRA_SR_POLICY_INIT;
		rnh_srte_list_init(&policy->nht);
		rnh_backup_srte_list_init(&policy->backup_nht);
		rn->info = policy;
		policy->flags |= ZEBRA_SR_POLICY_FLAG_COLOR_ONLY;
	} 
	return table;
}

static uint32_t srte_table_hash_key_make(const void *arg)
{
	const struct srte_table_key *srte_key = arg;
	uint32_t key = 0;

	key = jhash_1word(srte_key->afi, key);
	key = jhash_1word(srte_key->color, key);
	return key;
}

static bool srte_table_hash_same(const void *arg1, const void *arg2)
{
	const struct srte_table_key *srte_key1 = arg1;
	const struct srte_table_key *srte_key2 = arg2;
	if (srte_key1->afi != srte_key2->afi)
		return false;
	return (srte_key1->color == srte_key2->color);
}

void *srte_table_alloc(void *arg)
{
	struct route_table *srte_table;
	struct srte_table_key *srte_key = arg;
	struct srte_table_key *srte_key_table = NULL;

	srte_key_table = XCALLOC(MTYPE_ZEBRA_SR_POLICY, sizeof(struct srte_table_key));

	srte_table = zebra_srte_table_create(srte_key->afi, srte_key->color);
	srte_key_table->table = srte_table;
	srte_key_table->afi = srte_key->afi;
	srte_key_table->color = srte_key->color;

	return srte_key_table;
}

void zebra_srte_evaluate_rn_nexthops(struct zebra_sr_policy *policy, uint32_t seq, bool rt_delete)
{
	struct route_node *rn;
	struct rnh *rnh = NULL;
	struct rnh *backup_rnh = NULL;
	struct zebra_sr_policy *policyNext = policy;

	rn = policy->node;

	/*
	 * We are storing the rnh's associated withb
	 * the tracked nexthop as a list of the rn's.
	 * Unresolved rnh's are placed at the top
	 * of the tree list.( 0.0.0.0/0 for v4 and 0::0/0 for v6 )
	 * As such for each rn we need to walk up the tree
	 * and see if any rnh's need to see if they
	 * would match a more specific route
	 */
	while (rn) {
		if (!policyNext) {
			rn = rn->parent;
			if (rn)
				policyNext = rn->info;
			continue;
		}
		if (rt_delete && (!rnh_srte_list_count(&policyNext->nht))
			&& (!rnh_backup_srte_list_count(&policyNext->backup_nht))) {
			if (IS_ZEBRA_DEBUG_NHT_DETAILED)
				zlog_debug("%pRN has no tracking NHTs. Bailing",
					   rn);
			break;
		}

		if (rnh_srte_list_count(&policyNext->nht)) {
			frr_each_safe(rnh_srte_list, &policyNext->nht, rnh) {
				if (rnh->seqno == seq) {
					if (IS_ZEBRA_DEBUG_NHT_DETAILED)
						zlog_debug(
							"    Node processed and moved already");
					continue;
				}

				rnh->seqno = seq;
				struct prefix *p = &rnh->node->p;

				zebra_evaluate_rnh_by_srte(family2afi(p->family), rnh);
			}
		}
		if (rnh_backup_srte_list_count(&policyNext->backup_nht)) {
			frr_each_safe(rnh_backup_srte_list, &policyNext->backup_nht, backup_rnh) {
				if (backup_rnh->seqno == seq) {
					if (IS_ZEBRA_DEBUG_NHT_DETAILED)
						zlog_debug(
							"    Node processed and moved already");
					continue;
				}

				backup_rnh->seqno = seq;
				struct prefix *p = &backup_rnh->node->p;

				zebra_evaluate_rnh_by_srte(family2afi(p->family), backup_rnh);
			}
		}
		
		rn = rn->parent;
		if (rn)
			policyNext = rn->info;
	}
}

void zebra_bsid_route_add(struct zebra_sr_policy *policy,
						struct zapi_sr_policy *zp,
						enum seg6local_action_t act,
						struct seg6local_context *ctx)
{
	struct route_entry *re;
	struct nexthop_group *ng = NULL;
	int ret = 0;
	struct nhg_hash_entry nhe;
    struct zebra_vrf *zvrf;
    struct vrf *def_vrf = NULL;
    struct prefix p = {};
    struct nexthop *nexthop;
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();

	/* Set the prefix based on the binding SID format */
    p.family = AF_INET6;
    p.prefixlen = ctx->block_bits_length + ctx->node_bits_length + ctx->function_bits_length;

	memcpy(&p.u.prefix6, &zp->bsid.sid_v6.ipaddr_v6,
		sizeof(struct in6_addr));

    def_vrf = vrf_lookup_by_name(VRF_DEFAULT_NAME);
    zvrf = zebra_vrf_lookup_by_id(def_vrf->vrf_id);
    if (!zvrf) {
        return;
    }

	/* Allocate new route. */
	re = XCALLOC(MTYPE_RE, sizeof(struct route_entry));
	re->type = ZEBRA_ROUTE_STATIC;
	re->instance = 0;
    SET_FLAG(re->flags, ZEBRA_FLAG_LOCAL_SID_ROUTE);
	SET_FLAG(re->flags, ZEBRA_FLAG_FIB_BYPASS);
    SET_FLAG(re->status, ROUTE_ENTRY_INSTALLED);
	re->uptime = monotime(NULL);
	re->vrf_id = VRF_DEFAULT;

	re->table = zvrf->table_id;

    ng = nexthop_group_new();
	if (!ng) {
		return;
	}

	/* Create a nexthop from the IPv6 segment list */
	nexthop = nexthop_from_ipv6_segment_list(&zp->endpoint.u.prefix6, 0);
	if (!nexthop) {
		if (ng)
			nexthop_group_delete(&ng);
		return;
	}
	nexthop->srte_color = policy->color;
	nexthop->srte_color_flag = 1;
	SET_FLAG(nexthop->flags, NEXTHOP_FLAG_SRV6_BSID);
	nexthop_add_srv6_seg6local(nexthop, act, ctx);
	if (!IPV6_ADDR_SAME(&srv6->encap_src_addr, &in6addr_any)) {
		nexthop->nh_srv6->seg6_src = srv6->encap_src_addr;
		nexthop->seg6_src = srv6->encap_src_addr;
	}

	nexthop_group_add_sorted(ng, nexthop);

	if (IS_ZEBRA_DEBUG_RIB) {
		zlog_debug("%s: adding seg6local action %s",
			__func__,
			seg6local_action2str(act));
	}

	/* Initialize the nexthop group hash entry */
	zebra_nhe_init(&nhe, AFI_IP6, ng->nexthop);
	nhe.nhg.nexthop = ng->nexthop;
	SET_FLAG(nhe.flags, NEXTHOP_GROUP_BSID);
	ret = rib_add_multipath_nhe(AFI_IP6, SAFI_UNICAST, &p, NULL,
				    re, &nhe);
	if (ret == -1) {
		XFREE(MTYPE_RE, re);
	}
	nexthop_group_delete(&ng);
    return;

}
void zebra_binding_sid_route_add(struct zebra_sr_policy *policy, struct zapi_sr_policy *zp)
{
	struct seg6local_context ctx = {};
	struct vrf *vrf;

	if (!zp)
		return;

	/* If the binding SID is unspecified, delete the route instead */
	if (IN6_IS_ADDR_UNSPECIFIED(&zp->bsid.sid_v6.ipaddr_v6)) {
		return;
	}

	vrf = vrf_lookup_by_name(policy->zvrf->vrf->name);
	if (!vrf)
		return;

	/* Set up the SEG6 local context with SID format information */
	ctx.table = vrf->data.l.table_id;
	ctx.node_bits_length = zp->bsid.node_bits_length;
	ctx.function_bits_length = zp->bsid.function_bits_length;
	ctx.block_bits_length = zp->bsid.block_bits_length;
	ctx.argument_bits_length = zp->bsid.argument_bits_length;

	strncpy(ctx.vrfName, policy->zvrf->vrf->name, VRF_ALIASNAMESIZ + 1);

	/* Add the binding SID route if VRF is active */
    if (CHECK_FLAG(vrf->status, VRF_ACTIVE))
		zebra_bsid_route_add(policy, zp, ZEBRA_SEG6_LOCAL_ACTION_END_B6_ENCAP, &ctx);
	return;
}

void zebra_bsid_route_del(struct zebra_sr_policy *policy,
						struct zapi_sr_policy *zp,
						enum seg6local_action_t act,
						struct seg6local_context *ctx)
{
	uint32_t table_id;
    struct zebra_vrf *zvrf;
    struct vrf *def_vrf = NULL;
    uint32_t flags = 0;

    struct prefix p = {};

	/* Set up the prefix based on the binding SID format */
    p.family = AF_INET6;
    p.prefixlen = ctx->block_bits_length + ctx->node_bits_length + ctx->function_bits_length;


	memcpy(&p.u.prefix6, &zp->bsid.sid_v6.ipaddr_v6,
		sizeof(struct in6_addr));

    def_vrf = vrf_lookup_by_name(VRF_DEFAULT_NAME);
    zvrf = zebra_vrf_lookup_by_id(def_vrf->vrf_id);
    if (!zvrf) {
        return ;
    }

	table_id = zvrf->table_id;
	SET_FLAG(flags, ZEBRA_FLAG_LOCAL_SID_ROUTE);

	/* Delete the route from the RIB */
	rib_delete(AFI_IP6, SAFI_UNICAST, zvrf_id(zvrf), ZEBRA_ROUTE_STATIC, 0,
		   flags, &p, NULL, NULL, 0, table_id, 0,
		   0, false);

    return ;

}
void zebra_binding_sid_route_del(struct zebra_sr_policy *policy, struct zapi_sr_policy *zp)
{
	struct seg6local_context ctx = {};
	struct vrf *vrf;

	if (!zp)
		return;

	/* If the binding SID is unspecified, nothing to do */
	if (IN6_IS_ADDR_UNSPECIFIED(&zp->bsid.sid_v6.ipaddr_v6))
		return;

	vrf = vrf_lookup_by_name(policy->zvrf->vrf->name);
	if (!vrf)
		return;

	/* Set up the SEG6 local context with SID format information */
	ctx.table = vrf->data.l.table_id;
	ctx.node_bits_length = zp->bsid.node_bits_length;
	ctx.function_bits_length = zp->bsid.function_bits_length;
	ctx.block_bits_length = zp->bsid.block_bits_length;
	ctx.argument_bits_length = zp->bsid.argument_bits_length;

	strncpy(ctx.vrfName, policy->zvrf->vrf->name, VRF_ALIASNAMESIZ + 1);

	/* Delete the binding SID route */
	zebra_bsid_route_del(policy, zp, ZEBRA_SEG6_LOCAL_ACTION_END_B6_ENCAP, &ctx);
}


void zebra_srte_init(void)
{
	srte_table_hash = hash_create(srte_table_hash_key_make, srte_table_hash_same,
				    "SRTE table Hash");
	srte_table_hash->max_size = 1000;
}
