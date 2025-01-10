/*
 * Zebra SRv6 VTY functions
 * Copyright (C) 2020  Hiroki Shirokura, LINE Corporation
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

#include "memory.h"
#include "if.h"
#include "prefix.h"
#include "command.h"
#include "table.h"
#include "rib.h"
#include "nexthop.h"
#include "vrf.h"
#include "srv6.h"
#include "lib/json.h"
#include "termtable.h"

#include "zebra/zserv.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_srv6.h"
#include "zebra/zebra_srv6_vty.h"
#include "zebra/zebra_srte.h"
#include "zebra/zebra_rnh.h"
#include "zebra/redistribute.h"
#include "zebra/zebra_routemap.h"
#include "zebra/zebra_dplane.h"
#include "zebra/zapi_msg.h"

#ifndef VTYSH_EXTRACT_PL
#include "zebra/zebra_srv6_vty_clippy.c"
#endif

static int zebra_sr_config(struct vty *vty);

static struct cmd_node sr_node = {
	.name = "sr",
	.node = SEGMENT_ROUTING_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-sr)# ",
	.config_write = zebra_sr_config,
};

static struct cmd_node srv6_node = {
	.name = "srv6",
	.node = SRV6_NODE,
	.parent_node = SEGMENT_ROUTING_NODE,
	.prompt = "%s(config-srv6)# ",

};

static struct cmd_node srv6_locs_node = {
	.name = "srv6-locators",
	.node = SRV6_LOCS_NODE,
	.parent_node = SRV6_NODE,
	.prompt = "%s(config-srv6-locators)# ",
};

static struct cmd_node srv6_loc_node = {
	.name = "srv6-locator",
	.node = SRV6_LOC_NODE,
	.parent_node = SRV6_LOCS_NODE,
	.prompt = "%s(config-srv6-locator)# "
};

static struct cmd_node srv6_encap_node = {
	.name = "srv6-encap",
	.node = SRV6_ENCAP_NODE,
	.parent_node = SRV6_NODE,
	.prompt = "%s(config-srv6-encap)# "
};

DEFPY (show_srv6_manager,
       show_srv6_manager_cmd,
       "show segment-routing srv6 manager [json]",
       SHOW_STR
       "Segment Routing\n"
       "Segment Routing SRv6\n"
       "Verify SRv6 Manager\n"
       JSON_STR)
{
	const bool uj = use_json(argc, argv);
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	json_object *json = NULL;
	json_object *json_parameters = NULL;
	json_object *json_encapsulation = NULL;
	json_object *json_source_address = NULL;

	if (uj) {
		json = json_object_new_object();
		json_parameters = json_object_new_object();
		json_object_object_add(json, "parameters", json_parameters);
		json_encapsulation = json_object_new_object();
		json_object_object_add(json_parameters, "encapsulation",
				       json_encapsulation);
		json_source_address = json_object_new_object();
		json_object_object_add(json_encapsulation, "sourceAddress",
				       json_source_address);
		json_object_string_addf(json_source_address, "configured",
					"%pI6", &srv6->encap_src_addr);
		vty_json(vty, json);
	} else {
		vty_out(vty, "Parameters:\n");
		vty_out(vty, "  Encapsulation:\n");
		vty_out(vty, "    Source Address:\n");
		vty_out(vty, "      Configured: %pI6\n", &srv6->encap_src_addr);
	}

	return CMD_SUCCESS;
}

static size_t list_count(struct list *list) {
    size_t count = 0;
    struct listnode *node;

    for (node = list->head; node != NULL; node = node->next) {
        count++;
    }

    return count;
}

static struct seg6_sid_endx_params *seg6_sid_endx_param_lookup(struct list *list, struct seg6_sid_endx_params *sid_endx_params)
{
	struct seg6_sid_endx_params *sid_endx_param_index = NULL;
    struct listnode *node, *nnode;
    if (!sid_endx_params)
        return NULL;
    for (ALL_LIST_ELEMENTS(list, node, nnode, sid_endx_param_index)) {
		if (!strcmp(sid_endx_param_index->ifname, sid_endx_params->ifname) || 
		    !ipaddr_cmp(&sid_endx_param_index->nexthop, &sid_endx_params->nexthop))
			{
				return sid_endx_param_index;
			}       
    }

	return NULL;
}

static void seg6_sid_endx_ecmp_free(struct srv6_locator *locator, struct seg6_sid_endx_ecmp *sid_endx_ecmp)
{
	int sid_endx_ecmp_member_cnt = 0;

	if (!locator || !sid_endx_ecmp)
		return;

	sid_endx_ecmp_member_cnt = list_count(sid_endx_ecmp->sid_endx_params);
	if (sid_endx_ecmp_member_cnt == 0)
	{
		listnode_delete(locator->sid_endx_ecmps, sid_endx_ecmp);
		srv6_locator_sid_endx_ecmp_free(sid_endx_ecmp);
	}

	return;
}


static struct seg6_sid *sid_lookup_by_prefix_intf_nhp(struct srv6_locator *loc, struct prefix_ipv6 *ipv6prefix, 
             const char *ifName, struct ipaddr *nexthop, enum seg6local_sid_type_t sidtype)
{
	struct seg6_sid *sid = NULL;
	struct listnode *node, *nnode;

	if (!ipv6prefix || !ifName || !nexthop || !loc)
		return NULL;

	for (ALL_LIST_ELEMENTS(loc->sids, node, nnode, sid)) {
		if (IPV6_ADDR_SAME(&sid->ipv6Addr.prefix, &ipv6prefix->prefix)) {
			if (!strcmp(sid->ifname, ifName) && !ipaddr_cmp(&sid->nexthop, nexthop) && sid->sidtype == sidtype)	
			{
				return sid;
			}
		}
	}
	return NULL;
}

static bool seg6local_act_contain_sidact(enum seg6local_action_t action,
	enum seg6local_action_t sidaction)
{
	switch (action) {
	case ZEBRA_SEG6_LOCAL_ACTION_END:
	case ZEBRA_SEG6_LOCAL_ACTION_END_T:
	case ZEBRA_SEG6_LOCAL_ACTION_END_DX2:
	case ZEBRA_SEG6_LOCAL_ACTION_END_DX6:
	case ZEBRA_SEG6_LOCAL_ACTION_END_DX4:
	case ZEBRA_SEG6_LOCAL_ACTION_END_B6:
	case ZEBRA_SEG6_LOCAL_ACTION_END_B6_ENCAP:
	case ZEBRA_SEG6_LOCAL_ACTION_END_BM:
	case ZEBRA_SEG6_LOCAL_ACTION_END_S:
	case ZEBRA_SEG6_LOCAL_ACTION_END_AS:
	case ZEBRA_SEG6_LOCAL_ACTION_END_AM:
	case ZEBRA_SEG6_LOCAL_ACTION_END_UDX6:
	case ZEBRA_SEG6_LOCAL_ACTION_END_UDX4:
	case ZEBRA_SEG6_LOCAL_ACTION_END_UN:
	case ZEBRA_SEG6_LOCAL_ACTION_END_UA:
		if (action == sidaction)
			return true;
		break;
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT46:
		if (sidaction == ZEBRA_SEG6_LOCAL_ACTION_END_DT4
			|| sidaction == ZEBRA_SEG6_LOCAL_ACTION_END_DT6
			|| sidaction == ZEBRA_SEG6_LOCAL_ACTION_END_DT46)
			return true;
		break;
	case ZEBRA_SEG6_LOCAL_ACTION_END_UDT46:
		if (sidaction == ZEBRA_SEG6_LOCAL_ACTION_END_UDT4
			|| sidaction == ZEBRA_SEG6_LOCAL_ACTION_END_UDT6
			|| sidaction == ZEBRA_SEG6_LOCAL_ACTION_END_UDT46)
			return true;
		break;
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT4:
		if (sidaction == ZEBRA_SEG6_LOCAL_ACTION_END_DT4
			|| sidaction == ZEBRA_SEG6_LOCAL_ACTION_END_DT46)
			return true;
		break;
	case ZEBRA_SEG6_LOCAL_ACTION_END_UDT4:
		if (sidaction == ZEBRA_SEG6_LOCAL_ACTION_END_UDT4
			|| sidaction == ZEBRA_SEG6_LOCAL_ACTION_END_UDT46)
			return true;
		break;
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT6:
		if (sidaction == ZEBRA_SEG6_LOCAL_ACTION_END_DT46
			|| sidaction == ZEBRA_SEG6_LOCAL_ACTION_END_DT6)
			return true;
		break;
	case ZEBRA_SEG6_LOCAL_ACTION_END_UDT6:
		if (sidaction == ZEBRA_SEG6_LOCAL_ACTION_END_UDT46
			|| sidaction == ZEBRA_SEG6_LOCAL_ACTION_END_UDT6)
			return true;
		break;
	default:
		return false;
	}
	return false;
}
static struct seg6_sid *sid_lookup_by_vrf_action(struct srv6_locator *loc,
	const char *vrfname, enum seg6local_action_t sidaction)
{
	struct seg6_sid *sid = NULL;
	struct listnode *node, *nnode;

	if (!vrfname)
		return NULL;

	for (ALL_LIST_ELEMENTS(loc->sids, node, nnode, sid)) {
		if (strcmp(sid->vrfName, vrfname) == 0
			&& seg6local_act_contain_sidact(sid->sidaction, sidaction))
			return sid;
	}
	return NULL;
}

const char *policystatus2str(enum zebra_sr_policy_status status, struct zebra_sr_policy_show_para *para)
{
	switch (status) {
	case ZEBRA_SR_POLICY_UP:
		para->active_count++;
		return "Active";
	case ZEBRA_SR_POLICY_DOWN:
		para->inactive_count++;
		return "Inactive";
	case ZEBRA_SR_POLICY_INIT:
		para->init_count++;
		return "Init";
	default:
		break;
	}
	return NULL;
}

static int zebra_show_sr_policy_walk(struct hash_bucket *hb, void *arg)
{
	struct zebra_sr_policy *policy;
	struct route_node *rn;
	struct ttable *tt;
	struct zebra_sr_policy_show_para *para = arg;
	struct srte_table_key *srte_key_table = NULL;
	srte_key_table = hb->data;
	if (!srte_key_table || !srte_key_table->table) {
		return 0;
	}
	tt = para->tt;

	for (rn = route_top(srte_key_table->table); rn; rn = route_next(rn)) {
		policy = rn->info;
		if (!policy)
			continue;
		char endpoint[60];
		char binding_sid[16] = "-";
		char segmentlist_old[4096] = {0};
		char segmentlist[4096] = {0};
		strcat(segmentlist_old, "[");
		for(uint32_t i = 0; i < policy->srv6_segment_list.path_num_old; i++) {
			char buf[80] = {0};
			char typebuf[2] = {0};
			if (CHECK_FLAG(policy->srv6_segment_list.sidlists_old[i].flags, SRV6_SID_LIST_BACKUP))
				strcat(typebuf, "B");
			else
				strcat(typebuf, "M");

			sprintf(buf, "(%s-%u-%s)", policy->srv6_segment_list.sidlists_old[i].sidlist_name,
				policy->srv6_segment_list.sidlists_old[i].my_discriminator, typebuf);
			strcat(segmentlist_old, buf);
		}
		strcat(segmentlist_old, "]");

		strcat(segmentlist, "[");
		for(uint32_t i = 0; i < policy->srv6_segment_list.path_num; i++) {
			char buf[80] = {0};
			char typebuf[2] = {0};
			if (CHECK_FLAG(policy->srv6_segment_list.sidlists[i].flags, SRV6_SID_LIST_BACKUP))
				strcat(typebuf, "B");
			else
				strcat(typebuf, "M");

			sprintf(buf, "(%s-%u-%s)", policy->srv6_segment_list.sidlists[i].sidlist_name,
				policy->srv6_segment_list.sidlists[i].my_discriminator, typebuf);
			strcat(segmentlist, buf);
		}
		strcat(segmentlist, "]");
		inet_ntop(rn->p.family, &rn->p.u.prefix, endpoint, 60);

		ttable_add_row(tt, "%s|%u|%s|%s|%s|%s|%s", endpoint, policy->color,
			       policy->name, binding_sid,
			       policystatus2str(policy->status, para),
				   segmentlist_old, segmentlist);
	}

	
	return 0;
}

DEFUN (show_srv6_tunnel,
       show_srv6_tunnel_cmd,
       "show sr-te tunnel",
       SHOW_STR
       "SR-TE info\n"
       "Tunnel info\n")
{
	struct ttable *tt;
	//struct srte_policy *policy;
	char *table;
	struct zebra_sr_policy_show_para para = {0};

	/* Prepare table. */
	tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
	ttable_add_row(tt, "Endpoint|Color|Name|BSID|Status|SegmentList_old|SegmentList");
	tt->style.cell.rpad = 2;
	tt->style.corner = '+';
	ttable_restyle(tt);
	ttable_rowseps(tt, 0, BOTTOM, true, '-');
	para.vty = vty;
	para.tt = tt;

	hash_walk(srte_table_hash, zebra_show_sr_policy_walk, &para);
	
	/* Dump the generated table. */
	table = ttable_dump(tt, "\n");
	vty_out(vty, "%s\n", table);

	vty_out(vty, "Init count :%d    Active count :%d    Inactive count :%d\n", 
		para.init_count, para.active_count, para.inactive_count);

	XFREE(MTYPE_TMP, table);

	ttable_del(tt);

	return CMD_SUCCESS;
}

DEFUN (show_srv6_locator,
       show_srv6_locator_cmd,
       "show segment-routing srv6 locator [json]",
       SHOW_STR
       "Segment Routing\n"
       "Segment Routing SRv6\n"
       "Locator Information\n"
       JSON_STR)
{
	const bool uj = use_json(argc, argv);
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct srv6_locator *locator;
	struct listnode *node;
	char str[256];
	int id;
	json_object *json = NULL;
	json_object *json_locators = NULL;
	json_object *json_locator = NULL;

	if (uj) {
		json = json_object_new_object();
		json_locators = json_object_new_array();
		json_object_object_add(json, "locators", json_locators);

		for (ALL_LIST_ELEMENTS_RO(srv6->locators, node, locator)) {
			json_locator = srv6_locator_json(locator);
			if (!json_locator)
				continue;
			json_object_array_add(json_locators, json_locator);

		}

		vty_json(vty, json);
	} else {
		vty_out(vty, "Locator:\n");
		vty_out(vty, "Name                 ID      Prefix                   Status\n");
		vty_out(vty, "-------------------- ------- ------------------------ -------\n");

		id = 1;
		for (ALL_LIST_ELEMENTS_RO(srv6->locators, node, locator)) {
			prefix2str(&locator->prefix, str, sizeof(str));
			vty_out(vty, "%-20s %7d %-24s %s\n",
				locator->name, id, str,
				locator->status_up ? "Up" : "Down");
			++id;
		}
		vty_out(vty, "\n");
	}

	return CMD_SUCCESS;
}

DEFUN (show_srv6_locator_detail,
		show_srv6_locator_detail_cmd,
		"show segment-routing srv6 locator NAME detail [json]",
		SHOW_STR
		"Segment Routing\n"
		"Segment Routing SRv6\n"
		"Locator Information\n"
		"Locator Name\n"
		"Detailed information\n"
		JSON_STR)
	{
	const bool uj = use_json(argc, argv);
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct srv6_locator *locator;
	struct seg6_sid_endx_ecmp *sid_ecmp_index = NULL;
	struct seg6_sid_endx_params *sid_ecmp_params_index = NULL;
	struct listnode *node;
	struct listnode *sidnode;
	struct listnode *ecmp_node;
	struct listnode *ecmp_para_node;
	char str[256];
	const char *locator_name = argv[4]->arg;
	json_object *json_locator = NULL;
	struct seg6_sid *sid = NULL;
	struct in6_addr result_sid = {0};
	struct prefix p = {};
	char buf[256];

	if (uj) {
		locator = zebra_srv6_locator_lookup(locator_name);
		if (!locator)
			return CMD_WARNING;

		json_locator = srv6_locator_detailed_json(locator);
		vty_json(vty, json_locator);
		return CMD_SUCCESS;
	}

	for (ALL_LIST_ELEMENTS_RO(srv6->locators, node, locator)) {
		struct listnode *node;
		struct srv6_locator_chunk *chunk;

		if (strcmp(locator->name, locator_name) != 0)
			continue;

		prefix2str(&locator->prefix, str, sizeof(str));
		vty_out(vty, "Name: %s\n", locator->name);
		vty_out(vty, "Prefix: %s\n", str);
		vty_out(vty, "Compress: %s\n", locator->compress ? "Yes" : "No");
		vty_out(vty, "Block-Bit-Len: %u\n",
			locator->block_bits_length);
        vty_out(vty, "Node-Bit-Len: %u\n",
			locator->node_bits_length);
        vty_out(vty, "Function-Bit-Len: %u\n",
			locator->function_bits_length);
		vty_out(vty, "Argument-Bit-Len: %u\n",
			locator->argument_bits_length);

		vty_out(vty, "Chunks:\n");
		for (ALL_LIST_ELEMENTS_RO((struct list *)locator->chunks, node,
						chunk)) {
			prefix2str(&chunk->prefix, str, sizeof(str));
			vty_out(vty, "- prefix: %s, owner: %s\n", str,
				zebra_route_string(chunk->proto));
		}
		vty_out(vty, "  sids:\n");
		for (ALL_LIST_ELEMENTS_RO(locator->sids, sidnode, sid)) {
			if (sid->sidtype == ZEBRA_SEG6_LOCAL_SID_TYPE_UA) {
				combine_hide_sid(locator, &sid->ipv6Addr.prefix, &result_sid, sid->sidtype);
				p.family = AF_INET6;
				p.prefixlen = 128;
				p.u.prefix6 = result_sid;
				prefix2str(&p, buf, sizeof(buf));
			}
			else {
				combine_sid(locator, &sid->ipv6Addr.prefix, &result_sid);
				p.family = AF_INET6;
				p.prefixlen = 128;
				p.u.prefix6 = result_sid;
				prefix2str(&p, buf, sizeof(buf));
				//prefix2str(&sid->ipv6Addr, buf, sizeof(buf));
			}
			vty_out(vty, "   -opcode %s\n", buf);
			vty_out(vty, "    sidaction %s\n", seg6local_action2str(sid->sidaction));
			if(sid->sidaction == ZEBRA_SEG6_LOCAL_ACTION_END_X) {
				char ifbuf[INET6_ADDRSTRLEN] = {0};
				vty_out(vty, "    ifname %s\n", sid->ifname);
				if (sid->nexthop.ipa_type == IPADDR_V4)
					inet_ntop(AF_INET, &sid->nexthop.ipaddr_v4, ifbuf, sizeof(ifbuf));
				else if (sid->nexthop.ipa_type == IPADDR_V6)
					inet_ntop(AF_INET6, &sid->nexthop.ipaddr_v6, ifbuf, sizeof(ifbuf));
				vty_out(vty, "    nexthop %s\n", ifbuf);
			}
			vty_out(vty, "    vrf %s\n", sid->vrfName);
			if(ZEBRA_SEG6_ACTION_IS_END_DT46(sid->sidaction))
				vty_out(vty, "    service-sid-marking %d\n", sid->sidmarking);
		}

		vty_out(vty, "  end-x ecmp:\n");
		for (ALL_LIST_ELEMENTS_RO(locator->sid_endx_ecmps, ecmp_node, sid_ecmp_index)) {
			memset(buf,0,sizeof(buf));
			p.family = AF_INET6;
			p.prefixlen = 128;
			p.u.prefix6 = sid_ecmp_index->ipv6Addr.prefix;
			prefix2str(&p, buf, sizeof(buf));
			vty_out(vty, "   -prefix %s\n", buf);
			for (ALL_LIST_ELEMENTS_RO(sid_ecmp_index->sid_endx_params, ecmp_para_node, sid_ecmp_params_index)) {
				char ecmpbuf[INET6_ADDRSTRLEN] = {0};
				vty_out(vty, "    ifname %s\n", sid_ecmp_params_index->ifname);
				if (sid_ecmp_params_index->nexthop.ipa_type == IPADDR_V4)
					inet_ntop(AF_INET, &sid_ecmp_params_index->nexthop.ipaddr_v4, ecmpbuf, sizeof(ecmpbuf));
				else if (sid_ecmp_params_index->nexthop.ipa_type == IPADDR_V6)
					inet_ntop(AF_INET6, &sid_ecmp_params_index->nexthop.ipaddr_v6, ecmpbuf, sizeof(ecmpbuf));
				vty_out(vty, "    nexthop %s\n", ecmpbuf);		
			}
		}
	}

	return CMD_SUCCESS;
}

DEFUN_NOSH (segment_routing,
            segment_routing_cmd,
            "segment-routing",
            "Segment Routing\n")
{
	vty->node = SEGMENT_ROUTING_NODE;
	return CMD_SUCCESS;
}

DEFUN_NOSH (srv6,
            srv6_cmd,
            "srv6",
            "Segment Routing SRv6\n")
{
	vty->node = SRV6_NODE;
	return CMD_SUCCESS;
}

DEFUN (no_srv6,
       no_srv6_cmd,
       "no srv6",
       NO_STR
       "Segment Routing SRv6\n")
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct srv6_locator *locator;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(srv6->locators, node, nnode, locator))
		zebra_srv6_locator_delete(locator);
	return CMD_SUCCESS;
}

DEFUN_NOSH (srv6_locators,
            srv6_locators_cmd,
            "locators",
            "Segment Routing SRv6 locators\n")
{
	vty->node = SRV6_LOCS_NODE;
	return CMD_SUCCESS;
}

DEFUN_NOSH (srv6_locator_sid,
        srv6_locator_cmd,
        "locator WORD [ prefix X:X::X:X/M$prefix \
         [block-len (16-64)$block_bit_len] [node-len (16-64)$node_bit_len] [func-bits (16-80)$func_bit_len] [argu-bits (8-80)$argu_bit_len] ]",
        "Segment Routing SRv6 locator\n"
        "Specify locator-name\n"
        "Configure SRv6 locator prefix\n"
        "Specify SRv6 locator prefix\n"
        "Configure SRv6 locator block length in bits\n"
        "Specify SRv6 locator block length in bits\n"
        "Configure SRv6 locator node length in bits\n"
        "Specify SRv6 locator node length in bits\n"
        "Configure SRv6 locator function length in bits\n"
        "Specify SRv6 locator function length in bits\n"
        "Configure SRv6 locator argument length in bits\n"
        "Specify SRv6 locator argument length in bits\n")
{
	struct srv6_locator *locator_sid = NULL;
	char *prefix = NULL;
	int ret = 0;
	int idx = 0;
	int block_bit_len = 0;
	int node_bit_len = 0;
	int func_bit_len = 0;
	int args_bit_len = 0;
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct srv6_locator *locator;
	struct listnode *node;

	locator_sid = zebra_srv6_locator_lookup(argv[1]->arg);
	if (locator_sid) {
		VTY_PUSH_CONTEXT(SRV6_LOC_NODE, locator_sid);
		locator_sid->status_up = true;
		locator_sid->compress = false;
		return CMD_SUCCESS;
	}

	locator_sid = srv6_locator_alloc(argv[1]->arg);
	if (!locator_sid) {
		vty_out(vty, "%% Alloc failed\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	locator_sid->status_up = true;
	locator_sid->compress = false;

	prefix = argv[3]->arg;
	ret = str2prefix_ipv6(prefix, &locator_sid->prefix);
	apply_mask_ipv6(&locator_sid->prefix);
	if (!ret) {
		srv6_locator_del(locator_sid);
		vty_out(vty, "Malformed IPv6 prefix\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	for (ALL_LIST_ELEMENTS_RO(srv6->locators, node, locator)) {
		if (prefix_same((struct prefix *)&locator->prefix, (struct prefix *)&locator_sid->prefix)) {
			srv6_locator_del(locator_sid);
			vty_out(vty, "Duplicate locator prefix\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	if (argv_find(argv, argc, "block-len", &idx)) {
		block_bit_len = strtoul(argv[idx + 1]->arg, NULL, 10);
	}
	if (argv_find(argv, argc, "node-len", &idx)) {
		node_bit_len = strtoul(argv[idx + 1]->arg, NULL, 10);
	}
	if (argv_find(argv, argc, "func-bits", &idx)) {
		func_bit_len = strtoul(argv[idx + 1]->arg, NULL, 10);
	}
	if (argv_find(argv, argc, "argu-bits", &idx)) {
		args_bit_len = strtoul(argv[idx + 1]->arg, NULL, 10);
	}

	if (block_bit_len == 0 && node_bit_len == 0) {
		block_bit_len = block_bit_len ? block_bit_len : locator_sid->prefix.prefixlen - 24;
		node_bit_len = node_bit_len ? node_bit_len : 24;
	} else if (block_bit_len == 0) {
		block_bit_len = locator_sid->prefix.prefixlen - node_bit_len;
	} else if (node_bit_len == 0) {
		node_bit_len = locator_sid->prefix.prefixlen - block_bit_len;
	} else {
		if (block_bit_len + node_bit_len != locator_sid->prefix.prefixlen) {
			srv6_locator_del(locator_sid);
			vty_out(vty, "%% block-bits + node-bits must be equal to the prefix length\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	/*
	 * TODO(slankdev): please support variable node-bit-length.
	 * In draft-ietf-bess-srv6-services-05#section-3.2.1.
	 * Locator block length and Locator node length are defined.
	 * Which are defined as "locator-len == block-len + node-len".
	 * In current implementation, node bits length is hardcoded as 24.
	 * It should be supported various val.
	 *
	 * Cisco IOS-XR support only following pattern.
	 *  (1) Teh locator length should be 64-bits long.
	 *  (2) The SID block portion (MSBs) cannot exceed 40 bits.
	 *      If this value is less than 40 bits,
	 *      user should use a pattern of zeros as a filler.
	 *  (3) The Node Id portion (LSBs) cannot exceed 24 bits.
	 */
	locator_sid->block_bits_length = block_bit_len;
	locator_sid->node_bits_length = node_bit_len;
	locator_sid->function_bits_length = func_bit_len;
	locator_sid->argument_bits_length = args_bit_len;

	if (!zebra_srv6_local_sid_get_format(locator_sid)) {
		vty_out(vty, "%% Malformed locator sid format\n");
		srv6_locator_del(locator_sid);
		return CMD_WARNING_CONFIG_FAILED;
	}

    zebra_srv6_locator_add(locator_sid);

	VTY_PUSH_CONTEXT(SRV6_LOC_NODE, locator_sid);
	vty->node = SRV6_LOC_NODE;
	return CMD_SUCCESS;
}

DEFUN (no_srv6_locator_sid,
       no_srv6_locator_cmd,
       "no locator WORD",
       NO_STR
       "Segment Routing SRv6 locator\n"
       "Specify locator-name\n")
{
	struct srv6_locator *locator_sid = zebra_srv6_locator_lookup(argv[2]->arg);
	if (!locator_sid) {
		vty_out(vty, "%% Can't find SRv6 locator\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	zebra_srv6_locator_delete(locator_sid);
	return CMD_SUCCESS;
}

DEFUN_NOSH (srv6_compress_locator_sid,
		srv6_compress_locator_cmd,
		"locator WORD prefix X:X::X:X/M$prefix compress-16 next \
		 [block-len (16-64)$block_bit_len] [node-len (16-64)$node_bit_len] [func-bits (16-64)$func_bit_len]",
		"Segment Routing SRv6 locator\n"
		"Specify locator-name\n"
		"Configure SRv6 locator prefix\n"
		"Specify SRv6 locator prefix\n"
		"Configure SRv6 micro-sid\n"
		"Specify SRv6 micro-sid flavor\n"
		"Configure SRv6 locator block length in bits\n"
		"Specify SRv6 locator block length in bits\n"
		"Configure SRv6 locator node length in bits\n"
		"Specify SRv6 locator node length in bits\n"
		"Configure SRv6 locator function length in bits\n"
		"Specify SRv6 locator function length in bits\n")
{
	struct srv6_locator *locator_sid = NULL;
	struct seg6_sid *sid = NULL;
	struct listnode *node = NULL;
	struct zserv *client;
	struct listnode *client_node;
	char *prefix = NULL;
	int ret = 0;
	int idx = 0;
	int block_bit_len = 0;
	int node_bit_len = 0;
	int func_bit_len = 0;
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct srv6_locator *locator;
	struct listnode *locator_node;

	locator_sid = zebra_srv6_locator_lookup(argv[1]->arg);
	if (locator_sid) {
		VTY_PUSH_CONTEXT(SRV6_LOC_NODE, locator_sid);
		locator_sid->status_up = true;
		locator_sid->compress = true;
		return CMD_SUCCESS;
	}

	locator_sid = srv6_locator_alloc(argv[1]->arg);
	if (!locator_sid) {
		vty_out(vty, "%% Alloc failed\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	locator_sid->status_up = true;
	locator_sid->compress = true;

	prefix = argv[3]->arg;
	ret = str2prefix_ipv6(prefix, &locator_sid->prefix);
	apply_mask_ipv6(&locator_sid->prefix);
	if (!ret) {
		srv6_locator_del(locator_sid);
		vty_out(vty, "Malformed IPv6 prefix\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	for (ALL_LIST_ELEMENTS_RO(srv6->locators, locator_node, locator)) {
		if (prefix_same((struct prefix *)&locator->prefix, (struct prefix *)&locator_sid->prefix)) {
			srv6_locator_del(locator_sid);
			vty_out(vty, "Duplicate locator prefix\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	if (argv_find(argv, argc, "block-len", &idx)) {
		block_bit_len = strtoul(argv[idx + 1]->arg, NULL, 10);
	}
	if (argv_find(argv, argc, "node-len", &idx)) {
		node_bit_len = strtoul(argv[idx + 1]->arg, NULL, 10);
	}
	if (argv_find(argv, argc, "func-bits", &idx)) {
		func_bit_len = strtoul(argv[idx + 1]->arg, NULL, 10);
	}

	if (locator_sid->prefix.prefixlen == 48 && block_bit_len == 32 && node_bit_len ==16 && func_bit_len == 16)
	{
		locator_sid->block_bits_length = block_bit_len;
		locator_sid->node_bits_length = node_bit_len;
		locator_sid->function_bits_length = func_bit_len;
		locator_sid->argument_bits_length = 64;
	}
	else
	{
		srv6_locator_del(locator_sid);
		vty_out(vty, "%% Malformed locator sid format, it must be block-len 32 node-len 16 func-bits 16 and prefixlen 48\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (!zebra_srv6_local_sid_get_format(locator_sid)) {
		vty_out(vty, "%% Malformed locator sid format\n");
		srv6_locator_del(locator_sid);
		return CMD_WARNING_CONFIG_FAILED;
	}

	zebra_srv6_locator_add(locator_sid);
	sid = srv6_locator_sid_alloc();
	sid->sidaction = ZEBRA_SEG6_LOCAL_ACTION_END;
	sid->sidtype = ZEBRA_SEG6_LOCAL_SID_TYPE_UN;

	if (!zebra_srv6_local_sid_format_valid(locator_sid, sid)) {
		vty_out(vty, "%% Malformed locator sid opcode format\n");
		srv6_locator_sid_free(sid);
		return CMD_WARNING_CONFIG_FAILED;
	}

	listnode_add(locator_sid->sids, sid);
	zebra_srv6_local_sid_add(locator_sid, sid);

	VTY_PUSH_CONTEXT(SRV6_LOC_NODE, locator_sid);
	vty->node = SRV6_LOC_NODE;
	return CMD_SUCCESS;
}


DEFPY (locator_prefix,
		locator_prefix_cmd,
		"opcode WORD \
		 <end | end-dt46 vrf VIEWVRFNAME [service-sid-marking] | end-dt4 vrf VIEWVRFNAME [service-sid-marking] | end-dt6 vrf VIEWVRFNAME [service-sid-marking] | \
		 end-x interface IFNAME$ifname nexthop <A.B.C.D|X:X::X:X>$nhp>",
		"Configure SRv6 locator prefix\n"
		"Specify SRv6 locator hex opcode\n"
		"Apply the code to an End SID\n"
		"Apply the code to an End.DT46 SID\n"
		"vrf\n"
		"vrf\n"
		"sid marking\n"
		"Apply the code to an End.DT4 SID\n"
		"vrf\n"
		"vrf\n"
		"sid marking\n"
		"Apply the code to an End.DT6 SID\n"
		"vrf\n"
		"vrf\n"
		"sid marking\n"
		"Apply the code to an End.X SID\n"
		"Select an interface to configure\n"
		"Interface's name\n"
		"Nexthop\n"
		"Nexthop IP address\n"
		"Nexthop IPv6 address\n")
	{
	VTY_DECLVAR_CONTEXT(srv6_locator, locator);
	struct seg6_sid *sid = NULL;
	struct seg6_sid *sid_unua = NULL;
	struct seg6_sid *sid_ua = NULL;
	struct listnode *node = NULL;
	struct listnode *node_ua = NULL;

	struct seg6_sid_endx_ecmp *sid_endx_ecmp_node = NULL;
	struct seg6_sid_endx_ecmp *sid_ua_ecmp = NULL;
	struct seg6_sid_endx_ecmp *sid_unua_ecmp = NULL;
	struct seg6_sid_endx_ecmp *sid_endx_ecmp = NULL;

	struct seg6_sid_endx_params *sid_ua_params = NULL;
	struct seg6_sid_endx_params *sid_unua_params = NULL;
	struct seg6_sid_endx_params *sid_endx_params = NULL;
	struct seg6_sid_endx_params st_sid_endx_params = {0};

	struct in6_addr result_sid_ua = {0};
	struct in6_addr result_sid_unua = {0};
	struct in6_addr result_sid_endx = {0};

	bool is_found_ua_param = false;
	bool is_found_unua_param = false;
	bool is_found_endx_param = false;
	bool sidmarking = false;

	char buf[BUFSIZ] = {0};
	enum seg6local_action_t sidaction = ZEBRA_SEG6_LOCAL_ACTION_UNSPEC;
	int idx = 0;
	char *vrfName = VRF_DEFAULT_NAME;
	char *prefix = NULL;
	int ret = 0;
	struct prefix_ipv6 ipv6prefix = {0};
	struct zserv *client;
	struct listnode *client_node;
	char *ifName = NULL;
	struct ipaddr nexthop = {0};
	char *nhpstr = NULL;
	struct listnode *sidnode, *sidnnode;
	struct seg6_sid *sid_end_x = NULL;


	if (argv_find(argv, argc, "end", &idx))
		sidaction = ZEBRA_SEG6_LOCAL_ACTION_END;
	else if (argv_find(argv, argc, "end-dt46", &idx))
	{
		sidaction = ZEBRA_SEG6_LOCAL_ACTION_END_DT46;
		vrfName = argv[idx + 2]->arg;
	}
	else if (argv_find(argv, argc, "end-dt4", &idx))
	{
		sidaction = ZEBRA_SEG6_LOCAL_ACTION_END_DT4;
		vrfName = argv[idx + 2]->arg;
	}
	else if (argv_find(argv, argc, "end-dt6", &idx))
	{
		sidaction = ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
		vrfName = argv[idx + 2]->arg;
	}
	else if (argv_find(argv, argc, "end-x", &idx))
	{
		sidaction = ZEBRA_SEG6_LOCAL_ACTION_END_X;
		nhpstr = argv[idx + 4]->arg;
		ifName = argv[idx + 2]->arg;
		if (inet_pton(AF_INET, nhpstr, &nexthop.ipaddr_v4) == 1)
			nexthop.ipa_type = IPADDR_V4;
		else if (inet_pton(AF_INET6, nhpstr, &nexthop.ipaddr_v6) == 1)
			nexthop.ipa_type = IPADDR_V6;
		else {
			vty_out(vty, "%% Malformed address\n");
			return CMD_WARNING;
		}
	}

	if (argv_find(argv, argc, "service-sid-marking", &idx)) {
		sidmarking = true;
	}

	prefix = argv[1]->arg;
	ret = str2prefix_ipv6(prefix, &ipv6prefix);
	apply_mask_ipv6(&ipv6prefix);
	if (!ret) {
		vty_out(vty, "Malformed IPv6 prefix\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	for (ALL_LIST_ELEMENTS_RO(locator->sids, node, sid)) {
		if (IPV6_ADDR_SAME(&sid->ipv6Addr.prefix, &ipv6prefix.prefix) && (sidaction != ZEBRA_SEG6_LOCAL_ACTION_END_X)) {
			vty_out(vty, "Prefix %s is already exist,please delete it first. \n", argv[1]->arg);
			return CMD_WARNING;
		}
	}

	if (strcmp(vrfName, VRF_DEFAULT_NAME) != 0) {
		sid = sid_lookup_by_vrf_action(locator, vrfName, sidaction);
		if (sid) {
			vty_out(vty, "VRF %s is already exist,please delete it first. \n",vrfName);
			return CMD_WARNING;
		}
	}

	if (locator->compress) {
		if (sidaction == ZEBRA_SEG6_LOCAL_ACTION_END_X) {
			// check ecmp
			combine_hide_sid(locator, &ipv6prefix.prefix, &result_sid_ua, ZEBRA_SEG6_LOCAL_SID_TYPE_UA);
			combine_sid(locator, &ipv6prefix.prefix, &result_sid_unua);

			strlcpy(st_sid_endx_params.ifname, ifName, INTERFACE_NAMSIZ);
			memcpy(&st_sid_endx_params.nexthop, &nexthop, sizeof(struct ipaddr));

			for (ALL_LIST_ELEMENTS_RO(locator->sid_endx_ecmps, node, sid_endx_ecmp_node)) {
				if (IPV6_ADDR_SAME(&sid_endx_ecmp_node->ipv6Addr.prefix, &result_sid_ua)) {					
					if (seg6_sid_endx_param_lookup(sid_endx_ecmp_node->sid_endx_params, &st_sid_endx_params) == NULL)
					{
						is_found_ua_param = false;
					}
					else
					{
						is_found_ua_param = true;
					}

					sid_ua_ecmp = sid_endx_ecmp_node;
				}
			}

			for (ALL_LIST_ELEMENTS_RO(locator->sid_endx_ecmps, node, sid_endx_ecmp_node)) {
				if (IPV6_ADDR_SAME(&sid_endx_ecmp_node->ipv6Addr.prefix, &result_sid_unua)) {
					if (seg6_sid_endx_param_lookup(sid_endx_ecmp_node->sid_endx_params, &st_sid_endx_params) == NULL)
					{
						is_found_unua_param = false;
					}
					else
					{
						is_found_unua_param = true;
					}

					sid_unua_ecmp = sid_endx_ecmp_node;
				}
			}

			if (is_found_ua_param == true && is_found_unua_param == false)
			{
				vty_out(vty, "%% UA ifName %s and nexthop is already exist.\n", ifName);
				return CMD_WARNING;
			}
			else if (is_found_ua_param == false && is_found_unua_param == true)
			{
				vty_out(vty, "%% UNUA ifName %s and nexthop is already exist.\n", ifName);
				return CMD_WARNING;
			}
			else if (is_found_ua_param == true &&  is_found_unua_param == true)
			{
				vty_out(vty, "%% UA and UNUA ifName %s and nexthop is already exist.\n", ifName);
				return CMD_WARNING;
			}

			// uA
			/* first create uA */
			if (!sid_ua_ecmp)
			{
				sid_ua_ecmp = srv6_locator_sid_endx_ecmp_alloc();
				sid_ua_ecmp->ipv6Addr.family = AF_INET6;
				sid_ua_ecmp->ipv6Addr.prefixlen = 48;
				IPV6_ADDR_COPY(&sid_ua_ecmp->ipv6Addr.prefix, &result_sid_ua);
				listnode_add(locator->sid_endx_ecmps, sid_ua_ecmp);
			}

			sid_ua_params = srv6_locator_sid_endx_params_alloc();
			strlcpy(sid_ua_params->ifname, ifName, INTERFACE_NAMSIZ);
			memcpy(&sid_ua_params->nexthop, &nexthop, sizeof(struct ipaddr));
			listnode_add(sid_ua_ecmp->sid_endx_params, sid_ua_params);

			// uN + uA
			/* first create uN + uA */
			if (!sid_unua_ecmp)
			{
				sid_unua_ecmp = srv6_locator_sid_endx_ecmp_alloc();
				sid_unua_ecmp->ipv6Addr.family = AF_INET6;
				sid_unua_ecmp->ipv6Addr.prefixlen = 64;
				IPV6_ADDR_COPY(&sid_unua_ecmp->ipv6Addr.prefix, &result_sid_unua);
				listnode_add(locator->sid_endx_ecmps, sid_unua_ecmp);
			}

			sid_unua_params = srv6_locator_sid_endx_params_alloc();
			strlcpy(sid_unua_params->ifname, ifName, INTERFACE_NAMSIZ);
			memcpy(&sid_unua_params->nexthop, &nexthop, sizeof(struct ipaddr));
			listnode_add(sid_unua_ecmp->sid_endx_params, sid_unua_params);
		

			//uN+uA
			sid_unua = srv6_locator_sid_alloc();
			sid_unua->sidaction = sidaction;
			sid_unua->sidtype = ZEBRA_SEG6_LOCAL_SID_TYPE_UNUA;

			if (vrfName != NULL)
				strlcpy(sid_unua->vrfName, vrfName, VRF_ALIASNAMESIZ);

			sid_unua->ipv6Addr = ipv6prefix;
			strncpy(sid_unua->sidstr, prefix, PREFIX_STRLEN);
			if (ifName)
				strlcpy(sid_unua->ifname, ifName, INTERFACE_NAMSIZ);
			else
				sid_unua->ifname[0] = '\0';
			memcpy(&sid_unua->nexthop, &nexthop, sizeof(struct ipaddr));

			if (!zebra_srv6_local_sid_format_valid(locator, sid_unua)) {
				vty_out(vty, "%% Malformed locator sid_unua opcode format\n");
				srv6_locator_sid_free(sid_unua);

				/* free unua resource */
				listnode_delete(sid_unua_ecmp->sid_endx_params, sid_unua_params);
				srv6_locator_sid_endx_params_free(sid_unua_params);
				seg6_sid_endx_ecmp_free(locator,sid_unua_ecmp);

				/* free ua resource */
				listnode_delete(sid_ua_ecmp->sid_endx_params, sid_ua_params);
				srv6_locator_sid_endx_params_free(sid_ua_params);
				seg6_sid_endx_ecmp_free(locator,sid_ua_ecmp);

				return CMD_WARNING_CONFIG_FAILED;
			}

			listnode_add(locator->sids, sid_unua);
			zebra_srv6_local_sid_add(locator, sid_unua);

			//uA
			sid_ua = srv6_locator_sid_alloc();
			sid_ua->sidaction = sidaction;
			sid_ua->sidtype = ZEBRA_SEG6_LOCAL_SID_TYPE_UA;

			if (vrfName != NULL)
				strlcpy(sid_ua->vrfName, vrfName, VRF_ALIASNAMESIZ);

			sid_ua->ipv6Addr = ipv6prefix;
			strncpy(sid_ua->sidstr, prefix, PREFIX_STRLEN);
			if (ifName)
				strlcpy(sid_ua->ifname, ifName, INTERFACE_NAMSIZ);
			else
				sid_ua->ifname[0] = '\0';
			memcpy(&sid_ua->nexthop, &nexthop, sizeof(struct ipaddr));

			if (!zebra_srv6_local_sid_format_valid(locator, sid_ua)) {
				vty_out(vty, "%% Malformed locator sid_ua opcode format\n");
				srv6_locator_sid_free(sid_ua);

				/* free ua resource */
				listnode_delete(sid_ua_ecmp->sid_endx_params, sid_ua_params);
				srv6_locator_sid_endx_params_free(sid_ua_params);
				seg6_sid_endx_ecmp_free(locator,sid_ua_ecmp);

				return CMD_WARNING_CONFIG_FAILED;
			}

			listnode_add(locator->sids, sid_ua);
			zebra_srv6_local_sid_add(locator, sid_ua);
		}
		else {
			vty_out(vty, "locator is compressd, only support opcode end-x\n");
			return CMD_WARNING;
		}
	}
	else
	{
		if (sidaction == ZEBRA_SEG6_LOCAL_ACTION_END_X) 
		{
			combine_sid(locator, &ipv6prefix.prefix, &result_sid_endx);
			strlcpy(st_sid_endx_params.ifname, ifName, INTERFACE_NAMSIZ);
			memcpy(&st_sid_endx_params.nexthop, &nexthop, sizeof(struct ipaddr));

			for (ALL_LIST_ELEMENTS_RO(locator->sid_endx_ecmps, node, sid_endx_ecmp_node)) {
				if (IPV6_ADDR_SAME(&sid_endx_ecmp_node->ipv6Addr.prefix, &result_sid_endx)) {					
					if (seg6_sid_endx_param_lookup(sid_endx_ecmp_node->sid_endx_params, &st_sid_endx_params) == NULL)
					{
						is_found_endx_param = false;
					}
					else
					{
						is_found_endx_param = true;
					}

					sid_endx_ecmp = sid_endx_ecmp_node;
				}
			}

			if (is_found_endx_param == true)
			{
				vty_out(vty, "%% endx ifName %s and nexthop is already exist.\n", ifName);
				return CMD_WARNING;
			}

			if (!sid_endx_ecmp)
			{
				sid_endx_ecmp = srv6_locator_sid_endx_ecmp_alloc();
				sid_endx_ecmp->ipv6Addr.family = AF_INET6;
				sid_endx_ecmp->ipv6Addr.prefixlen = locator->block_bits_length + locator->node_bits_length;
				IPV6_ADDR_COPY(&sid_endx_ecmp->ipv6Addr.prefix, &result_sid_endx);
				listnode_add(locator->sid_endx_ecmps, sid_endx_ecmp);
			}

			sid_endx_params = srv6_locator_sid_endx_params_alloc();
			strlcpy(sid_endx_params->ifname, ifName, INTERFACE_NAMSIZ);
			memcpy(&sid_endx_params->nexthop, &nexthop, sizeof(struct ipaddr));
			listnode_add(sid_endx_ecmp->sid_endx_params, sid_endx_params);
		}
		
		sid = srv6_locator_sid_alloc();
		sid->sidaction = sidaction;
		sid->sidtype = ZEBRA_SEG6_LOCAL_SID_TYPE_DEFAULT;
		sid->sidmarking = sidmarking;

		if (vrfName != NULL)
			strlcpy(sid->vrfName, vrfName, VRF_ALIASNAMESIZ);

		sid->ipv6Addr = ipv6prefix;
		strncpy(sid->sidstr, prefix, PREFIX_STRLEN);
		if (ifName)
			strlcpy(sid->ifname, ifName, INTERFACE_NAMSIZ);
		else
			sid->ifname[0] = '\0';
		memcpy(&sid->nexthop, &nexthop, sizeof(struct ipaddr));

		if (!zebra_srv6_local_sid_format_valid(locator, sid)) {
			srv6_locator_sid_free(sid);
			if (sidaction == ZEBRA_SEG6_LOCAL_ACTION_END_X) 
			{
				listnode_delete(sid_endx_ecmp->sid_endx_params, sid_endx_params);
				srv6_locator_sid_endx_params_free(sid_endx_params);			
				seg6_sid_endx_ecmp_free(locator,sid_endx_ecmp);
			}
			vty_out(vty, "%% Malformed locator sid opcode format\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		listnode_add(locator->sids, sid);
		zebra_srv6_local_sid_add(locator, sid);
		if (ZEBRA_SEG6_ACTION_IS_END_DT46(sidaction)) {
			for (ALL_LIST_ELEMENTS_RO(zrouter.client_list, client_node, client)) {
				zsend_srv6_manager_get_locator_sid_response(client, VRF_DEFAULT, locator, sid);
			}
		}
	}

	return CMD_SUCCESS;
}

DEFPY (no_locator_prefix,
       no_locator_prefix_cmd,
       "no opcode WORD",
       NO_STR
       "Configure SRv6 locator prefix\n"
       "Specify SRv6 locator hex opcode\n"
       )
{
	VTY_DECLVAR_CONTEXT(srv6_locator, locator);
	struct seg6_sid *sid = NULL;
	struct listnode *node, *next;
    char *prefix = NULL;
    int ret = 0;
    struct prefix_ipv6 ipv6prefix = {0};
    struct zserv *client;
    struct listnode *client_node;
	struct in6_addr result_sid_endx = {0};
	struct in6_addr result_sid_ua = {0};
	struct in6_addr result_sid_unua = {0};
	struct seg6_sid_endx_ecmp *sid_ecmp_index = NULL;
	struct seg6_sid_endx_ecmp *sid_endx_ecmp = NULL;
	struct seg6_sid_endx_ecmp *sid_unua_ecmp = NULL;
	struct seg6_sid_endx_ecmp *sid_ua_ecmp = NULL;
	struct seg6_sid_endx_params *sid_endx_params = NULL;

    prefix = argv[2]->arg;
    ret = str2prefix_ipv6(prefix, &ipv6prefix);
	if (!ret) {
		vty_out(vty, "Malformed IPv6 prefix\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (locator->compress)
	{
		combine_hide_sid(locator, &ipv6prefix.prefix, &result_sid_ua, ZEBRA_SEG6_LOCAL_SID_TYPE_UA);
		combine_sid(locator, &ipv6prefix.prefix, &result_sid_unua);
		for (ALL_LIST_ELEMENTS_RO(locator->sid_endx_ecmps, node, sid_ecmp_index)) {
			if (IPV6_ADDR_SAME(&sid_ecmp_index->ipv6Addr.prefix, &result_sid_ua)) {
				sid_ua_ecmp = sid_ecmp_index;
				for (ALL_LIST_ELEMENTS(sid_ecmp_index->sid_endx_params, node, next, sid_endx_params)) {
					listnode_delete(sid_ecmp_index->sid_endx_params, sid_endx_params);
					srv6_locator_sid_endx_params_free(sid_endx_params);
				}
			}
		}

		for (ALL_LIST_ELEMENTS_RO(locator->sid_endx_ecmps, node, sid_ecmp_index)) {
			if (IPV6_ADDR_SAME(&sid_ecmp_index->ipv6Addr.prefix, &result_sid_unua)) {
				sid_unua_ecmp = sid_ecmp_index;
				for (ALL_LIST_ELEMENTS(sid_ecmp_index->sid_endx_params, node, next, sid_endx_params)) {
					listnode_delete(sid_ecmp_index->sid_endx_params, sid_endx_params);
					srv6_locator_sid_endx_params_free(sid_endx_params);
				}
			}
		}

		seg6_sid_endx_ecmp_free(locator,sid_ua_ecmp);
		seg6_sid_endx_ecmp_free(locator,sid_unua_ecmp);
	}
	else
	{
		combine_sid(locator, &ipv6prefix.prefix, &result_sid_endx);
		for (ALL_LIST_ELEMENTS_RO(locator->sid_endx_ecmps, node, sid_ecmp_index)) {
			if (IPV6_ADDR_SAME(&sid_ecmp_index->ipv6Addr.prefix, &result_sid_endx)) {
				sid_endx_ecmp = sid_ecmp_index;
				for (ALL_LIST_ELEMENTS(sid_ecmp_index->sid_endx_params, node, next, sid_endx_params)) {
					listnode_delete(sid_ecmp_index->sid_endx_params, sid_endx_params);
					srv6_locator_sid_endx_params_free(sid_endx_params);
				}
			}
		}
		seg6_sid_endx_ecmp_free(locator,sid_endx_ecmp);
	}

	for (ALL_LIST_ELEMENTS(locator->sids, node, next, sid)) {
		if (IPV6_ADDR_SAME(&sid->ipv6Addr.prefix, &ipv6prefix.prefix) && (sid->sidtype != ZEBRA_SEG6_LOCAL_SID_TYPE_UN)) {
			if (ZEBRA_SEG6_ACTION_IS_END_DT46(sid->sidaction)) {
				for (ALL_LIST_ELEMENTS_RO(zrouter.client_list, client_node, client)) {
					zsend_srv6_manager_del_sid(client, VRF_DEFAULT, locator, sid);
				}
			}
			zebra_srv6_local_sid_del(locator, sid);
			listnode_delete(locator->sids, sid);
			srv6_locator_sid_free(sid);
		}		
	}

	return CMD_SUCCESS;
}

DEFPY (no_locator_endx_prefix,
       no_locator_endx_prefix_cmd,
       "no opcode WORD end-x interface IFNAME$ifname nexthop <A.B.C.D|X:X::X:X>$nhp",
       NO_STR
       "Configure SRv6 locator prefix\n"
       "Specify SRv6 locator hex opcode\n"
       "Apply the code to an End.X SID\n"
       "Select an interface to configure\n"
       "Interface's name\n"
       "Nexthop\n"
       "Nexthop IP address\n"
       "Nexthop IPv6 address\n"
       )
{
	VTY_DECLVAR_CONTEXT(srv6_locator, locator);
	struct seg6_sid *sid = NULL;
	struct listnode *node, *next;
    char *prefix = NULL;
    int ret = 0;
    struct prefix_ipv6 ipv6prefix = {0};
    struct zserv *client;
    struct listnode *client_node;

	struct seg6_sid_endx_ecmp *sid_ecmp_index = NULL;
	struct seg6_sid_endx_ecmp *sid_ua_ecmp = NULL;
	struct seg6_sid_endx_ecmp *sid_unua_ecmp = NULL;
	struct seg6_sid_endx_ecmp *sid_endx_ecmp = NULL;

	struct seg6_sid_endx_params *sid_endx_params = NULL;
	struct seg6_sid_endx_params *sid_ua_params = NULL;
	struct seg6_sid_endx_params *sid_unua_params = NULL;

	struct in6_addr result_sid_ua = {0};
	struct in6_addr result_sid_unua = {0};
	struct in6_addr result_sid_endx = {0};

	char *ifName = NULL;
	struct ipaddr nexthop = {0};
	char *nhpstr = NULL;
    int idx = 0;
	bool is_found_ua = false;
	bool is_found_unua = false;
	bool is_found_endx = false;
	int ecmp_member_ua_cnt = 0;
	int ecmp_member_unua_cnt = 0;
	int ecmp_member_endx_cnt = 0;
	char *vrfName = VRF_DEFAULT_NAME;
	struct seg6local_context ctx = {};


    prefix = argv[2]->arg;
    ret = str2prefix_ipv6(prefix, &ipv6prefix);
	if (!ret) {
		vty_out(vty, "Malformed IPv6 prefix\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (argv_find(argv, argc, "end-x", &idx))
	{
		nhpstr = argv[idx + 4]->arg;
		ifName = argv[idx + 2]->arg;
		if (inet_pton(AF_INET, nhpstr, &nexthop.ipaddr_v4) == 1)
			nexthop.ipa_type = IPADDR_V4;
		else if (inet_pton(AF_INET6, nhpstr, &nexthop.ipaddr_v6) == 1)
			nexthop.ipa_type = IPADDR_V6;
		else {
			vty_out(vty, "%% Malformed address\n");
			return CMD_WARNING;
		}
	}
	else
	{
		vty_out(vty, "%% invalid cmd\n");
		return CMD_WARNING;
	}

	
	if (locator->compress == true)
	{
		combine_hide_sid(locator, &ipv6prefix.prefix, &result_sid_ua, ZEBRA_SEG6_LOCAL_SID_TYPE_UA);
		combine_sid(locator, &ipv6prefix.prefix, &result_sid_unua);
	
		for (ALL_LIST_ELEMENTS_RO(locator->sid_endx_ecmps, node, sid_ecmp_index)) {
			if (IPV6_ADDR_SAME(&sid_ecmp_index->ipv6Addr.prefix, &result_sid_ua)) {
				for (ALL_LIST_ELEMENTS(sid_ecmp_index->sid_endx_params, node, next, sid_ua_params)) {
					if (!strcmp(sid_ua_params->ifname, ifName) && !ipaddr_cmp(&sid_ua_params->nexthop, &nexthop)) {
						sid_ua_ecmp = sid_ecmp_index;
						sid = sid_lookup_by_prefix_intf_nhp(locator, &ipv6prefix, ifName, &nexthop, ZEBRA_SEG6_LOCAL_SID_TYPE_UA);
						if (!sid)
						{
							vty_out(vty, "%% find ua sid fail, ifname:%s\n", ifName);
							return CMD_WARNING;
						}
						if (list_count(sid_ecmp_index->sid_endx_params) > 1)
						{
							listnode_delete(locator->sids, sid);
							srv6_locator_sid_free(sid);	
						}
						listnode_delete(sid_ecmp_index->sid_endx_params, sid_ua_params);
						srv6_locator_sid_endx_params_free(sid_ua_params);
						is_found_ua = true;
					}
				}
			}
		}

		for (ALL_LIST_ELEMENTS_RO(locator->sid_endx_ecmps, node, sid_ecmp_index)) {
			if (IPV6_ADDR_SAME(&sid_ecmp_index->ipv6Addr.prefix, &result_sid_unua)) {
				for (ALL_LIST_ELEMENTS(sid_ecmp_index->sid_endx_params, node, next, sid_unua_params)) {
					if (!strcmp(sid_unua_params->ifname, ifName) && !ipaddr_cmp(&sid_unua_params->nexthop,  &nexthop)) {
						sid_unua_ecmp = sid_ecmp_index;
						sid = sid_lookup_by_prefix_intf_nhp(locator, &ipv6prefix, ifName, &nexthop, ZEBRA_SEG6_LOCAL_SID_TYPE_UNUA);
						if (!sid)
						{
							vty_out(vty, "%% find unua sid fail, ifname:%s\n", ifName);
							return CMD_WARNING;
						}
						if (list_count(sid_ecmp_index->sid_endx_params) > 1)
						{
							listnode_delete(locator->sids, sid);
							srv6_locator_sid_free(sid);	
						}
						listnode_delete(sid_ecmp_index->sid_endx_params, sid_unua_params);
						srv6_locator_sid_endx_params_free(sid_unua_params);
						is_found_unua = true;
					}
				}
			}
		}

		if (!is_found_ua)
		{
			vty_out(vty, "%% del opcode fail: invalid ua sid\n");
			return CMD_WARNING;
		}

		if (!is_found_unua)
		{
			vty_out(vty, "%% del opcode fail: invalid unua sid\n");
			return CMD_WARNING;		
		}
		
		ecmp_member_ua_cnt = list_count(sid_ua_ecmp->sid_endx_params);
		ecmp_member_unua_cnt = list_count(sid_unua_ecmp->sid_endx_params);

		if (ecmp_member_ua_cnt >= 1)
		{
			ctx.block_bits_length = locator->block_bits_length;
			ctx.node_bits_length = 0;
			ctx.function_bits_length = locator->function_bits_length;
			ctx.argument_bits_length = locator->argument_bits_length;

			zebra_Db_Set_SRV6_LOCAL_ENDX_SID(&result_sid_ua, vrfName, ZEBRA_SEG6_LOCAL_ACTION_END_X, &ctx, sid_ua_ecmp->sid_endx_params);
		}

		if (ecmp_member_unua_cnt >= 1)
		{
			ctx.block_bits_length = locator->block_bits_length;
			ctx.node_bits_length = locator->node_bits_length;
			ctx.function_bits_length = locator->function_bits_length;
			ctx.argument_bits_length = locator->argument_bits_length;

			zebra_Db_Set_SRV6_LOCAL_ENDX_SID(&result_sid_unua, vrfName, ZEBRA_SEG6_LOCAL_ACTION_END_X, &ctx, sid_ua_ecmp->sid_endx_params);
		}


		if (ecmp_member_unua_cnt == 0)
		{
			for (ALL_LIST_ELEMENTS(locator->sids, node, next, sid)) {
				if (IPV6_ADDR_SAME(&sid->ipv6Addr.prefix, &ipv6prefix.prefix) && (sid->sidtype == ZEBRA_SEG6_LOCAL_SID_TYPE_UNUA)) {
					/* free unua ecmp resource */
					listnode_delete(locator->sid_endx_ecmps, sid_unua_ecmp);
					srv6_locator_sid_endx_ecmp_free(sid_unua_ecmp);

					/* free sid */
					zebra_srv6_local_sid_del(locator, sid);
					listnode_delete(locator->sids, sid);
					srv6_locator_sid_free(sid);
				}
			}
		}

		// unua and ua ecmp member must be same
		if (ecmp_member_ua_cnt == 0)
		{
			for (ALL_LIST_ELEMENTS(locator->sids, node, next, sid)) {
				if (IPV6_ADDR_SAME(&sid->ipv6Addr.prefix, &ipv6prefix.prefix) && (sid->sidtype == ZEBRA_SEG6_LOCAL_SID_TYPE_UA)) {
					/* free ua ecmp resource */
					listnode_delete(locator->sid_endx_ecmps, sid_ua_ecmp);
					srv6_locator_sid_endx_ecmp_free(sid_ua_ecmp);

					/* free sid */
					zebra_srv6_local_sid_del(locator, sid);
					listnode_delete(locator->sids, sid);
					srv6_locator_sid_free(sid);
				}
			}
		}
	}
	else
	{
		combine_sid(locator, &ipv6prefix.prefix, &result_sid_endx);
	
		for (ALL_LIST_ELEMENTS_RO(locator->sid_endx_ecmps, node, sid_ecmp_index)) {
			if (IPV6_ADDR_SAME(&sid_ecmp_index->ipv6Addr.prefix, &result_sid_endx)) {
				for (ALL_LIST_ELEMENTS(sid_ecmp_index->sid_endx_params, node, next, sid_endx_params)) {
					if (!strcmp(sid_endx_params->ifname, ifName) && !ipaddr_cmp(&sid_endx_params->nexthop, &nexthop)) {
						sid_endx_ecmp = sid_ecmp_index;
						sid = sid_lookup_by_prefix_intf_nhp(locator, &ipv6prefix, ifName, &nexthop, ZEBRA_SEG6_LOCAL_SID_TYPE_DEFAULT);
						if (!sid)
						{
							vty_out(vty, "%% find endx sid fail, ifname:%s\n", ifName);
							return CMD_WARNING;
						}
						
						if (list_count(sid_ecmp_index->sid_endx_params) > 1)
						{
							listnode_delete(locator->sids, sid);
							srv6_locator_sid_free(sid);
						}
	
						listnode_delete(sid_ecmp_index->sid_endx_params, sid_endx_params);
						srv6_locator_sid_endx_params_free(sid_endx_params);
						is_found_endx = true;
					}
				}
			}
		}

		if (!is_found_endx)
		{
			vty_out(vty, "%% del opcode fail: invalid endx sid\n");
			return CMD_WARNING;
		}
		
		ecmp_member_endx_cnt = list_count(sid_endx_ecmp->sid_endx_params);

		if (ecmp_member_endx_cnt >= 1)
		{
			ctx.block_bits_length = locator->block_bits_length;
			ctx.node_bits_length = locator->node_bits_length;
			ctx.function_bits_length = locator->function_bits_length;
			ctx.argument_bits_length = locator->argument_bits_length;

			zebra_Db_Set_SRV6_LOCAL_ENDX_SID(&result_sid_endx, vrfName, ZEBRA_SEG6_LOCAL_ACTION_END_X, &ctx, sid_endx_ecmp->sid_endx_params);
		}

		if (ecmp_member_endx_cnt == 0)
		{
			for (ALL_LIST_ELEMENTS(locator->sids, node, next, sid)) {
				if (IPV6_ADDR_SAME(&sid->ipv6Addr.prefix, &ipv6prefix.prefix) && (sid->sidtype == ZEBRA_SEG6_LOCAL_SID_TYPE_DEFAULT)) {
					/* free endx ecmp resource */
					listnode_delete(locator->sid_endx_ecmps, sid_endx_ecmp);
					srv6_locator_sid_endx_ecmp_free(sid_endx_ecmp);

					/* free sid */
					zebra_srv6_local_sid_del(locator, sid);
					listnode_delete(locator->sids, sid);
					srv6_locator_sid_free(sid);
				}
			}
		}
	}
	
	
    return CMD_SUCCESS;
}

DEFUN_NOSH (srv6_encap,
            srv6_encap_cmd,
            "encapsulation",
            "Segment Routing SRv6 encapsulation\n")
{
	vty->node = SRV6_ENCAP_NODE;
	return CMD_SUCCESS;
}

DEFPY (srv6_src_addr,
       srv6_src_addr_cmd,
       "source-address X:X::X:X$encap_src_addr",
       "Segment Routing SRv6 source address\n"
       "Specify source address for SRv6 encapsulation\n")
{
	zebra_srv6_encap_src_addr_set(&encap_src_addr);
	return CMD_SUCCESS;
}

DEFPY (no_srv6_src_addr,
       no_srv6_src_addr_cmd,
       "no source-address [X:X::X:X$encap_src_addr]",
       NO_STR
       "Segment Routing SRv6 source address\n"
       "Specify source address for SRv6 encapsulation\n")
{
	zebra_srv6_encap_src_addr_unset();
	return CMD_SUCCESS;
}

static int zebra_sr_config(struct vty *vty)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct listnode *node, *opcodenode;
	struct srv6_locator *locator;
    struct seg6_sid *sid;
	char str[256];
	char buf[INET6_ADDRSTRLEN];

	vty_out(vty, "!\n");
	if (zebra_srv6_is_enable()) {
		vty_out(vty, "segment-routing\n");
		vty_out(vty, " srv6\n");
		if (!IPV6_ADDR_SAME(&srv6->encap_src_addr, &in6addr_any)) {
			vty_out(vty, "  encapsulation\n");
			vty_out(vty, "   source-address %pI6\n",
				&srv6->encap_src_addr);
		}
		vty_out(vty, "  locators\n");
		for (ALL_LIST_ELEMENTS_RO(srv6->locators, node, locator)) {
			inet_ntop(AF_INET6, &locator->prefix.prefix,
				  str, sizeof(str));
			vty_out(vty, "   locator %s", locator->name);
			vty_out(vty, " prefix %s/%u", str,
				locator->prefix.prefixlen);
			if (locator->compress)
				vty_out(vty, " compress-16 next");
			if (locator->node_bits_length)
				vty_out(vty, " block-len %u", locator->block_bits_length);
			if (locator->function_bits_length)
				vty_out(vty, " node-len %u", locator->node_bits_length);
			if (locator->block_bits_length)
				vty_out(vty, " func-bits %u", locator->function_bits_length);
			if (locator->compress == false) {
				if (locator->argument_bits_length)
					vty_out(vty, " argu-bits %u", locator->argument_bits_length);
			}
			vty_out(vty, "\n");
			for (ALL_LIST_ELEMENTS_RO(locator->sids, opcodenode, sid)) {
				if (sid->sidtype == ZEBRA_SEG6_LOCAL_SID_TYPE_UA || sid->sidtype == ZEBRA_SEG6_LOCAL_SID_TYPE_UN)
					continue;
				vty_out(vty, "    opcode %s", sid->sidstr);
				if (sid->sidaction == ZEBRA_SEG6_LOCAL_ACTION_END)
					vty_out(vty, " end");
				else if (sid->sidaction == ZEBRA_SEG6_LOCAL_ACTION_END_DT4) {
					vty_out(vty, " end-dt4");
					vty_out(vty, " vrf %s", sid->vrfName);
					if (sid->sidmarking)
						vty_out(vty, " service-sid-marking");
				}
				else if (sid->sidaction == ZEBRA_SEG6_LOCAL_ACTION_END_DT6) {
					vty_out(vty, " end-dt6");
					vty_out(vty, " vrf %s", sid->vrfName);
					if (sid->sidmarking)
						vty_out(vty, " service-sid-marking");
				}
				else if (sid->sidaction == ZEBRA_SEG6_LOCAL_ACTION_END_DT46) {
					vty_out(vty, " end-dt46");
					vty_out(vty, " vrf %s", sid->vrfName);
					if (sid->sidmarking)
						vty_out(vty, " service-sid-marking");
				}
				else if (sid->sidaction == ZEBRA_SEG6_LOCAL_ACTION_END_X) {
					vty_out(vty, " end-x");
					vty_out(vty, " interface %s", sid->ifname);
					if (sid->nexthop.ipa_type == IPADDR_V4)
						inet_ntop(AF_INET, &sid->nexthop.ipaddr_v4, buf, sizeof(buf));
					else if (sid->nexthop.ipa_type == IPADDR_V6)
						inet_ntop(AF_INET6, &sid->nexthop.ipaddr_v6, buf, sizeof(buf));
					vty_out(vty, " nexthop %s", buf);
				}
				vty_out(vty, "\n");
			}
			vty_out(vty, "\n");
			vty_out(vty, "   exit\n");
			vty_out(vty, "   !\n");
		}
        vty_out(vty, "  exit\n");
		vty_out(vty, "  !\n");
		vty_out(vty, " !\n");
		vty_out(vty, "!\n");
	}
	return 0;
}

void zebra_srv6_vty_init(void)
{
	/* Install nodes and its default commands */
	install_node(&sr_node);
	install_node(&srv6_node);
	install_node(&srv6_locs_node);
	install_node(&srv6_loc_node);
	install_node(&srv6_encap_node);
	install_default(SEGMENT_ROUTING_NODE);
	install_default(SRV6_NODE);
	install_default(SRV6_LOCS_NODE);
	install_default(SRV6_LOC_NODE);
	install_default(SRV6_ENCAP_NODE);

	/* Command for change node */
	install_element(CONFIG_NODE, &segment_routing_cmd);
	install_element(SEGMENT_ROUTING_NODE, &srv6_cmd);
	install_element(SEGMENT_ROUTING_NODE, &no_srv6_cmd);
	install_element(SRV6_NODE, &srv6_locators_cmd);
	install_element(SRV6_NODE, &srv6_encap_cmd);
	install_element(SRV6_LOCS_NODE, &srv6_locator_cmd);
	install_element(SRV6_LOCS_NODE, &no_srv6_locator_cmd);
	install_element(SRV6_LOCS_NODE, &srv6_compress_locator_cmd);

	/* Command for configuration */
	install_element(SRV6_LOC_NODE, &locator_prefix_cmd);
    install_element(SRV6_LOC_NODE, &no_locator_prefix_cmd);
	install_element(SRV6_LOC_NODE, &no_locator_endx_prefix_cmd);
	install_element(SRV6_ENCAP_NODE, &srv6_src_addr_cmd);
	install_element(SRV6_ENCAP_NODE, &no_srv6_src_addr_cmd);

	/* Command for operation */
	install_element(VIEW_NODE, &show_srv6_locator_cmd);
	install_element(VIEW_NODE, &show_srv6_locator_detail_cmd);
    install_element(VIEW_NODE, &show_srv6_tunnel_cmd);
	install_element(VIEW_NODE, &show_srv6_manager_cmd);
}
