/*
 * SRv6 definitions
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

#include "zebra.h"

#include "lib/srv6.h"
#include "log.h"
DEFINE_QOBJ_TYPE(srv6_locator);
DEFINE_MTYPE_STATIC(LIB, SRV6_LOCATOR, "SRV6 locator");
DEFINE_MTYPE_STATIC(LIB, SRV6_LOCATOR_CHUNK, "SRV6 locator chunk");
DEFINE_MTYPE_STATIC(LIB, SRV6_SID_ENDX_ECMP, "SRV6 locator endx sid ecmp");
DEFINE_MTYPE_STATIC(LIB, SRV6_SID_ENDX_PARAMS, "SRV6 locator endx sid ecmp params");

const char *seg6local_action2str(uint32_t action)
{
	switch (action) {
	case ZEBRA_SEG6_LOCAL_ACTION_END:
		return "End";
	case ZEBRA_SEG6_LOCAL_ACTION_END_X:
		return "End.X";
	case ZEBRA_SEG6_LOCAL_ACTION_END_T:
		return "End.T";
	case ZEBRA_SEG6_LOCAL_ACTION_END_DX2:
		return "End.DX2";
	case ZEBRA_SEG6_LOCAL_ACTION_END_DX6:
		return "End.DX6";
	case ZEBRA_SEG6_LOCAL_ACTION_END_DX4:
		return "End.DX4";
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT6:
		return "End.DT6";
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT4:
		return "End.DT4";
    case ZEBRA_SEG6_LOCAL_ACTION_END_DT46:
		return "End.DT46";
	case ZEBRA_SEG6_LOCAL_ACTION_END_B6:
		return "End.B6";
	case ZEBRA_SEG6_LOCAL_ACTION_END_B6_ENCAP:
		return "End.B6.Encap";
	case ZEBRA_SEG6_LOCAL_ACTION_END_BM:
		return "End.BM";
	case ZEBRA_SEG6_LOCAL_ACTION_END_S:
		return "End.S";
	case ZEBRA_SEG6_LOCAL_ACTION_END_AS:
		return "End.AS";
	case ZEBRA_SEG6_LOCAL_ACTION_END_AM:
		return "End.AM";
	case ZEBRA_SEG6_LOCAL_ACTION_END_UDX6:
		return "End.UDX6";
	case ZEBRA_SEG6_LOCAL_ACTION_END_UDX4:
		return "End.UDX4";
	case ZEBRA_SEG6_LOCAL_ACTION_END_UDT6:
		return "End.UDT6";
	case ZEBRA_SEG6_LOCAL_ACTION_END_UDT4:
		return "End.UDT4";
	case ZEBRA_SEG6_LOCAL_ACTION_END_UDT46:
		return "End.UDT46";
	case ZEBRA_SEG6_LOCAL_ACTION_END_UN:
		return "End.UN";
	case ZEBRA_SEG6_LOCAL_ACTION_END_UA:
		return "End.UA";
	case ZEBRA_SEG6_LOCAL_ACTION_UNSPEC:
		return "unspec";
	default:
		return "unknown";
	}
}

int snprintf_seg6_segs(char *str,
		size_t size, const struct seg6_segs *segs)
{
	str[0] = '\0';
	for (size_t i = 0; i < segs->num_segs; i++) {
		char addr[INET6_ADDRSTRLEN];
		bool not_last = (i + 1) < segs->num_segs;

		inet_ntop(AF_INET6, &segs->segs[i], addr, sizeof(addr));
		strlcat(str, addr, size);
		strlcat(str, not_last ? "," : "", size);
	}
	return strlen(str);
}

const char *seg6local_context2str(char *str, size_t size,
				  const struct seg6local_context *ctx,
				  uint32_t action)
{
	char b0[128];

	switch (action) {

	case ZEBRA_SEG6_LOCAL_ACTION_END:
	case ZEBRA_SEG6_LOCAL_ACTION_END_UN:
		snprintf(str, size, "USP");
		return str;

	case ZEBRA_SEG6_LOCAL_ACTION_END_X:
	case ZEBRA_SEG6_LOCAL_ACTION_END_DX6:
	case ZEBRA_SEG6_LOCAL_ACTION_END_UDX6:
	case ZEBRA_SEG6_LOCAL_ACTION_END_UA:
		inet_ntop(AF_INET6, &ctx->nh6, b0, 128);
		snprintf(str, size, "nh6 %s", b0);
		return str;

	case ZEBRA_SEG6_LOCAL_ACTION_END_DX4:
	case ZEBRA_SEG6_LOCAL_ACTION_END_UDX4:
		inet_ntop(AF_INET, &ctx->nh4, b0, 128);
		snprintf(str, size, "nh4 %s", b0);
		return str;

	case ZEBRA_SEG6_LOCAL_ACTION_END_T:
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT6:
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT4:
    case ZEBRA_SEG6_LOCAL_ACTION_END_DT46:
	case ZEBRA_SEG6_LOCAL_ACTION_END_UDT6:
	case ZEBRA_SEG6_LOCAL_ACTION_END_UDT4:
	case ZEBRA_SEG6_LOCAL_ACTION_END_UDT46:
		snprintf(str, size, "table %u", ctx->table);
		return str;

	case ZEBRA_SEG6_LOCAL_ACTION_END_DX2:
	case ZEBRA_SEG6_LOCAL_ACTION_END_B6:
	case ZEBRA_SEG6_LOCAL_ACTION_END_B6_ENCAP:
	case ZEBRA_SEG6_LOCAL_ACTION_END_BM:
	case ZEBRA_SEG6_LOCAL_ACTION_END_S:
	case ZEBRA_SEG6_LOCAL_ACTION_END_AS:
	case ZEBRA_SEG6_LOCAL_ACTION_END_AM:
	case ZEBRA_SEG6_LOCAL_ACTION_UNSPEC:
	default:
		snprintf(str, size, "unknown(%s)", __func__);
		return str;
	}
}

struct srv6_locator *srv6_locator_new(void)
{
	struct srv6_locator *locator = NULL;
	locator = XCALLOC(MTYPE_SRV6_LOCATOR, sizeof(struct srv6_locator));
	return locator;
}
void srv6_locator_del(struct srv6_locator *locator)
{
    if (locator->chunks)
        list_delete(&locator->chunks);
    if (locator->sids)
        list_delete(&locator->sids);
	if (locator->sid_endx_ecmps)
        list_delete(&locator->sid_endx_ecmps);
    XFREE(MTYPE_SRV6_LOCATOR, locator);
    return;
}

struct srv6_locator *srv6_locator_alloc(const char *name)
{
	struct srv6_locator *locator = NULL;

    locator = srv6_locator_new();
    strlcpy(locator->name, name, sizeof(locator->name));
	locator->chunks = list_new();
	locator->chunks->del = (void (*)(void *))srv6_locator_chunk_free;

    locator->sids = list_new();
	locator->sid_endx_ecmps = list_new();

	QOBJ_REG(locator, srv6_locator);
	return locator;
}

void combine_hide_sid(struct srv6_locator *locator, struct in6_addr *sid_addr, struct in6_addr *result_addr, enum seg6local_sid_type_t sidtype)
{
	uint8_t idx = 0;
	uint8_t funcid = 0;
	uint8_t locatorbit = 0;
	uint8_t totalbit = 0;
	uint8_t funbit = 0;

	if (sidtype == ZEBRA_SEG6_LOCAL_SID_TYPE_UA) {  // block:32 node:0 func:16
		locatorbit = locator->block_bits_length / 8;
		totalbit = (locator->block_bits_length + locator->function_bits_length + locator->argument_bits_length) / 8;
		funbit = (locator->function_bits_length + locator->argument_bits_length) / 8;

	} else if (sidtype == ZEBRA_SEG6_LOCAL_SID_TYPE_UN) {  // block:32 node:16 func:0
		locatorbit = (locator->block_bits_length + locator->node_bits_length) / 8;
		totalbit = (locator->block_bits_length + locator->node_bits_length  + locator->argument_bits_length) / 8;
		funbit = locator->argument_bits_length / 8;

	} 
	
	for (idx = 0; idx < locatorbit; idx++) {
		result_addr->s6_addr[idx] = locator->prefix.prefix.s6_addr[idx];
	}
	for (; idx < totalbit; idx++) {
		result_addr->s6_addr[idx] = sid_addr->s6_addr[16 - funbit + funcid];
		funcid++;
	}
}

void combine_sid(struct srv6_locator *locator, struct in6_addr *sid_addr, struct in6_addr *result_addr)
{
	uint8_t idx = 0;
	uint8_t funcid = 0;
	uint8_t locatorbit = 0;
	/* uint8_t sidbit = 0;*/
	uint8_t totalbit = 0;
	uint8_t funbit = 0;
	locatorbit = (locator->block_bits_length + locator->node_bits_length) / 8;

	if (locator->format == SRV6_FORMAT_F1)
	{
		/* LBL:40 LNL:24 FL:16 AL:8, funbit = 128-LB-LNL */
		totalbit = 16; 
		funbit = 8;
	}
	/* SRV6_FORMAT_USID_3216 */
	else 
	{
		/* sidbit = 16 - locatorbit; */
		totalbit = (locator->block_bits_length + locator->node_bits_length + locator->function_bits_length + locator->argument_bits_length) / 8;
		funbit = (locator->function_bits_length + locator->argument_bits_length) / 8;
	}
	
	for (idx = 0; idx < locatorbit; idx++) {
		result_addr->s6_addr[idx] = locator->prefix.prefix.s6_addr[idx];
	}
	for (; idx < totalbit; idx++) {
		result_addr->s6_addr[idx] = sid_addr->s6_addr[16 - funbit + funcid];
		funcid++;
	}
}

struct srv6_locator_chunk *srv6_locator_chunk_alloc(void)
{
	struct srv6_locator_chunk *chunk = NULL;

	chunk = XCALLOC(MTYPE_SRV6_LOCATOR_CHUNK,
			sizeof(struct srv6_locator_chunk));
	return chunk;
}

void srv6_locator_free(struct srv6_locator *locator)
{
	if (locator) {
		QOBJ_UNREG(locator);
		list_delete(&locator->chunks);
        list_delete(&locator->sids);
		list_delete(&locator->sid_endx_ecmps);

		XFREE(MTYPE_SRV6_LOCATOR, locator);
	}
}

void srv6_locator_chunk_free(struct srv6_locator_chunk *chunk)
{
	XFREE(MTYPE_SRV6_LOCATOR_CHUNK, chunk);
}

struct seg6_sid_endx_params *srv6_locator_sid_endx_params_alloc(void)
{
	struct seg6_sid_endx_params *sid_endx_params = NULL;

	sid_endx_params = XCALLOC(MTYPE_SRV6_SID_ENDX_PARAMS, sizeof(struct seg6_sid_endx_params));

	return sid_endx_params;
}

void srv6_locator_sid_endx_params_free(struct seg6_sid_endx_ecmp *sid_endx_params)
{
	XFREE(MTYPE_SRV6_SID_ENDX_PARAMS, sid_endx_params);
	return;
}

struct seg6_sid_endx_ecmp *srv6_locator_sid_endx_ecmp_alloc(void)
{
	struct seg6_sid_endx_ecmp *sid_endx_ecmp = NULL;

	sid_endx_ecmp = XCALLOC(MTYPE_SRV6_SID_ENDX_ECMP, sizeof(struct seg6_sid_endx_ecmp));

	sid_endx_ecmp->sid_endx_params = list_new();

	return sid_endx_ecmp;
}

void srv6_locator_sid_endx_ecmp_free(struct seg6_sid_endx_ecmp *sid_endx_ecmp)
{
	if (sid_endx_ecmp->sid_endx_params)
        list_delete(&sid_endx_ecmp->sid_endx_params);
	XFREE(MTYPE_SRV6_SID_ENDX_ECMP, sid_endx_ecmp);
	return;
}

struct seg6_sid *srv6_locator_sid_alloc(void)
{
    struct seg6_sid *sid = NULL;

    sid = XCALLOC(MTYPE_SRV6_LOCATOR_CHUNK,
        sizeof(struct seg6_sid));
    strlcpy(sid->vrfName, "Default", sizeof(sid->vrfName));
    return sid;
}
void srv6_locator_sid_free(struct seg6_sid *sid)
{
	XFREE(MTYPE_SRV6_LOCATOR_CHUNK, sid);
	return;
}

json_object *srv6_locator_chunk_json(const struct srv6_locator_chunk *chunk)
{
	json_object *jo_root = NULL;

	jo_root = json_object_new_object();
	json_object_string_addf(jo_root, "prefix", "%pFX", &chunk->prefix);
	json_object_string_add(jo_root, "proto",
			       zebra_route_string(chunk->proto));

	return jo_root;
}

json_object *
srv6_locator_chunk_detailed_json(const struct srv6_locator_chunk *chunk)
{
	json_object *jo_root = NULL;

	jo_root = json_object_new_object();

	/* set prefix */
	json_object_string_addf(jo_root, "prefix", "%pFX", &chunk->prefix);

	/* set block_bits_length */
	json_object_int_add(jo_root, "blockBitsLength",
			    chunk->block_bits_length);

	/* set node_bits_length */
	json_object_int_add(jo_root, "nodeBitsLength", chunk->node_bits_length);

	/* set function_bits_length */
	json_object_int_add(jo_root, "functionBitsLength",
			    chunk->function_bits_length);

	/* set argument_bits_length */
	json_object_int_add(jo_root, "argumentBitsLength",
			    chunk->argument_bits_length);

	/* set keep */
	json_object_int_add(jo_root, "keep", chunk->keep);

	/* set proto */
	json_object_string_add(jo_root, "proto",
			       zebra_route_string(chunk->proto));

	/* set instance */
	json_object_int_add(jo_root, "instance", chunk->instance);

	/* set session_id */
	json_object_int_add(jo_root, "sessionId", chunk->session_id);

	return jo_root;
}

json_object *
srv6_locator_sid_detailed_json(const struct srv6_locator *locator,
							   const struct seg6_sid *sid)
{
	json_object *jo_root = NULL;
	struct in6_addr result_sid = {0};
	char buf[256];
	struct prefix p = {};

	jo_root = json_object_new_object();

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
	}

	/* set opcode */
	json_object_string_add(jo_root, "opcode", buf);

	/* set sidaction */
	json_object_string_add(jo_root, "sidaction",
						   seg6local_action2str(sid->sidaction));

	/* set ifname and nexthop */
	if (sid->sidaction == ZEBRA_SEG6_LOCAL_ACTION_END_X) {
		char ifbuf[INET6_ADDRSTRLEN] = {0};
		json_object_string_add(jo_root, "ifname", sid->ifname);
		if (sid->nexthop.ipa_type == IPADDR_V4)
			inet_ntop(AF_INET, &sid->nexthop.ipaddr_v4, ifbuf, sizeof(ifbuf));
		else if (sid->nexthop.ipa_type == IPADDR_V6)
			inet_ntop(AF_INET6, &sid->nexthop.ipaddr_v6, ifbuf, sizeof(ifbuf));
		json_object_string_add(jo_root, "nexthop", ifbuf);
	}

	/* set vrf */
	json_object_string_add(jo_root, "vrf", sid->vrfName);

	/* set service-sid-marking */
	if (ZEBRA_SEG6_ACTION_IS_END_DT46(sid->sidaction))
		json_object_int_add(jo_root, "service-sid-marking", sid->sidmarking);

	return jo_root;
}

json_object *srv6_locator_json(const struct srv6_locator *loc)
{
	struct listnode *node;
	struct srv6_locator_chunk *chunk;
	json_object *jo_root = NULL;
	json_object *jo_chunk = NULL;
	json_object *jo_chunks = NULL;

	jo_root = json_object_new_object();

	/* set name */
	json_object_string_add(jo_root, "name", loc->name);

	/* set prefix */
	json_object_string_addf(jo_root, "prefix", "%pFX", &loc->prefix);

	/* set function_bits_length */
	json_object_int_add(jo_root, "functionBitsLength",
			    loc->function_bits_length);

	/* set status_up */
	json_object_boolean_add(jo_root, "statusUp",
				loc->status_up);

	/* set chunks */
	jo_chunks = json_object_new_array();
	json_object_object_add(jo_root, "chunks", jo_chunks);
	for (ALL_LIST_ELEMENTS_RO((struct list *)loc->chunks, node, chunk)) {
		jo_chunk = srv6_locator_chunk_json(chunk);
		json_object_array_add(jo_chunks, jo_chunk);
	}

	return jo_root;
}

json_object *srv6_locator_detailed_json(const struct srv6_locator *loc)
{
	struct listnode *node;
	struct listnode *sidnode;
	struct srv6_locator_chunk *chunk;
	struct seg6_sid *sid = NULL;
	json_object *jo_root = NULL;
	json_object *jo_chunk = NULL;
	json_object *jo_chunks = NULL;
	json_object *jo_sid = NULL;
	json_object *jo_sids = NULL;

	jo_root = json_object_new_object();

	/* set name */
	json_object_string_add(jo_root, "name", loc->name);

	/* set prefix */
	json_object_string_addf(jo_root, "prefix", "%pFX", &loc->prefix);

	/* set block_bits_length */
	json_object_int_add(jo_root, "blockBitsLength", loc->block_bits_length);

	/* set node_bits_length */
	json_object_int_add(jo_root, "nodeBitsLength", loc->node_bits_length);

	/* set function_bits_length */
	json_object_int_add(jo_root, "functionBitsLength",
			    loc->function_bits_length);

	/* set argument_bits_length */
	json_object_int_add(jo_root, "argumentBitsLength",
			    loc->argument_bits_length);

	/* set algonum */
	json_object_int_add(jo_root, "algoNum", loc->algonum);

	/* set status_up */
	json_object_boolean_add(jo_root, "statusUp", loc->status_up);

	/* set chunks */
	jo_chunks = json_object_new_array();
	json_object_object_add(jo_root, "chunks", jo_chunks);
	for (ALL_LIST_ELEMENTS_RO((struct list *)loc->chunks, node, chunk)) {
		jo_chunk = srv6_locator_chunk_detailed_json(chunk);
		json_object_array_add(jo_chunks, jo_chunk);
	}

	/* set sids */
	jo_sids = json_object_new_array();
	json_object_object_add(jo_root, "sids", jo_sids);
	for (ALL_LIST_ELEMENTS_RO(loc->sids, sidnode, sid)) {
		jo_sid = srv6_locator_sid_detailed_json(loc, sid);
		json_object_array_add(jo_sids, jo_sid);
	}

	return jo_root;
}
