
#include <zebra.h>

/* The following definition is to workaround an issue in the Linux kernel
 * header files with redefinition of 'struct in6_addr' in both
 * netinet/in.h and linux/in6.h.
 * Reference - https://sourceware.org/ml/libc-alpha/2013-01/msg00599.html
 */
#define _LINUX_IN6_H

#include <net/if_arp.h>
#include <linux/lwtunnel.h>
#include <linux/mpls_iptunnel.h>
#include <linux/seg6_iptunnel.h>
#include <linux/seg6_local.h>
#include <linux/neighbour.h>
#include <linux/rtnetlink.h>
#include <linux/nexthop.h>

/* Hack for GNU libc version 2. */
#ifndef MSG_TRUNC
#define MSG_TRUNC      0x20
#endif /* MSG_TRUNC */

#include "linklist.h"
#include "if.h"
#include "log.h"
#include "prefix.h"
#include "plist.h"
#include "plist_int.h"
#include "connected.h"
#include "table.h"
#include "memory.h"
#include "rib.h"
#include "thread.h"
#include "privs.h"
#include "nexthop.h"
#include "vrf.h"
#include "vty.h"
#include "mpls.h"
#include "vxlan.h"
#include "printfrr.h"

#include "zebra/zapi_msg.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_vrf.h"
#include "zebra/rt.h"
#include "zebra/redistribute.h"
#include "zebra/interface.h"
#include "zebra/debug.h"
#include "zebra/rtadv.h"
#include "zebra/zebra_ptm.h"
#include "zebra/zebra_mpls.h"
#include "zebra/kernel_netlink.h"
#include "zebra/zebra_nhg.h"
#include "zebra/zebra_mroute.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_evpn_mh.h"
#include "zebra/rt_protobuf.h"

#ifndef AF_MPLS
#define AF_MPLS 28
#endif

/* Re-defining as I am unable to include <linux/if_bridge.h> which has the
 * UAPI for MAC sync. */
#ifndef _UAPI_LINUX_IF_BRIDGE_H
#define BR_SPH_LIST_SIZE 10
#endif

ssize_t protobuf_msg_encode(int cmd, struct zebra_dplane_ctx *ctx, uint8_t *data,
				   size_t datalen, bool fpm)
{
	Fpm__Message *msg;
	QPB_DECLARE_STACK_ALLOCATOR(allocator, 4096);
	size_t len;

	QPB_INIT_STACK_ALLOCATOR(allocator);

	msg = create_route_message(cmd, &allocator, ctx, fpm);
	if (!msg)
	{
		zlog_err("%s: create route message errors", __func__);
		return 0;
	}
	len = fpm__message__pack(msg, data);
	memory_deallocation(msg, cmd);
	/* not enough space */
	if (len > datalen) {
		return 0;
	}
	QPB_RESET_STACK_ALLOCATOR(allocator);
	return len;
}

Fpm__Message *create_route_message(int cmd, qpb_allocator_t *allocator,
					  struct zebra_dplane_ctx *ctx, bool fpm)
{
	Fpm__Message *msg;

	msg = QPB_ALLOC(allocator, typeof(*msg));
	if (!msg)
	{
		zlog_err("%s: allocating memory errors", __func__);
		return NULL;
	}
	fpm__message__init(msg);

	switch (cmd) {
	case RTM_NEWROUTE:
		/*create add route message*/
		msg->has_type = 1;
		msg->type = FPM__MESSAGE__TYPE__ADD_ROUTE;
		msg->add_route = create_route_install_message(allocator, ctx);
		if (!msg->add_route)
		{
			zlog_err("%s: create_route_install_message failed",
				 __func__);
			return NULL;
		}
		break;
	case RTM_NEWNEXTHOP:
	case RTM_DELNEXTHOP:
		msg->has_type = 1;
		msg->type = FPM__MESSAGE__TYPE__NHG;
		msg->next_hop_group = protobuf_nexthop_msg_encode(allocator, cmd, ctx, fpm);

		if (!msg->next_hop_group)
		{
			zlog_err("%s: protobuf_nexthop_msg_encode failed",
				 __func__);
			return NULL;
		}
		break;
	}

	return msg;
}

Fpm__AddRoute *create_route_install_message(qpb_allocator_t *allocator,
					       struct zebra_dplane_ctx *ctx)
{
	Fpm__AddRoute *msg;
	const struct prefix *p;
	struct prefix p_dest;

	msg = QPB_ALLOC(allocator, typeof(*msg));
	if (!msg)
	{
		zlog_err("%s: allocating memory errors", __func__);
		return NULL;
	}

	p = dplane_ctx_get_dest(ctx);
	if (!p)
		return NULL;
	prefix_copy(&p_dest, p);

	fpm__add_route__init(msg);
	msg->vrf_id = dplane_ctx_get_vrf(ctx);
	msg->address_family = p->family;
	msg->metric = dplane_ctx_get_metric(ctx);
	msg->sub_address_family = QPB__SUB_ADDRESS_FAMILY__UNICAST;
	msg->key = fpm_route_key_create(allocator, &p_dest);
	msg->has_route_type = 1;
	msg->route_type = FPM__ROUTE_TYPE__NORMAL;

	if (IS_ZEBRA_DEBUG_FPM) {
		zlog_debug("add route message:");
		zlog_debug("==========");
		zlog_debug("vrf_id: %d", msg->vrf_id);
		zlog_debug("address_family: %d", msg->address_family);
		zlog_debug("metric:%d", msg->metric);
		zlog_debug("sub_address_family: %d", msg->sub_address_family);
		zlog_debug("has_router_type: %d", msg->has_route_type);
		zlog_debug("route_type:%d", msg->route_type);
	}
	return msg;
}

/*
 * Some people may only want to use NHGs created by protos and not
 * implicitly created by Zebra. This check accounts for that.
 */
static bool proto_nexthops_only(void)
{
	return zebra_nhg_proto_nexthops_only();
}

/* Is this a proto created NHG? */
static bool is_proto_nhg(uint32_t id, int type)
{
	/* If type is available, use it as the source of truth */
	if (type) {
		if (type != ZEBRA_ROUTE_NHG)
			return true;
		return false;
	}

	if (id >= ZEBRA_NHG_PROTO_LOWER)
		return true;

	return false;
}

static inline int zebra2proto(int proto)
{
	switch (proto) {
	case ZEBRA_ROUTE_BABEL:
		proto = RTPROT_BABEL;
		break;
	case ZEBRA_ROUTE_BGP:
		proto = RTPROT_BGP;
		break;
	case ZEBRA_ROUTE_OSPF:
	case ZEBRA_ROUTE_OSPF6:
		proto = RTPROT_OSPF;
		break;
	case ZEBRA_ROUTE_STATIC:
		proto = RTPROT_ZSTATIC;
		break;
	case ZEBRA_ROUTE_ISIS:
		proto = RTPROT_ISIS;
		break;
	case ZEBRA_ROUTE_RIP:
		proto = RTPROT_RIP;
		break;
	case ZEBRA_ROUTE_RIPNG:
		proto = RTPROT_RIPNG;
		break;
	case ZEBRA_ROUTE_NHRP:
		proto = RTPROT_NHRP;
		break;
	case ZEBRA_ROUTE_EIGRP:
		proto = RTPROT_EIGRP;
		break;
	case ZEBRA_ROUTE_LDP:
		proto = RTPROT_LDP;
		break;
	case ZEBRA_ROUTE_SHARP:
		proto = RTPROT_SHARP;
		break;
	case ZEBRA_ROUTE_PBR:
		proto = RTPROT_PBR;
		break;
	case ZEBRA_ROUTE_OPENFABRIC:
		proto = RTPROT_OPENFABRIC;
		break;
	case ZEBRA_ROUTE_SRTE:
		proto = RTPROT_SRTE;
		break;
	case ZEBRA_ROUTE_TABLE:
	case ZEBRA_ROUTE_NHG:
		proto = RTPROT_ZEBRA;
		break;
	case ZEBRA_ROUTE_CONNECT:
	case ZEBRA_ROUTE_KERNEL:
		proto = RTPROT_KERNEL;
		break;
	default:
		/*
		 * When a user adds a new protocol this will show up
		 * to let them know to do something about it.  This
		 * is intentionally a warn because we should see
		 * this as part of development of a new protocol
		 */
		zlog_debug(
			"%s: Please add this protocol(%d) to proper rt_netlink.c handling",
			__func__, proto);
		proto = RTPROT_ZEBRA;
		break;
	}

	return proto;
}

static int build_label_stack(struct mpls_label_stack *nh_label,
			     mpls_lse_t *out_lse, char *label_buf,
			     size_t label_buf_size)
{
	char label_buf1[20];
	int num_labels = 0;

	for (int i = 0; nh_label && i < nh_label->num_labels; i++) {
		if (nh_label->label[i] == MPLS_LABEL_IMPLICIT_NULL)
			continue;

		if (IS_ZEBRA_DEBUG_KERNEL) {
			if (!num_labels)
				snprintf(label_buf, label_buf_size, "label %u",
					 nh_label->label[i]);
			else {
				snprintf(label_buf1, sizeof(label_buf1), "/%u",
					 nh_label->label[i]);
				strlcat(label_buf, label_buf1, label_buf_size);
			}
		}

		out_lse[num_labels] =
			mpls_lse_encode(nh_label->label[i], 0, 0, 0);
		num_labels++;
	}

	return num_labels;
}

static ssize_t fill_seg6ipt_encap_private(char *buffer, size_t buflen,
				  const struct in6_addr *seg, const struct in6_addr *src,
				  const char *segment_name)
{
	struct seg6_iptunnel_encap_proto *ipt;
	struct ipv6_sr_hdr *srh;
	const size_t srhlen = 8 + 16;

	/*
	 * Caution: Support only SINGLE-SID, not MULTI-SID
	 * This function only supports the case where segs represents
	 * a single SID. If you want to extend the SRv6 functionality,
	 * you should improve the Boundary Check.
	 * Ex. In case of set a SID-List include multiple-SIDs as an
	 * argument of the Transit Behavior, we must support variable
	 * boundary check for buflen.
	 */
	if (buflen < (sizeof(struct seg6_iptunnel_encap_proto) + srhlen))
		return -1;

	memset(buffer, 0, buflen);

	ipt = (struct seg6_iptunnel_encap_proto *)buffer;
	ipt->mode = SEG6_IPTUN_MODE_ENCAP;
	srh = ipt->srh;
	srh->hdrlen = (srhlen >> 3) - 1;
	srh->type = 4;
	srh->segments_left = 0;
	srh->first_segment = 0;
	memcpy(&srh->segments[0], seg, sizeof(struct in6_addr));
	memcpy(&ipt->src, src, sizeof(struct in6_addr));

	if (segment_name != NULL)
		memcpy(ipt->segment_name, segment_name, 64);

	return sizeof(struct seg6_iptunnel_encap_proto) + srhlen;
}

Fpm__NextHopGroup *protobuf_nexthop_msg_encode(qpb_allocator_t *allocator,
				   uint16_t cmd, const struct zebra_dplane_ctx *ctx, bool fpm)
{
	Fpm__NextHopGroup *nhg;
	nhg = QPB_ALLOC(allocator, typeof(*nhg));
	if (!nhg)
	{
		zlog_err("%s: allocating memory errors", __func__);
		return NULL;
	}
	fpm__next_hop_group__init(nhg);

	mpls_lse_t out_lse[MPLS_MAX_LABELS];
	char label_buf[256];
	int num_labels = 0;
	int n_encap_nest = 0;
	uint32_t id = dplane_ctx_get_nhe_id(ctx);
	int type = dplane_ctx_get_nhe_type(ctx);
	uint16_t encap;
	uint32_t flag;
	Fpm__Encap *encap_message;
	Fpm__AttrNest *nest_message;
	Fpm__EncapNest *encap_nest;
	nhg->encap_nest = malloc(3*sizeof(Fpm__EncapNest*));

	if (!id)
	{
		flog_err(
			EC_ZEBRA_NHG_FIB_UPDATE,
			"Failed trying to update a nexthop group in the kernel that does not have an ID");
		return NULL;
	}
	/*
	 * Nothing to do if the kernel doesn't support nexthop objects or
	 * we dont want to install this type of NHG, but FPM may possible to
	 * handle this.
	 */
	if (!fpm) {
		if (IS_ZEBRA_DEBUG_KERNEL || IS_ZEBRA_DEBUG_NHG)
			zlog_debug(
				"%s: nhg_id %u (%s): fpm not supported, ignoring",
				__func__, id, zebra_route_string(type));
		return NULL;
	}

	if (proto_nexthops_only() && !is_proto_nhg(id, type)) {
		if (IS_ZEBRA_DEBUG_KERNEL || IS_ZEBRA_DEBUG_NHG)
			zlog_debug(
				"%s: nhg_id %u (%s): proto-based nexthops only, ignoring",
				__func__, id, zebra_route_string(type));
		return NULL;
	}

	flag = dplane_ctx_get_flags(ctx);

	if (CHECK_FLAG(flag, ZEBRA_FLAG_FIB_BYPASS)) {
		zlog_info("%s:fib bypass",__func__);
		if (IS_ZEBRA_DEBUG_KERNEL || IS_ZEBRA_DEBUG_NHG)
			zlog_debug(
				"%s: nhg_id %u (%s): this nexthops no need to install kernel, ignoring",
				__func__, id, zebra_route_string(type));
		return NULL;
	}
	if (CHECK_FLAG(flag, ZEBRA_FLAG_KERNEL_BYPASS) && !fpm) {
		zlog_info("%s:kernel bypass",__func__);
		if (IS_ZEBRA_DEBUG_KERNEL || IS_ZEBRA_DEBUG_NHG)
			zlog_debug(
				"%s: nhg_id %u (%s): this nexthops no need to install kernel, ignoring",
				__func__, id, zebra_route_string(type));
		return NULL;
	}

	label_buf[0] = '\0';
	nhg->nh_family = AF_UNSPEC;
	/* TODO: Scope? */

	nhg->nha_id = id;
	nhg->nh_msg_type = cmd;

	if (cmd == RTM_NEWNEXTHOP) {
		/*
		 * We distinguish between a "group", which is a collection
		 * of ids, and a singleton nexthop with an id. The
		 * group is installed as an id that just refers to a list of
		 * other ids.
		 */
		if (dplane_ctx_get_nhe_nh_grp_count(ctx))
		{
			if (!protobuf_nexthop_build_group(
				    nhg, allocator, id,
				    dplane_ctx_get_nhe_nh_grp(ctx),
				    dplane_ctx_get_nhe_nh_grp_count(ctx)))
				return 0;
		}
		else
		{
			const struct nexthop *nh =
				dplane_ctx_get_nhe_ng(ctx)->nexthop;
			afi_t afi = dplane_ctx_get_nhe_afi(ctx);

			if (afi == AFI_IP)
				nhg->nh_family = AF_INET;
			else if (afi == AFI_IP6)
				nhg->nh_family = AF_INET6;

			nhg->nh_type = nh->type;
			switch (nh->type) {
			case NEXTHOP_TYPE_IPV4:
			case NEXTHOP_TYPE_IPV4_IFINDEX:
			case NEXTHOP_TYPE_IPV4_SEGMENTLIST:
				nhg->gate = create_gate_message(allocator,
				         NHA_GATEWAY, &nh->gate.ipv4,
						 IPV4_MAX_BYTELEN, AF_INET);
				if(!nhg->gate) return NULL;
				break;
			case NEXTHOP_TYPE_IPV6:
			case NEXTHOP_TYPE_IPV6_IFINDEX:
			case NEXTHOP_TYPE_IPV6_SEGMENTLIST:
				nhg->gate = create_gate_message(allocator,
				         NHA_GATEWAY, &nh->gate.ipv6,
						 IPV6_MAX_BYTELEN, AF_INET6);
				if(!nhg->gate) return NULL;
				break;
			case NEXTHOP_TYPE_BLACKHOLE:
				// if (!nl_attr_put(&req->n, buflen, NHA_BLACKHOLE,
				// 		 NULL, 0))
				// 	return 0;
				/* Blackhole shouldn't have anymore attributes
				 */
				goto nexthop_done;
			case NEXTHOP_TYPE_IFINDEX:
				/* Don't need anymore info for this */
				break;
			}
			if (!nh->ifindex && !fpm) {
				flog_err(
					EC_ZEBRA_NHG_FIB_UPDATE,
					"Context received for kernel nexthop update without an interface");
				return NULL;
			}

			nhg->if_index = nh->ifindex;
			if(!nhg->if_index && !fpm)
			{
				zlog_err("%s: ifindex is zero,ifidnex:%d",
					 	 __func__, nh->ifindex);
				return NULL;
			}
			if (CHECK_FLAG(nh->flags, NEXTHOP_FLAG_ONLINK))
				nhg->nh_flags |= RTNH_F_ONLINK;

			num_labels =
				build_label_stack(nh->nh_label, out_lse,
						  label_buf, sizeof(label_buf));
			if (num_labels) {
				/* Set the BoS bit */
				out_lse[num_labels - 1] |=
					htonl(1 << MPLS_LS_S_SHIFT);

				/*
				 * TODO: MPLS unsupported for now in kernel.
				 */
				if (nhg->nh_family == AF_MPLS)
					goto nexthop_done;

				encap = LWTUNNEL_ENCAP_MPLS;
				encap_message = create_encap_message(allocator,
							   NHA_ENCAP_TYPE, encap, sizeof(uint16_t));
				Fpm__OutLse *out_lse_message = create_out_lse_message(allocator,
				               MPLS_IPTUNNEL_DST,
							   &out_lse, num_labels * sizeof(mpls_lse_t));
				nest_message = create_arrt_nest_message(allocator,
				               NHA_ENCAP, out_lse_message,
							   FPM_OUT_LSE);
				encap_nest = create_encap_nest_message(allocator,
							   encap_message, nest_message);
				nhg->encap_nest[n_encap_nest++] = encap_nest;
				nhg->n_encap_nest = n_encap_nest;
			}
			if (nh->nh_srv6) {
				/*
				if (nh->nh_srv6->seg6local_action !=
				    ZEBRA_SEG6_LOCAL_ACTION_UNSPEC) {
					uint32_t action;
					uint16_t encap;
					const struct seg6local_context *ctx;

					nhg->nh_family = AF_INET6;
					action = nh->nh_srv6->seg6local_action;
					ctx = &nh->nh_srv6->seg6local_ctx;

					encap = LWTUNNEL_ENCAP_SEG6_LOCAL;
					encap_message = create_encap_message(allocator, NHA_ENCAP_TYPE, encap, sizeof(uint16_t));
					Fpm__Seg6Local *seg6_local;

					switch (action) {
					case SEG6_LOCAL_ACTION_END:
						seg6_local = create_seg6_local_message(allocator,
									 SEG6_LOCAL_ACTION_END, -1,
									 NULL, sizeof(size_t));
						break;
					case SEG6_LOCAL_ACTION_END_X:
						seg6_local = create_seg6_local_message(allocator,
									 SEG6_LOCAL_ACTION_END_X, SEG6_LOCAL_NH6,
									 &ctx->nh6, sizeof(struct in6_addr));
						break;
					case SEG6_LOCAL_ACTION_END_T:
						seg6_local = create_seg6_local_message(allocator,
									 SEG6_LOCAL_ACTION_END_T, SEG6_LOCAL_TABLE,
									 &ctx->table, sizeof(uint32_t));
						break;
					case SEG6_LOCAL_ACTION_END_DX4:
						seg6_local = create_seg6_local_message(allocator,
									 SEG6_LOCAL_ACTION_END_DX4, SEG6_LOCAL_NH4,
									 &ctx->nh4, sizeof(struct in_addr));
						break;
					case SEG6_LOCAL_ACTION_END_DT6:
						seg6_local = create_seg6_local_message(allocator,
									 SEG6_LOCAL_ACTION_END_DT6, SEG6_LOCAL_TABLE,
									 &ctx->table, sizeof(uint32_t));
						break;
					default:
						zlog_err("%s: unsupport seg6local behaviour action=%u",
							 __func__, action);
						return 0;
					}
					nest_message = create_arrt_nest_message(allocator,
				             	  NHA_ENCAP | NLA_F_NESTED, seg6_local,
							 	  FPM_SEG6_LOCAL);
					encap_nest = create_encap_nest_message(allocator, encap_message, nest_message);
					nhg->encap_nest[n_encap_nest++] = encap_nest;
					nhg->n_encap_nest = n_encap_nest;
				}
				*/
				if (!sid_zero(&nh->nh_srv6->seg6_segs)) {
					char tun_buf[4096];
					ssize_t tun_len;

					encap = LWTUNNEL_ENCAP_SEG6;
					encap_message = create_encap_message(allocator,
								  NHA_ENCAP_TYPE, encap, sizeof(uint16_t));
					tun_len = fill_seg6ipt_encap_private(tun_buf,
					    sizeof(tun_buf),
					    &nh->nh_srv6->seg6_segs,
					    &nh->nh_srv6->seg6_src,
						nh->sidlist_name);
					if (tun_len < 0)
						return NULL;
					Fpm__Seg6Segs *seg6_segs = create_seg6_segs_message(allocator,
								  SEG6_IPTUNNEL_SRH, tun_buf, tun_len);
					nest_message = create_arrt_nest_message(allocator,
				             	  NHA_ENCAP | NLA_F_NESTED, seg6_segs,
							 	  FPM_SEG6_SEGS);
					encap_nest = create_encap_nest_message(allocator,
								  encap_message, nest_message);
					nhg->encap_nest[n_encap_nest++] = encap_nest;
					nhg->n_encap_nest = n_encap_nest;
				}
			}

nexthop_done:

			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug("%s: ID (%u): %pNHv(%d) vrf %s(%u) %s ",
					   __func__, id, nh, nh->ifindex,
					   vrf_id_to_name(nh->vrf_id),
					   nh->vrf_id, label_buf);
		}

		nhg->nh_protocol = zebra2proto(type);
	} else if (cmd != RTM_DELNEXTHOP) {
		flog_err(
			EC_ZEBRA_NHG_FIB_UPDATE,
			"Nexthop group kernel update command (%d) does not exist",
			cmd);
		return NULL;
	}

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s: %s, id=%u", __func__, nl_msg_type_to_str(cmd),
			   id);
	return nhg;
}

/* Char length to debug ID with */
#define ID_LENGTH 10

bool protobuf_nexthop_build_group(Fpm__NextHopGroup *nhg,
 					 qpb_allocator_t *allocator,
					 uint32_t id,
					 const struct nh_grp *z_grp,
					 const uint8_t count)
{
	struct nexthop_grp grp[count];
	/* Need space for max group size, "/", and null term */
	char buf[(MULTIPATH_NUM * (ID_LENGTH + 1)) + 1];
	char buf1[ID_LENGTH + 2];

	buf[0] = '\0';

	memset(grp, 0, sizeof(grp));

	if (count) {
		for (int i = 0; i < count; i++) {
			grp[i].id = z_grp[i].id;
			grp[i].weight = z_grp[i].weight - 1;

			if (IS_ZEBRA_DEBUG_KERNEL) {
				if (i == 0)
					snprintf(buf, sizeof(buf1), "group %u",
						 grp[i].id);
				else {
					snprintf(buf1, sizeof(buf1), "/%u",
						 grp[i].id);
					strlcat(buf, buf1, sizeof(buf));
				}
			}
		}
		Fpm__NHGrp *nh_grp = create_nh_grp_message(allocator, NHA_GROUP, grp, count * sizeof(*grp));
		if(!nh_grp) return false;
		nhg->nh_grp = nh_grp;
	}

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s: ID (%u): %s", __func__, id, buf);

	return true;
}

Fpm__Gate *create_gate_message(qpb_allocator_t *allocator,
				  uint16_t type, const void *data, unsigned int len, int family)
{
	Fpm__Gate *gate;
	gate = QPB_ALLOC(allocator, typeof(*gate));
	if (!gate)
	{
		zlog_err("%s: allocating memory errors", __func__);
		return NULL;
	}
	fpm__gate__init(gate);

	gate->type = type;
	gate->family = family;
	if (family == AF_INET)
	{
		gate->has_in_addr = true;
		gate->in_addr.len = len;
		gate->in_addr.data = malloc(len);
		memcpy(gate->in_addr.data, data, len);
	}
	else if (family == AF_INET6)
	{
		gate->has_in6_addr = true;
		gate->in6_addr.len = len;
		gate->in6_addr.data = malloc(len);
		memcpy(gate->in6_addr.data, data, len);
	}
	else
	{
		zlog_err("%s: gate family errors: %d", __func__,
			 family);
		return NULL;
	}
	return gate;
}

Fpm__Encap *create_encap_message(qpb_allocator_t *allocator,
				  uint16_t type, uint32_t data, uint16_t len)
{
	Fpm__Encap *fpm_encap;
	fpm_encap = QPB_ALLOC(allocator, typeof(*fpm_encap));
	if (!fpm_encap)
	{
		zlog_err("%s: allocating memory errors", __func__);
		return NULL;
	}
	fpm__encap__init(fpm_encap);

	fpm_encap->type = type;
	fpm_encap->data = data;
	fpm_encap->len = len;

	return fpm_encap;
}

Fpm__Seg6Segs *create_seg6_segs_message(qpb_allocator_t *allocator,
				  uint16_t type, const void *data, uint32_t len)
{
	Fpm__Seg6Segs *fpm_seg6_segs;
	fpm_seg6_segs = QPB_ALLOC(allocator, typeof(*fpm_seg6_segs));
	if (!fpm_seg6_segs)
	{
		zlog_err("%s: allocating memory errors", __func__);
		return NULL;
	}
	fpm__seg6_segs__init(fpm_seg6_segs);

	fpm_seg6_segs->type = type;
	fpm_seg6_segs->data.len = len;
	fpm_seg6_segs->data.data = malloc(len);
	memcpy(fpm_seg6_segs->data.data, data, len);

	return fpm_seg6_segs;
}

Fpm__OutLse *create_out_lse_message(qpb_allocator_t *allocator,
				  uint16_t type, const void *data, uint32_t len)
{
	Fpm__OutLse *fpm_out_lse;
	fpm_out_lse = QPB_ALLOC(allocator, typeof(*fpm_out_lse));
	if (!fpm_out_lse)
	{
		zlog_err("%s: allocating memory errors", __func__);
		return NULL;
	}
	fpm__out_lse__init(fpm_out_lse);

	fpm_out_lse->type = type;
	fpm_out_lse->data.len = len;
	fpm_out_lse->data.data = malloc(len);
	memcpy(fpm_out_lse->data.data, data, len);

	return fpm_out_lse;
}

Fpm__Seg6Local *create_seg6_local_message(qpb_allocator_t *allocator,
				  uint32_t action, uint16_t type, const void *data, uint16_t len)
{
	Fpm__Seg6Local *fpm_seg6_local;
	fpm_seg6_local = QPB_ALLOC(allocator, typeof(*fpm_seg6_local));
	if (!fpm_seg6_local)
	{
		zlog_err("%s: allocating memory errors", __func__);
		return NULL;
	}
	fpm__seg6_local__init(fpm_seg6_local);

	fpm_seg6_local->action = action;
	fpm_seg6_local->type = type;
	switch(action){
		case SEG6_LOCAL_ACTION_END:
			break;
		case SEG6_LOCAL_ACTION_END_X:
			fpm_seg6_local->has_nh6 = true;
			fpm_seg6_local->nh6.len = len;
			fpm_seg6_local->nh6.data = malloc(len);
			memcpy(fpm_seg6_local->nh6.data, data, len);
			break;
		case SEG6_LOCAL_ACTION_END_T:
		case SEG6_LOCAL_ACTION_END_DT6:
			fpm_seg6_local->has_table = true;
			fpm_seg6_local->table = *(int*)data;
			break;
		case SEG6_LOCAL_ACTION_END_DX4:
			fpm_seg6_local->has_nh4 = true;
			fpm_seg6_local->nh4.len = len;
			fpm_seg6_local->nh4.data = malloc(len);
			memcpy(fpm_seg6_local->nh4.data, data, len);
			break;
		default:
			qpb_free(allocator, fpm_seg6_local);
			return NULL;
	}

	return fpm_seg6_local;
}

Fpm__AttrNest *create_arrt_nest_message(qpb_allocator_t *allocator,
				  uint16_t type, const void *data, uint16_t sub_type)
{
	Fpm__AttrNest *fpm_attr_nest;
	fpm_attr_nest = QPB_ALLOC(allocator, typeof(*fpm_attr_nest));
	if (!fpm_attr_nest)
	{
		zlog_err("%s: allocating memory errors", __func__);
		return NULL;
	}
	fpm__attr_nest__init(fpm_attr_nest);

	fpm_attr_nest->type = type;
	fpm_attr_nest->sub_type = sub_type;
	switch (sub_type)
	{
		case FPM_OUT_LSE:
			fpm_attr_nest->out_lse = (Fpm__OutLse *)data;
			break;
		case FPM_SEG6_LOCAL:
			fpm_attr_nest->seg6_local = (Fpm__Seg6Local *)data;
			break;
		case FPM_SEG6_SEGS:
			fpm_attr_nest->seg6_segs = (Fpm__Seg6Segs *)data;
			break;
		default:
			qpb_free(allocator, fpm_attr_nest);
			return NULL;
	}

	return fpm_attr_nest;
}

Fpm__EncapNest *create_encap_nest_message(qpb_allocator_t *allocator,
				  Fpm__Encap *encap, Fpm__AttrNest *nest)
{
	Fpm__EncapNest *fpm_encap_nest;
	fpm_encap_nest = QPB_ALLOC(allocator, typeof(*fpm_encap_nest));
	if (!fpm_encap_nest)
	{
		zlog_err("%s: allocating memory errors", __func__);
		return NULL;
	}
	fpm__encap_nest__init(fpm_encap_nest);

	fpm_encap_nest->encap = encap;
	fpm_encap_nest->attr_nest = nest;

	return fpm_encap_nest;
}

Fpm__NHGrp *create_nh_grp_message(qpb_allocator_t *allocator,
				  uint16_t type, const void *data, uint16_t len)
{
	Fpm__NHGrp *fpm_nh_grp;
	fpm_nh_grp = QPB_ALLOC(allocator, typeof(*fpm_nh_grp));
	if (!fpm_nh_grp)
	{
		zlog_err("%s: allocating memory errors", __func__);
		return NULL;
	}
	fpm__nhgrp__init(fpm_nh_grp);

	fpm_nh_grp->type = type;
	fpm_nh_grp->data.len = len;
	fpm_nh_grp->data.data = malloc(len);
	memcpy(fpm_nh_grp->data.data, data, len);

	return fpm_nh_grp;
}

void memory_deallocation(Fpm__Message *msg, int cmd)
{
	switch (cmd) {
	case RTM_NEWROUTE:
		break;
	case RTM_NEWNEXTHOP:
	case RTM_DELNEXTHOP:
		next_hop_group_dealloc(msg->next_hop_group);
		break;
	}
	return;
}

void gate_dealloc(Fpm__Gate *gate)
{
	if (!gate) return;
	if (gate->in_addr.len) free(gate->in_addr.data);
	if (gate->in6_addr.len) free(gate->in6_addr.data);
	return;
}

void out_lse_dealloc(Fpm__OutLse *out_lse)
{
	if (!out_lse) return;
	if (out_lse->data.len) free(out_lse->data.data);
	return;
}

void seg6_local_dealloc(Fpm__Seg6Local *seg6_local)
{
	if (!seg6_local) return;
	if (seg6_local->nh4.len) free(seg6_local->nh4.data);
	if (seg6_local->nh6.len) free(seg6_local->nh6.data);
	return;
}

void seg6_segs_dealloc(Fpm__Seg6Segs *seg6_segs)
{
	if (!seg6_segs) return;
	if (seg6_segs->data.len) free(seg6_segs->data.data);
	return;
}

void attr_nest_dealloc(Fpm__AttrNest *attr_nest)
{
	if (!attr_nest) return;
	out_lse_dealloc(attr_nest->out_lse);
	seg6_local_dealloc(attr_nest->seg6_local);
	seg6_segs_dealloc(attr_nest->seg6_segs);
	return;
}

void encap_nest_dealloc(Fpm__EncapNest *encap_nest)
{
	if (!encap_nest) return;
	attr_nest_dealloc(encap_nest->attr_nest);
	return;
}

void multi_encap_nest_dealloc(Fpm__EncapNest **m_encap_nest, uint32_t n)
{
	if (n==0) return;
	for (uint32_t i=0; i<n; i++) encap_nest_dealloc(m_encap_nest[i]);
	return;
}

void nhgrp_dealloc(Fpm__NHGrp *nhgrp)
{
	if (!nhgrp) return;
	if (nhgrp->data.len) free(nhgrp->data.data);
	return;
}

void next_hop_group_dealloc(Fpm__NextHopGroup *nhg)
{
	if (!nhg) return;
	gate_dealloc(nhg->gate);
	multi_encap_nest_dealloc(nhg->encap_nest, nhg->n_encap_nest);
	nhgrp_dealloc(nhg->nh_grp);
	return;
}