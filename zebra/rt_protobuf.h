#ifndef _ZEBRA_RT_PROTOBUF_H
#define _ZEBRA_RT_PROTOBUF_H

#include "zebra/zebra_dplane.h"
#include "zebra/debug.h"
#include "fpm/fpm.h"
#include "qpb/qpb.h"
#include "qpb/qpb_allocator.h"
#include "qpb/linear_allocator.h"
#include "fpm/fpm_pb.h"

#include "zebra/zebra_mpls.h"
#include <linux/seg6.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NL_DEFAULT_ROUTE_METRIC 20

#define NL_RTA_ENCAP_TYPE_PIC_CONTEXT_ID 300

/*
 * Additional protocol strings to push into routes
 * If we add anything new here please make sure
 * to update:
 * zebra2proto                 Function
 * proto2zebra                 Function
 * is_selfroute                Function
 * tools/frr                   To flush the route upon exit
 *
 * Finally update this file to allow iproute2 to
 * know about this new route.
 * tools/etc/iproute2/rt_protos.d
 */
#define RTPROT_BGP         186
#define RTPROT_ISIS        187
#define RTPROT_OSPF        188
#define RTPROT_RIP         189
#define RTPROT_RIPNG       190
#if !defined(RTPROT_BABEL)
#define RTPROT_BABEL        42
#endif
#define RTPROT_NHRP        191
#define RTPROT_EIGRP       192
#define RTPROT_LDP         193
#define RTPROT_SHARP       194
#define RTPROT_PBR         195
#define RTPROT_ZSTATIC     196
#define RTPROT_OPENFABRIC  197
#define RTPROT_SRTE        198

enum {
	FPM_OUT_LSE,
	FPM_SEG6_LOCAL,
	FPM_SEG6_SEGS,
};
struct seg6_iptunnel_encap_proto {
	int mode;
	char segment_name[64];
	struct in6_addr src;
	unsigned int discriminator;
	struct ipv6_sr_hdr srh[0];
};
extern ssize_t protobuf_msg_encode(int cmd, struct zebra_dplane_ctx *ctx, uint8_t *data,
				   size_t datalen, bool fpm);
extern Fpm__Message *create_route_message(int cmd, qpb_allocator_t *allocator,
					  struct zebra_dplane_ctx *ctx, bool fpm);
extern Fpm__AddRoute *create_route_install_message(qpb_allocator_t *allocator,
					       struct zebra_dplane_ctx *ctx);
extern Fpm__NextHopGroup *protobuf_nexthop_msg_encode(qpb_allocator_t *allocator,
				   uint16_t cmd, const struct zebra_dplane_ctx *ctx, bool fpm);
extern bool protobuf_nexthop_build_group(Fpm__NextHopGroup *nhg,
 					 qpb_allocator_t *allocator,
					 uint32_t id,
					 const struct nh_grp *z_grp,
					 const uint8_t count);
extern Fpm__Gate *create_gate_message(qpb_allocator_t *allocator,
				  uint16_t type, const void *data, unsigned int len, int family);
extern Fpm__Encap *create_encap_message(qpb_allocator_t *allocator,
				  uint16_t type, uint32_t data, uint16_t len);
extern Fpm__Seg6Segs *create_seg6_segs_message(qpb_allocator_t *allocator,
				  uint16_t type, const void *data, uint32_t len);
extern Fpm__OutLse *create_out_lse_message(qpb_allocator_t *allocator,
				  uint16_t type, const void *data, uint32_t len);
extern Fpm__Seg6Local *create_seg6_local_message(qpb_allocator_t *allocator,
				  uint32_t action, uint16_t type, const void *data, uint16_t len);
extern Fpm__AttrNest *create_arrt_nest_message(qpb_allocator_t *allocator,
				  uint16_t type, const void *data, uint16_t sub_type);
extern Fpm__EncapNest *create_encap_nest_message(qpb_allocator_t *allocator,
				  Fpm__Encap *encap, Fpm__AttrNest *nest);
extern Fpm__NHGrp *create_nh_grp_message(qpb_allocator_t *allocator,
				  uint16_t type, const void *data, uint16_t len);
extern void memory_deallocation(Fpm__Message *msg, int cmd);
extern void gate_dealloc(Fpm__Gate *gate);
extern void out_lse_dealloc(Fpm__OutLse *out_lse);
extern void seg6_local_dealloc(Fpm__Seg6Local *seg6_local);
extern void seg6_segs_dealloc(Fpm__Seg6Segs *seg6_segs);
extern void attr_nest_dealloc(Fpm__AttrNest *attr_nest);
extern void encap_nest_dealloc(Fpm__EncapNest *encap_nest);
extern void multi_encap_nest_dealloc(Fpm__EncapNest **m_encap_nest, uint32_t n);
extern void nhgrp_dealloc(Fpm__NHGrp *nhgrp);
extern void next_hop_group_dealloc(Fpm__NextHopGroup *nhg);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_RT_PROTOBUF_H */