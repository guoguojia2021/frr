#include <zebra.h>

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

#include "zebra/rt_protobuf.h"

static ssize_t protobuf_msg_encode(int cmd, struct zebra_dplane_ctx *ctx, uint8_t *data,
				   size_t datalen)
{
	Fpm__Message *msg;
	QPB_DECLARE_STACK_ALLOCATOR(allocator, 4096);
	size_t len;

	QPB_INIT_STACK_ALLOCATOR(allocator);

	msg = create_route_message(cmd, &allocator, ctx);
	if (!msg) {
		return 0;
	}
	len = fpm__message__pack(msg, data);
	/* not enough space */
	if (len > datalen) {
		return 0;
	}
	QPB_RESET_STACK_ALLOCATOR(allocator);
	return len;
}

static Fpm__Message *create_route_message(int cmd, qpb_allocator_t *allocator,
					  struct zebra_dplane_ctx *ctx)
{
	Fpm__Message *msg;

	msg = QPB_ALLOC(allocator, typeof(*msg));
	if (!msg) {
		return NULL;
	}

	fpm__message__init(msg);
	switch (cmd) {
	case RTM_NEWROUTE:
		/*create add route message*/
		msg->has_type = 1;
		msg->type = FPM__MESSAGE__TYPE__ADD_ROUTE;
		if (IS_ZEBRA_DEBUG_FPM) {
			zlog_debug("fpm_pb message:");
			zlog_debug("==========");
			zlog_debug("has_type: %d", msg->has_type);
			zlog_debug("type: %d", msg->type);
		}
		msg->add_route = create_add_route_message(allocator, ctx);
		if (!msg->add_route) {
			return NULL;
		}
		break;
	}

	return msg;
}

static Fpm__AddRoute *create_add_route_message(qpb_allocator_t *allocator,
					       struct zebra_dplane_ctx *ctx)
{
	Fpm__AddRoute *msg;
	const struct prefix *p;
	struct prefix p_dest;

	msg = QPB_ALLOC(allocator, typeof(*msg));
	if (!msg)
		return NULL;

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
