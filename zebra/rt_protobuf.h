#ifndef _ZEBRA_RT_PROTOBUF_H
#define _ZEBRA_RT_PROTOBUF_H

#include "zebra/zebra_dplane.h"
#include "zebra/debug.h"
#include "fpm/fpm.h"
#include "qpb/qpb.h"
#include "qpb/qpb_allocator.h"
#include "qpb/linear_allocator.h"
#include "fpm/fpm_pb.h"

static ssize_t protobuf_msg_encode(int cmd, struct zebra_dplane_ctx *ctx, uint8_t *data,
				   size_t datalen);
static Fpm__Message *create_route_message(int cmd, qpb_allocator_t *allocator,
					  struct zebra_dplane_ctx *ctx);
static Fpm__AddRoute *create_route_install_message(qpb_allocator_t *allocator,
					       struct zebra_dplane_ctx *ctx);

#endif
