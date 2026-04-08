/* Tracing for Zebra
 *
 * Copyright (C) 2024  Alibaba, Inc.
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

#if !defined(_ZEBRA_TRACE_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _ZEBRA_TRACE_H

#include "lib/trace.h"

#ifdef HAVE_LTTNG

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER frr_zebra

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "zebra/zebra_trace.h"

#include <lttng/tracepoint.h>

/* clang-format off */

/*
 * Zebra receives route add from client (e.g. BGP).
 * Traces: zread_route_add() -> zebra收到客户端路由添加请求
 *   client -> zapi_route_decode -> rib_add_multipath_nhe
 */
TRACEPOINT_EVENT(
	frr_zebra,
	zebra_route_recv_add,
	TP_ARGS(vrf_id_t, vrf_id, const char *, prefix,
		const char *, client_proto, uint32_t, nh_count,
		uint32_t, distance, uint32_t, metric),
	TP_FIELDS(
		ctf_integer(vrf_id_t, vrf_id, vrf_id)
		ctf_string(prefix, prefix)
		ctf_string(client_proto, client_proto)
		ctf_integer(uint32_t, nh_count, nh_count)
		ctf_integer(uint32_t, distance, distance)
		ctf_integer(uint32_t, metric, metric)
	)
)
TRACEPOINT_LOGLEVEL(frr_zebra, zebra_route_recv_add, TRACE_INFO)

/*
 * Zebra receives route delete from client (e.g. BGP).
 * Traces: zread_route_del() -> zebra收到客户端路由删除请求
 *   client -> zapi_route_decode -> rib_delete
 */
TRACEPOINT_EVENT(
	frr_zebra,
	zebra_route_recv_del,
	TP_ARGS(vrf_id_t, vrf_id, const char *, prefix,
		const char *, client_proto),
	TP_FIELDS(
		ctf_integer(vrf_id_t, vrf_id, vrf_id)
		ctf_string(prefix, prefix)
		ctf_string(client_proto, client_proto)
	)
)
TRACEPOINT_LOGLEVEL(frr_zebra, zebra_route_recv_del, TRACE_INFO)

/*
 * Zebra installs route to kernel via dplane.
 * Traces: rib_install_kernel() -> zebra下发路由到kernel
 *   -> dplane_route_add / dplane_route_update -> kernel_route_update
 */
TRACEPOINT_EVENT(
	frr_zebra,
	zebra_rib_install_kernel,
	TP_ARGS(vrf_id_t, vrf_id, const char *, prefix,
		const char *, route_type, bool, is_update),
	TP_FIELDS(
		ctf_integer(vrf_id_t, vrf_id, vrf_id)
		ctf_string(prefix, prefix)
		ctf_string(route_type, route_type)
		ctf_integer(uint8_t, is_update, is_update)
	)
)
TRACEPOINT_LOGLEVEL(frr_zebra, zebra_rib_install_kernel, TRACE_INFO)

/*
 * Zebra uninstalls route from kernel via dplane.
 * Traces: rib_uninstall_kernel() -> zebra从kernel删除路由
 *   -> dplane_route_delete -> kernel_route_update
 */
TRACEPOINT_EVENT(
	frr_zebra,
	zebra_rib_uninstall_kernel,
	TP_ARGS(vrf_id_t, vrf_id, const char *, prefix,
		const char *, route_type),
	TP_FIELDS(
		ctf_integer(vrf_id_t, vrf_id, vrf_id)
		ctf_string(prefix, prefix)
		ctf_string(route_type, route_type)
	)
)
TRACEPOINT_LOGLEVEL(frr_zebra, zebra_rib_uninstall_kernel, TRACE_INFO)

/*
 * Zebra receives nexthop register from client.
 * Traces: zread_rnh_register() -> zebra收到客户端下一跳注册请求
 *   client -> zebra_add_rnh -> zebra_evaluate_rnh
 */
TRACEPOINT_EVENT(
	frr_zebra,
	zebra_nht_register,
	TP_ARGS(vrf_id_t, vrf_id, const char *, prefix,
		const char *, client_proto, bool, is_register),
	TP_FIELDS(
		ctf_integer(vrf_id_t, vrf_id, vrf_id)
		ctf_string(prefix, prefix)
		ctf_string(client_proto, client_proto)
		ctf_integer(uint8_t, is_register, is_register)
	)
)
TRACEPOINT_LOGLEVEL(frr_zebra, zebra_nht_register, TRACE_INFO)

/*
 * Zebra sends nexthop update to client.
 * Traces: zebra_send_rnh_update() -> zebra向客户端发送下一跳更新通知
 *   -> zsend_nexthop_update -> client
 */
TRACEPOINT_EVENT(
	frr_zebra,
	zebra_nht_send_update,
	TP_ARGS(vrf_id_t, vrf_id, const char *, prefix,
		const char *, client_proto, uint32_t, nh_num,
		uint32_t, metric),
	TP_FIELDS(
		ctf_integer(vrf_id_t, vrf_id, vrf_id)
		ctf_string(prefix, prefix)
		ctf_string(client_proto, client_proto)
		ctf_integer(uint32_t, nh_num, nh_num)
		ctf_integer(uint32_t, metric, metric)
	)
)
TRACEPOINT_LOGLEVEL(frr_zebra, zebra_nht_send_update, TRACE_INFO)

/*
 * Zebra receives route change from kernel via netlink.
 * Traces: netlink_route_change_read_unicast() -> zebra收到kernel路由变化通知
 *   RTM_NEWROUTE / RTM_DELROUTE -> rib_add / rib_delete
 */
TRACEPOINT_EVENT(
	frr_zebra,
	zebra_netlink_route_change,
	TP_ARGS(vrf_id_t, vrf_id, const char *, prefix,
		const char *, route_type, uint32_t, metric,
		uint32_t, distance, bool, is_add),
	TP_FIELDS(
		ctf_integer(vrf_id_t, vrf_id, vrf_id)
		ctf_string(prefix, prefix)
		ctf_string(route_type, route_type)
		ctf_integer(uint32_t, metric, metric)
		ctf_integer(uint32_t, distance, distance)
		ctf_integer(uint8_t, is_add, is_add)
	)
)
TRACEPOINT_LOGLEVEL(frr_zebra, zebra_netlink_route_change, TRACE_INFO)

/*
 * Zebra receives nexthop change from kernel via netlink.
 * Traces: netlink_nexthop_change() -> zebra收到kernel下一跳变化通知
 *   RTM_NEWNEXTHOP / RTM_DELNEXTHOP -> zebra_nhg_kernel_find / zebra_nhg_kernel_del
 */
TRACEPOINT_EVENT(
	frr_zebra,
	zebra_netlink_nexthop_change,
	TP_ARGS(vrf_id_t, vrf_id, uint32_t, nhg_id,
		const char *, nh_type, bool, is_add),
	TP_FIELDS(
		ctf_integer(vrf_id_t, vrf_id, vrf_id)
		ctf_integer(uint32_t, nhg_id, nhg_id)
		ctf_string(nh_type, nh_type)
		ctf_integer(uint8_t, is_add, is_add)
	)
)
TRACEPOINT_LOGLEVEL(frr_zebra, zebra_netlink_nexthop_change, TRACE_INFO)

/*
 * Zebra receives interface link change from kernel via netlink.
 * Traces: netlink_link_change() -> zebra收到kernel接口变化通知
 *   RTM_NEWLINK / RTM_DELLINK -> if_add_update / if_delete_update
 */
TRACEPOINT_EVENT(
	frr_zebra,
	zebra_netlink_link_change,
	TP_ARGS(uint32_t, ns_id, const char *, ifname,
		uint32_t, ifindex, uint32_t, flags, bool, is_add),
	TP_FIELDS(
		ctf_integer(uint32_t, ns_id, ns_id)
		ctf_string(ifname, ifname)
		ctf_integer(uint32_t, ifindex, ifindex)
		ctf_integer(uint32_t, flags, flags)
		ctf_integer(uint8_t, is_add, is_add)
	)
)
TRACEPOINT_LOGLEVEL(frr_zebra, zebra_netlink_link_change, TRACE_INFO)

/*
 * Zebra receives interface address change from kernel via netlink.
 * Traces: netlink_interface_addr() -> zebra收到kernel接口地址变化通知
 *   RTM_NEWADDR / RTM_DELADDR -> connected_add / connected_delete
 */
TRACEPOINT_EVENT(
	frr_zebra,
	zebra_netlink_addr_change,
	TP_ARGS(uint32_t, ns_id, const char *, ifname,
		const char *, addr, uint32_t, prefixlen, bool, is_add),
	TP_FIELDS(
		ctf_integer(uint32_t, ns_id, ns_id)
		ctf_string(ifname, ifname)
		ctf_string(addr, addr)
		ctf_integer(uint32_t, prefixlen, prefixlen)
		ctf_integer(uint8_t, is_add, is_add)
	)
)
TRACEPOINT_LOGLEVEL(frr_zebra, zebra_netlink_addr_change, TRACE_INFO)

/*
 * Zebra interface up event.
 * Traces: if_up() -> zebra接口UP事件
 *   -> zebra_interface_up_update -> if_install_connected
 */
TRACEPOINT_EVENT(
	frr_zebra,
	zebra_if_up,
	TP_ARGS(vrf_id_t, vrf_id, const char *, ifname,
		uint32_t, ifindex, uint32_t, flags),
	TP_FIELDS(
		ctf_integer(vrf_id_t, vrf_id, vrf_id)
		ctf_string(ifname, ifname)
		ctf_integer(uint32_t, ifindex, ifindex)
		ctf_integer(uint32_t, flags, flags)
	)
)
TRACEPOINT_LOGLEVEL(frr_zebra, zebra_if_up, TRACE_INFO)

/*
 * Zebra interface down event.
 * Traces: if_down() -> zebra接口DOWN事件
 *   -> if_down_nhg_dependents -> zebra_interface_down_update -> if_uninstall_connected
 */
TRACEPOINT_EVENT(
	frr_zebra,
	zebra_if_down,
	TP_ARGS(vrf_id_t, vrf_id, const char *, ifname,
		uint32_t, ifindex, uint32_t, flags),
	TP_FIELDS(
		ctf_integer(vrf_id_t, vrf_id, vrf_id)
		ctf_string(ifname, ifname)
		ctf_integer(uint32_t, ifindex, ifindex)
		ctf_integer(uint32_t, flags, flags)
	)
)
TRACEPOINT_LOGLEVEL(frr_zebra, zebra_if_down, TRACE_INFO)

/* clang-format on */

#include <lttng/tracepoint-event.h>

#endif /* HAVE_LTTNG */

#endif /* _ZEBRA_TRACE_H */
