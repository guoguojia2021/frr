/* Tracing for BGP
 *
 * Copyright (C) 2020  NVIDIA Corporation
 * Quentin Young
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

#if !defined(_BGP_TRACE_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _BGP_TRACE_H

#include "lib/trace.h"

#ifdef HAVE_LTTNG

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER frr_bgp

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "bgpd/bgp_trace.h"

#include <lttng/tracepoint.h>

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "lib/stream.h"
#include "bgpd/bgp_evpn_private.h"
#include "bgpd/bgp_evpn_mh.h"


/* clang-format off */

TRACEPOINT_EVENT_CLASS(
	frr_bgp,
	packet_process,
	TP_ARGS(struct peer *, peer, bgp_size_t, size),
	TP_FIELDS(
		ctf_string(peer, PEER_HOSTNAME(peer))
	)
)

#define PKT_PROCESS_TRACEPOINT_INSTANCE(name)                                  \
	TRACEPOINT_EVENT_INSTANCE(                                             \
		frr_bgp, packet_process, name,                                 \
		TP_ARGS(struct peer *, peer, bgp_size_t, size))                \
	TRACEPOINT_LOGLEVEL(frr_bgp, name, TRACE_INFO)

PKT_PROCESS_TRACEPOINT_INSTANCE(open_process)
PKT_PROCESS_TRACEPOINT_INSTANCE(keepalive_process)
PKT_PROCESS_TRACEPOINT_INSTANCE(update_process)
PKT_PROCESS_TRACEPOINT_INSTANCE(notification_process)
PKT_PROCESS_TRACEPOINT_INSTANCE(capability_process)
PKT_PROCESS_TRACEPOINT_INSTANCE(refresh_process)

TRACEPOINT_EVENT(
	frr_bgp,
	packet_read,
	TP_ARGS(struct peer_connection *, connection, struct stream *, pkt),
	TP_FIELDS(
		ctf_string(peer, PEER_HOSTNAME(connection->peer))
		ctf_sequence_hex(uint8_t, packet, pkt->data, size_t,
				 STREAM_READABLE(pkt))
	)
)

TRACEPOINT_LOGLEVEL(frr_bgp, packet_read, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	process_update,
	TP_ARGS(struct peer *, peer, char *, pfx, uint32_t, addpath_id, afi_t,
		afi, safi_t, safi, struct attr *, attr),
	TP_FIELDS(
		ctf_string(peer, PEER_HOSTNAME(peer))
		ctf_string(prefix, pfx)
		ctf_integer(uint32_t, addpath_id, addpath_id)
		ctf_integer(afi_t, afi, afi)
		ctf_integer(safi_t, safi, safi)
		ctf_integer_hex(intptr_t, attribute_ptr, attr)
	)
)

TRACEPOINT_LOGLEVEL(frr_bgp, process_update, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	input_filter,
	TP_ARGS(struct peer *, peer, char *, pfx, afi_t, afi, safi_t, safi,
		const char *, result),
	TP_FIELDS(
		ctf_string(peer, PEER_HOSTNAME(peer))
		ctf_string(prefix, pfx)
		ctf_integer(afi_t, afi, afi)
		ctf_integer(safi_t, safi, safi)
		ctf_string(action, result)
	)
)

TRACEPOINT_LOGLEVEL(frr_bgp, input_filter, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	output_filter,
	TP_ARGS(struct peer *, peer, char *, pfx, afi_t, afi, safi_t, safi,
		const char *, result),
	TP_FIELDS(
		ctf_string(peer, PEER_HOSTNAME(peer))
		ctf_string(prefix, pfx)
		ctf_integer(afi_t, afi, afi)
		ctf_integer(safi_t, safi, safi)
		ctf_string(action, result)
	)
)

TRACEPOINT_LOGLEVEL(frr_bgp, output_filter, TRACE_INFO)

/* BMP tracepoints */

/* BMP mirrors a packet to all mirror-enabled targets */
TRACEPOINT_EVENT(
	frr_bgp,
	bmp_mirror_packet,
	TP_ARGS(struct peer *, peer, uint8_t, type, struct stream *, pkt),
	TP_FIELDS(
		ctf_string(peer, PEER_HOSTNAME(peer))
		ctf_integer(uint8_t, type, type)
		ctf_sequence_hex(uint8_t, packet, pkt->data, size_t,
				 STREAM_READABLE(pkt))
	)
)

TRACEPOINT_LOGLEVEL(frr_bgp, bmp_mirror_packet, TRACE_INFO)


/* BMP sends an EOR */
TRACEPOINT_EVENT(
	frr_bgp,
	bmp_eor,
	TP_ARGS(afi_t, afi, safi_t, safi, uint8_t, flags),
	TP_FIELDS(
		ctf_integer(afi_t, afi, afi)
		ctf_integer(safi_t, safi, safi)
		ctf_integer(uint8_t, flags, flags)
	)
)

TRACEPOINT_LOGLEVEL(frr_bgp, bmp_eor, TRACE_INFO)


/* BMP updates its copy of the last OPEN a peer sent */
TRACEPOINT_EVENT(
	frr_bgp,
	bmp_update_saved_open,
	TP_ARGS(struct peer *, peer, struct stream *, pkt),
	TP_FIELDS(
		ctf_string(peer, PEER_HOSTNAME(peer))
		ctf_sequence_hex(uint8_t, packet, pkt->data, size_t,
				 STREAM_READABLE(pkt))
	)
)

TRACEPOINT_LOGLEVEL(frr_bgp, bmp_update_saved_open, TRACE_DEBUG)


/* BMP is notified of a peer status change internally */
TRACEPOINT_EVENT(
	frr_bgp,
	bmp_peer_status_changed,
	TP_ARGS(struct peer *, peer),
	TP_FIELDS(
		ctf_string(peer, PEER_HOSTNAME(peer))
	)
)

TRACEPOINT_LOGLEVEL(frr_bgp, bmp_peer_status_changed, TRACE_DEBUG)


/*
 * BMP is notified that a peer has transitioned in the opposite direction of
 * Established internally
 */
TRACEPOINT_EVENT(
	frr_bgp,
	bmp_peer_backward_transition,
	TP_ARGS(struct peer *, peer),
	TP_FIELDS(
		ctf_string(peer, PEER_HOSTNAME(peer))
	)
)

TRACEPOINT_LOGLEVEL(frr_bgp, bmp_peer_backward, TRACE_DEBUG)


/*
 * BMP is hooked for a route process
 */
TRACEPOINT_EVENT(
	frr_bgp,
	bmp_process,
	TP_ARGS(struct peer *, peer, char *, pfx, afi_t,
		afi, safi_t, safi, bool, withdraw),
	TP_FIELDS(
		ctf_string(peer, PEER_HOSTNAME(peer))
		ctf_string(prefix, pfx)
		ctf_integer(afi_t, afi, afi)
		ctf_integer(safi_t, safi, safi)
		ctf_integer(bool, withdraw, withdraw)
	)
)

TRACEPOINT_LOGLEVEL(frr_bgp, bmp_process, TRACE_DEBUG)

/*
 * bgp_dest_lock/bgp_dest_unlock
 */
TRACEPOINT_EVENT(
	frr_bgp,
	bgp_dest_lock,
	TP_ARGS(struct bgp_dest *, dest),
	TP_FIELDS(
		ctf_string(prefix, bgp_dest_get_prefix_str(dest))
		ctf_integer(unsigned int, count, bgp_dest_get_lock_count(dest))
		ctf_string(afi, afi2str(bgp_dest_table(dest)->afi))
		ctf_string(safi, safi2str(bgp_dest_table(dest)->safi))
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, bgp_dest_lock, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	bgp_dest_unlock,
	TP_ARGS(struct bgp_dest *, dest),
	TP_FIELDS(
		ctf_string(prefix, bgp_dest_get_prefix_str(dest))
		ctf_integer(unsigned int, count, bgp_dest_get_lock_count(dest))
		ctf_string(afi, afi2str(bgp_dest_table(dest)->afi))
		ctf_string(safi, safi2str(bgp_dest_table(dest)->safi))
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, bgp_dest_unlock, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mac_ip_zsend,
	TP_ARGS(int, add, struct bgpevpn *, vpn,
		const struct prefix_evpn *, pfx,
		struct in_addr, vtep, esi_t *, esi),
	TP_FIELDS(
		ctf_string(action, add ? "add" : "del")
		ctf_integer(vni_t, vni, vpn->vni)
		ctf_array(unsigned char, mac, &pfx->prefix.macip_addr.mac,
			sizeof(struct ethaddr))
		ctf_array(unsigned char, ip, &pfx->prefix.macip_addr.ip,
			sizeof(struct ipaddr))
		ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_mac_ip_zsend, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_bum_vtep_zsend,
	TP_ARGS(int, add, struct bgpevpn *, vpn,
		const struct prefix_evpn *, pfx),
	TP_FIELDS(
		ctf_string(action, add ? "add" : "del")
		ctf_integer(vni_t, vni, vpn->vni)
		ctf_integer_network_hex(unsigned int, vtep,
			pfx->prefix.imet_addr.ip.ipaddr_v4.s_addr)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_bum_vtep_zsend, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mh_vtep_zsend,
	TP_ARGS(bool, add, struct bgp_evpn_es *, es,
		struct bgp_evpn_es_vtep *, es_vtep),
	TP_FIELDS(
		ctf_string(action, add ? "add" : "del")
		ctf_string(esi, es->esi_str)
		ctf_string(vtep, es_vtep->vtep_str)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_mh_vtep_zsend, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mh_nhg_zsend,
	TP_ARGS(bool, add, bool, type_v4, uint32_t, nhg_id,
		struct bgp_evpn_es_vrf *, es_vrf),
	TP_FIELDS(
		ctf_string(action, add ? "add" : "del")
		ctf_string(type, type_v4 ? "v4" : "v6")
		ctf_integer(unsigned int, nhg, nhg_id)
		ctf_string(esi, es_vrf->es->esi_str)
		ctf_integer(int, vrf, es_vrf->bgp_vrf->vrf_id)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_mh_nhg_zsend, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mh_nh_zsend,
	TP_ARGS(uint32_t, nhg_id, struct bgp_evpn_es_vtep *, vtep,
		struct bgp_evpn_es_vrf *, es_vrf),
	TP_FIELDS(
		ctf_integer(unsigned int, nhg, nhg_id)
		ctf_string(vtep, vtep->vtep_str)
		ctf_integer(int, svi, es_vrf->bgp_vrf->l3vni_svi_ifindex)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_mh_nh_zsend, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mh_nh_rmac_zsend,
	TP_ARGS(bool, add, struct bgp_evpn_nh *, nh),
	TP_FIELDS(
		ctf_string(action, add ? "add" : "del")
		ctf_integer(int, vrf, nh->bgp_vrf->vrf_id)
		ctf_string(nh, nh->nh_str)
		ctf_array(unsigned char, rmac, &nh->rmac,
			sizeof(struct ethaddr))
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_nh_rmac_zsend, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mh_local_es_add_zrecv,
	TP_ARGS(esi_t *, esi, struct in_addr, vtep,
		uint8_t, active, uint8_t, bypass, uint16_t, df_pref),
	TP_FIELDS(
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
		ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
		ctf_integer(uint8_t, active, active)
		ctf_integer(uint8_t, bypass, bypass)
		ctf_integer(uint16_t, df_pref, df_pref)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_mh_local_es_add_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mh_local_es_del_zrecv,
	TP_ARGS(esi_t *, esi),
	TP_FIELDS(
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_mh_local_es_del_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mh_local_es_evi_add_zrecv,
	TP_ARGS(esi_t *, esi, vni_t, vni),
	TP_FIELDS(
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
		ctf_integer(vni_t, vni, vni)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_mh_local_es_evi_add_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mh_local_es_evi_del_zrecv,
	TP_ARGS(esi_t *, esi, vni_t, vni),
	TP_FIELDS(
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
		ctf_integer(vni_t, vni, vni)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_mh_local_es_evi_del_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_local_vni_add_zrecv,
	TP_ARGS(vni_t, vni, struct in_addr, vtep, vrf_id_t, vrf,
			struct in_addr, mc_grp),
	TP_FIELDS(
		ctf_integer(vni_t, vni, vni)
		ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
		ctf_integer_network_hex(unsigned int, mc_grp,
			mc_grp.s_addr)
		ctf_integer(int, vrf, vrf)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_local_vni_add_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_local_vni_del_zrecv,
	TP_ARGS(vni_t, vni),
	TP_FIELDS(
		ctf_integer(vni_t, vni, vni)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_local_vni_del_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_local_macip_add_zrecv,
	TP_ARGS(vni_t, vni, struct ethaddr *, mac,
		struct ipaddr *, ip, uint32_t, flags,
		uint32_t, seqnum, esi_t *, esi),
	TP_FIELDS(
		ctf_integer(vni_t, vni, vni)
		ctf_array(unsigned char, mac, mac,
			sizeof(struct ethaddr))
		ctf_array(unsigned char, ip, ip,
			sizeof(struct ipaddr))
		ctf_integer(uint32_t, flags, flags)
		ctf_integer(uint32_t, seq, seqnum)
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_local_macip_add_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_local_macip_del_zrecv,
	TP_ARGS(vni_t, vni, struct ethaddr *, mac, struct ipaddr *, ip,
			int, state),
	TP_FIELDS(
		ctf_integer(vni_t, vni, vni)
		ctf_array(unsigned char, mac, mac,
			sizeof(struct ethaddr))
		ctf_array(unsigned char, ip, ip,
			sizeof(struct ipaddr))
		ctf_integer(int, state, state)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_local_macip_del_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_local_l3vni_add_zrecv,
	TP_ARGS(vni_t, vni, vrf_id_t, vrf,
			struct ethaddr *, svi_rmac,
			struct ethaddr *, vrr_rmac, int, filter,
			struct in_addr, vtep, int, svi_ifindex,
			bool, anycast_mac),
	TP_FIELDS(
		ctf_integer(vni_t, vni, vni)
		ctf_integer(int, vrf, vrf)
		ctf_array(unsigned char, svi_rmac, svi_rmac,
			sizeof(struct ethaddr))
		ctf_array(unsigned char, vrr_rmac, vrr_rmac,
			sizeof(struct ethaddr))
		ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
		ctf_integer(int, filter, filter)
		ctf_integer(int, svi_ifindex, svi_ifindex)
		ctf_string(anycast_mac, anycast_mac ? "y" : "n")
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_local_l3vni_add_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_local_l3vni_del_zrecv,
	TP_ARGS(vni_t, vni, vrf_id_t, vrf),
	TP_FIELDS(
		ctf_integer(vni_t, vni, vni)
		ctf_integer(int, vrf, vrf)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_local_l3vni_del_zrecv, TRACE_INFO)
/*
 * BGP receives interface up from zebra.
 * Traces: bgp_ifp_up() -> bgp收到zebra接口UP通知
 */
TRACEPOINT_EVENT(
	frr_bgp,
	bgp_zebra_intf_up,
	TP_ARGS(vrf_id_t, vrf_id, const char *, ifname),
	TP_FIELDS(
		ctf_integer(vrf_id_t, vrf_id, vrf_id)
		ctf_string(ifname, ifname)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, bgp_zebra_intf_up, TRACE_INFO)

/*
 * BGP receives interface down from zebra.
 * Traces: bgp_ifp_down() -> bgp收到zebra接口DOWN通知
 */
TRACEPOINT_EVENT(
	frr_bgp,
	bgp_zebra_intf_down,
	TP_ARGS(vrf_id_t, vrf_id, const char *, ifname),
	TP_FIELDS(
		ctf_integer(vrf_id_t, vrf_id, vrf_id)
		ctf_string(ifname, ifname)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, bgp_zebra_intf_down, TRACE_INFO)

/*
 * BGP receives interface address add from zebra.
 * Traces: bgp_interface_address_add() -> bgp收到zebra接口地址添加通知
 */
TRACEPOINT_EVENT(
	frr_bgp,
	bgp_zebra_addr_add,
	TP_ARGS(vrf_id_t, vrf_id, const char *, ifname,
		const char *, addr),
	TP_FIELDS(
		ctf_integer(vrf_id_t, vrf_id, vrf_id)
		ctf_string(ifname, ifname)
		ctf_string(addr, addr)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, bgp_zebra_addr_add, TRACE_INFO)

/*
 * BGP receives interface address delete from zebra.
 * Traces: bgp_interface_address_delete() -> bgp收到zebra接口地址删除通知
 */
TRACEPOINT_EVENT(
	frr_bgp,
	bgp_zebra_addr_del,
	TP_ARGS(vrf_id_t, vrf_id, const char *, ifname,
		const char *, addr),
	TP_FIELDS(
		ctf_integer(vrf_id_t, vrf_id, vrf_id)
		ctf_string(ifname, ifname)
		ctf_string(addr, addr)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, bgp_zebra_addr_del, TRACE_INFO)

/*
 * BGP receives nexthop update from zebra.
 * Traces: bgp_parse_nexthop_update() -> bgp收到zebra下一跳更新消息
 */
TRACEPOINT_EVENT(
	frr_bgp,
	bgp_zebra_nh_update,
	TP_ARGS(vrf_id_t, vrf_id, const char *, prefix,
		uint32_t, nh_num, uint32_t, metric,
		uint32_t, srte_color),
	TP_FIELDS(
		ctf_integer(vrf_id_t, vrf_id, vrf_id)
		ctf_string(prefix, prefix)
		ctf_integer(uint32_t, nh_num, nh_num)
		ctf_integer(uint32_t, metric, metric)
		ctf_integer(uint32_t, srte_color, srte_color)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, bgp_zebra_nh_update, TRACE_INFO)

/*
 * BGP announces route to zebra.
 * Traces: bgp_zebra_announce() -> bgp下发路由到zebra
 */
TRACEPOINT_EVENT(
	frr_bgp,
	bgp_zebra_route_announce,
	TP_ARGS(vrf_id_t, vrf_id, const char *, prefix,
		uint32_t, nh_count, uint32_t, distance,
		uint32_t, metric, bool, is_add),
	TP_FIELDS(
		ctf_integer(vrf_id_t, vrf_id, vrf_id)
		ctf_string(prefix, prefix)
		ctf_integer(uint32_t, nh_count, nh_count)
		ctf_integer(uint32_t, distance, distance)
		ctf_integer(uint32_t, metric, metric)
		ctf_integer(uint8_t, is_add, is_add)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, bgp_zebra_route_announce, TRACE_INFO)

/*
 * BGP withdraws route from zebra.
 * Traces: bgp_zebra_withdraw() -> bgp从zebra撤销路由
 */
TRACEPOINT_EVENT(
	frr_bgp,
	bgp_zebra_route_withdraw,
	TP_ARGS(vrf_id_t, vrf_id, const char *, prefix),
	TP_FIELDS(
		ctf_integer(vrf_id_t, vrf_id, vrf_id)
		ctf_string(prefix, prefix)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, bgp_zebra_route_withdraw, TRACE_INFO)

/* clang-format on */

#include <lttng/tracepoint-event.h>

#endif /* HAVE_LTTNG */

#endif /* _BGP_TRACE_H */
