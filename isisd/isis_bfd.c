/*
 * IS-IS Rout(e)ing protocol - BFD support
 * Copyright (C) 2018 Christian Franke
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

#include "zclient.h"
#include "nexthop.h"
#include "bfd.h"
#include "lib_errors.h"

#include "isisd/isis_bfd.h"
#include "isisd/isis_zebra.h"
#include "isisd/isis_common.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_circuit.h"
#include "isisd/isisd.h"
#include "isisd/fabricd.h"
#include "isisd/isis_pdu.h"

DEFINE_MTYPE_STATIC(ISISD, BFD_SESSION, "ISIS BFD Session");

static void adj_bfd_cb(struct bfd_session_params *bsp,
		       const struct bfd_session_status *bss, void *arg)
{
	struct isis_adjacency *adj = arg;
	struct isis_circuit *circuit = adj->circuit;

	if (IS_DEBUG_BFD)
		zlog_debug(
			"ISIS-BFD: BFD changed status for adjacency %s old %s new %s",
			isis_adj_name(adj),
			bfd_get_status_str(bss->previous_state),
			bfd_get_status_str(bss->state));

	if (bss->state == BFD_STATUS_DOWN
	    && bss->previous_state == BFD_STATUS_UP) {
		adj->circuit->area->bfd_signalled_down = true;

		zlog_warn(
			"ISIS-BFD: BFD session DOWN for neighbor %s on interface %s, bringing IS-IS adjacency DOWN",
			isis_adj_name(adj),
			circuit->interface->name);

		/* RFC 6213: BFD strict mode handling
		 * If negotiated mode is strict and BFD session goes down,
		 * block adjacency from being re-established until BFD
		 * session comes back up.
		 */
		if (adj->bfd_negotiated_mode == ISIS_BFD_MODE_STRICT) {
			adj->bfd_strict_blocked = true;
		}

		isis_adj_state_change(&adj, ISIS_ADJ_DOWN,
				      "bfd session went down");
	} else if (bss->state == BFD_STATUS_UP) {
		/* Clear BFD strict check block when session comes up */
		if (adj->bfd_strict_blocked) {
			if (IS_DEBUG_BFD)
				zlog_debug(
					"ISIS-BFD: BFD session up, clearing strict mode block for adjacency %s",
					isis_adj_name(adj));
			adj->bfd_strict_blocked = false;
		}

		/* RFC 6213: In strict BFD mode, if the adjacency
		 * is not UP yet, trigger a hello to re-evaluate the
		 * adjacency state. The next hello from the neighbor will
		 * call isis_adj_process_threeway() which will now allow
		 * the adjacency to go UP since BFD is established.
		 */
		if (adj->bfd_negotiated_mode == ISIS_BFD_MODE_STRICT
		    && adj->adj_state != ISIS_ADJ_UP) {
			const char *adj_state_str;
			switch (adj->adj_state) {
			case ISIS_ADJ_INITIALIZING:
				adj_state_str = "Initializing";
				break;
			case ISIS_ADJ_DOWN:
				adj_state_str = "Down";
				break;
			default:
				adj_state_str = "Unknown";
				break;
			}
			if (IS_DEBUG_BFD)
				zlog_debug(
					"ISIS-BFD: BFD session UP in strict mode for neighbor %s, adjacency is %s, triggering hello to allow adjacency UP",
					isis_adj_name(adj), adj_state_str);
			send_hello_sched(circuit, 0, TRIGGERED_IIH_DELAY);
		}
	}
}

static void bfd_handle_adj_down(struct isis_adjacency *adj)
{
	bfd_sess_free(&adj->bfd_session);
}

static void bfd_handle_adj_up(struct isis_adjacency *adj)
{
	struct isis_circuit *circuit = adj->circuit;
	int family;
	union g_addr dst_ip;
	union g_addr src_ip;
	struct list *local_ips;
	struct prefix *local_ip;

	if (circuit->bfd_config.mode == ISIS_BFD_MODE_DISABLED) {
		if (IS_DEBUG_BFD)
			zlog_debug(
				"ISIS-BFD: skipping BFD initialization on adjacency with %s because BFD is not enabled for the circuit",
				isis_adj_name(adj));
		goto out;
	}

	/* If IS-IS IPv6 is configured wait for IPv6 address to be programmed
	 * before starting up BFD
	 */
	if (circuit->ipv6_router
	    && (listcount(circuit->ipv6_link) == 0
		|| adj->ll_ipv6_count == 0)) {
		if (IS_DEBUG_BFD)
			zlog_debug(
				"ISIS-BFD: skipping BFD initialization on adjacency with %s because IPv6 is enabled but not ready",
				isis_adj_name(adj));
		return;
	}

	/*
	 * If IS-IS is enabled for both IPv4 and IPv6 on the circuit, prefer
	 * creating a BFD session over IPv6.
	 */
	if (circuit->ipv6_router && adj->ll_ipv6_count) {
		family = AF_INET6;
		dst_ip.ipv6 = adj->ll_ipv6_addrs[0];
		local_ips = circuit->ipv6_link;
		if (list_isempty(local_ips)) {
			if (IS_DEBUG_BFD)
				zlog_debug(
					"ISIS-BFD: skipping BFD initialization: IPv6 enabled and no local IPv6 addresses");
			goto out;
		}
		local_ip = listgetdata(listhead(local_ips));
		src_ip.ipv6 = local_ip->u.prefix6;
	} else if (circuit->ip_router && adj->ipv4_address_count) {
		family = AF_INET;
		dst_ip.ipv4 = adj->ipv4_addresses[0];
		local_ips = fabricd_ip_addrs(adj->circuit);
		if (!local_ips || list_isempty(local_ips)) {
			if (IS_DEBUG_BFD)
				zlog_debug(
					"ISIS-BFD: skipping BFD initialization: IPv4 enabled and no local IPv4 addresses");
			goto out;
		}
		local_ip = listgetdata(listhead(local_ips));
		src_ip.ipv4 = local_ip->u.prefix4;
	} else
		goto out;

	if (adj->bfd_session == NULL)
		adj->bfd_session = bfd_sess_new(adj_bfd_cb, adj);

	bfd_sess_set_timers(adj->bfd_session, circuit->bfd_config.detection_multiplier,
			    circuit->bfd_config.min_rx, circuit->bfd_config.min_tx);
	if (family == AF_INET)
		bfd_sess_set_ipv4_addrs(adj->bfd_session, &src_ip.ipv4,
					&dst_ip.ipv4);
	else
		bfd_sess_set_ipv6_addrs(adj->bfd_session, &src_ip.ipv6,
					&dst_ip.ipv6);
	bfd_sess_set_interface(adj->bfd_session, adj->circuit->interface->name);
	bfd_sess_set_vrf(adj->bfd_session,
			 adj->circuit->interface->vrf->vrf_id);
	bfd_sess_set_profile(adj->bfd_session, circuit->bfd_config.profile);
	bfd_sess_install(adj->bfd_session);
	return;
out:
	bfd_handle_adj_down(adj);
}

static int bfd_handle_adj_state_change(struct isis_adjacency *adj)
{
	/* In negotiated strict BFD mode, start BFD as early as possible
	 * so BFD session can come UP before the adjacency transitions.
	 */
	if (adj->bfd_negotiated_mode == ISIS_BFD_MODE_STRICT
	    && adj->adj_state != ISIS_ADJ_DOWN) {
		bfd_handle_adj_up(adj);
	} else if (adj->adj_state == ISIS_ADJ_UP) {
		bfd_handle_adj_up(adj);
	} else {
		bfd_handle_adj_down(adj);
	}
	return 0;
}

static void bfd_adj_cmd(struct isis_adjacency *adj)
{
	if (adj->circuit->bfd_config.mode == ISIS_BFD_MODE_DISABLED) {
		bfd_handle_adj_down(adj);
		return;
	}

	/* In negotiated strict BFD mode, start BFD as soon as neighbor
	 * has BFD-enabled TLV, even before adjacency is UP. BFD must
	 * establish first so it can gate the adjacency UP transition.
	 */
	if (adj->bfd_negotiated_mode == ISIS_BFD_MODE_STRICT) {
		bfd_handle_adj_up(adj);
	} else if (adj->adj_state == ISIS_ADJ_UP) {
		bfd_handle_adj_up(adj);
	} else {
		bfd_handle_adj_down(adj);
	}
}

void isis_bfd_circuit_cmd(struct isis_circuit *circuit)
{
	switch (circuit->circ_type) {
	case CIRCUIT_T_BROADCAST:
		for (int level = ISIS_LEVEL1; level <= ISIS_LEVEL2; level++) {
			struct list *adjdb = circuit->u.bc.adjdb[level - 1];

			struct listnode *node;
			struct isis_adjacency *adj;

			if (!adjdb)
				continue;
			for (ALL_LIST_ELEMENTS_RO(adjdb, node, adj)) {
				isis_bfd_recompute_negotiated_mode(adj);
				bfd_adj_cmd(adj);
			}
		}
		break;
	case CIRCUIT_T_P2P:
		if (circuit->u.p2p.neighbor) {
			isis_bfd_recompute_negotiated_mode(
				circuit->u.p2p.neighbor);
			bfd_adj_cmd(circuit->u.p2p.neighbor);
		}
		break;
	default:
		break;
	}
}

static int bfd_handle_adj_ip_enabled(struct isis_adjacency *adj, int family,
				     bool global)
{

	if (family != AF_INET6 || global)
		return 0;

	if (adj->bfd_session)
		return 0;

	/* In negotiated strict BFD mode, start BFD even before
	 * adjacency is UP.
	 */
	if (adj->adj_state != ISIS_ADJ_UP
	    && adj->bfd_negotiated_mode != ISIS_BFD_MODE_STRICT)
		return 0;

	bfd_handle_adj_up(adj);

	return 0;
}

static int bfd_handle_circuit_add_addr(struct isis_circuit *circuit)
{
	struct isis_adjacency *adj;
	struct listnode *node;

	if (circuit->area == NULL)
		return 0;

	for (ALL_LIST_ELEMENTS_RO(circuit->area->adjacency_list, node, adj)) {
		if (adj->bfd_session)
			continue;

		/* In negotiated strict BFD mode, start BFD even before
		 * adjacency is UP.
		 */
		if (adj->adj_state != ISIS_ADJ_UP
		    && adj->bfd_negotiated_mode != ISIS_BFD_MODE_STRICT)
			continue;

		bfd_handle_adj_up(adj);
	}

	return 0;
}

void isis_bfd_init(struct thread_master *tm)
{
	bfd_protocol_integration_init(zclient, tm);

	hook_register(isis_adj_state_change_hook, bfd_handle_adj_state_change);
	hook_register(isis_adj_ip_enabled_hook, bfd_handle_adj_ip_enabled);
	hook_register(isis_circuit_add_addr_hook, bfd_handle_circuit_add_addr);
}

/* RFC 6213: BFD mode helpers
 *
 * In strict BFD mode, the IS-IS adjacency must NOT go UP until
 * the BFD session is UP. BFD must be started as early as possible
 * (when we have neighbor info from TLVs), and the adjacency is
 * blocked from transitioning to UP until BFD confirms reachability.
 *
 * The bfd_negotiated_mode is computed in isis_tlvs_to_adj() based on
 * both local and remote BFD configuration:
 * - Either side strict → negotiated as strict
 * - Both sides standard → negotiated as standard
 * - Neighbor has no BFD → not blocked (adjacency can come up)
 */

/* Recompute bfd_negotiated_mode for an adjacency based on the current
 * local circuit BFD config and the stored remote TLV info.
 * Must be called whenever the local BFD config changes, so that
 * bfd_negotiated_mode stays consistent even before the next hello
 * arrives.
 */
void isis_bfd_recompute_negotiated_mode(struct isis_adjacency *adj)
{
	enum isis_bfd_mode new_negotiated = ISIS_BFD_MODE_DISABLED;

	if (adj->circuit->bfd_config.mode == ISIS_BFD_MODE_STRICT
	    && adj->bfd_enabled_received) {
		/* Local strict + neighbor BFD enabled → strict */
		new_negotiated = ISIS_BFD_MODE_STRICT;
	} else if (adj->circuit->bfd_config.mode == ISIS_BFD_MODE_STANDARD
		   && adj->bfd_enabled_received) {
		new_negotiated = ISIS_BFD_MODE_STANDARD;
	}

	if (adj->bfd_negotiated_mode != new_negotiated) {
		if (IS_DEBUG_BFD)
			zlog_debug(
				"ISIS-BFD: BFD negotiated mode changed for neighbor %s: %s → %s",
				isis_adj_name(adj),
				adj->bfd_negotiated_mode == ISIS_BFD_MODE_STRICT ? "strict" :
				adj->bfd_negotiated_mode == ISIS_BFD_MODE_STANDARD ? "standard" : "disabled",
				new_negotiated == ISIS_BFD_MODE_STRICT ? "strict" :
				new_negotiated == ISIS_BFD_MODE_STANDARD ? "standard" : "disabled");
		adj->bfd_negotiated_mode = new_negotiated;
	}
}

/* Start BFD session for strict mode if not already running.
 * Called from isis_adj_process_threeway() before the adjacency
 * UP check, so BFD can begin establishing while the adjacency
 * is still in INITIALIZING state.
 */
void isis_bfd_adj_establish(struct isis_adjacency *adj)
{
	if (adj->bfd_negotiated_mode != ISIS_BFD_MODE_STRICT)
		return;

	if (adj->bfd_session)
		return;
	if (IS_DEBUG_BFD)
		zlog_debug(
		"ISIS-BFD: Strict BFD mode negotiated for neighbor %s, starting BFD session before adjacency UP",
			isis_adj_name(adj));
	bfd_handle_adj_up(adj);
}

/* Check whether the adjacency is blocked from going UP by strict BFD.
 * Returns true if negotiated BFD mode is strict and BFD session is
 * not UP.
 *
 * Requirement 1: one side strict, other side no BFD →
 *   bfd_negotiated_mode = DISABLED (neighbor has no BFD TLV),
 *   so this returns false → adjacency can come up normally.
 *
 * Requirement 2: one side strict, other side standard →
 *   bfd_negotiated_mode = STRICT (auto-negotiated),
 *   so this returns true until BFD is UP.
 *
 * Requirement 3: if the adjacency is already UP, do not block it
 *   even if strict BFD was configured after the adjacency came up.
 *   Strict mode only affects the initial adjacency establishment;
 *   once UP, the adjacency stays UP until BFD goes DOWN explicitly.
 */
bool isis_bfd_adj_blocked(struct isis_adjacency *adj)
{
	if (adj->bfd_negotiated_mode != ISIS_BFD_MODE_STRICT)
		return false;

	/* Already UP adjacency is not blocked by strict BFD.
	 * BFD session down will tear it down via adj_bfd_cb.
	 */
	if (adj->adj_state == ISIS_ADJ_UP)
		return false;

	if (adj->bfd_strict_blocked)
		return true;

	if (!adj->bfd_session)
		return true;

	if (bfd_sess_status(adj->bfd_session) != BSS_UP)
		return true;

	return false;
}
