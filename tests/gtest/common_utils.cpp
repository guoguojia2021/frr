//
// Created by lsn on 2024/12/13.
//
#include <map>
#include <iostream>
#include <cstring>
#include <gtest/gtest.h>

#include "common_utils.h"
#include "nhg_utils.h"
#include "policy_utils.h"
#include "rnh_utils.h"
#include "rib_utils.h"
#include "test_model.h"

#include "zebra.h"
#include "zebra/debug.h"
#include "zebra/router-id.h"
#include "zebra/table_manager.h"
#include "zebra/zapi_msg.h"
#include "zebra/zebra_mpls.h"
#include "zebra/zebra_nhg.h"
#include "zebra/zebra_rnh.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_srte.h"
#include "zebra/zebra_vxlan.h"


int common_utils::prefix2_prefix_t(const struct prefix *p, struct prefix_t &dst)
{
	if (p->family == AF_INET) {
		dst.family = AF_INET;
		dst.prefixlen = p->prefixlen;
		std::memset(dst.endpoint, 0, sizeof(dst.endpoint));
		std::memcpy(dst.endpoint, &p->u.prefix4.s_addr, 4);
	} else if (p->family == AF_INET6) {
		dst.family = AF_INET6;
		dst.prefixlen = p->prefixlen;
		std::memcpy(dst.endpoint, p->u.val, 16);
	} else {
		return -1;
	}

	return 0;
}


extern void table_manager_enable(struct zebra_vrf *zvrf);

static void zebra_rnhtable_node_cleanup(struct route_table *table,
					struct route_node *node)
{
	if (node->info)
		zebra_free_rnh((struct rnh *)node->info);
}

/*
 * Create a routing table for the specific AFI/SAFI in the given VRF.
 */
static void zebra_vrf_table_create(struct zebra_vrf *zvrf, afi_t afi,
				   safi_t safi)
{
	struct route_node *rn;
	struct prefix p;

	assert(!zvrf->table[afi][safi]);

	zvrf->table[afi][safi] =
		zebra_router_get_table(zvrf, zvrf->table_id, afi, safi);

	memset(&p, 0, sizeof(p));
	p.family = afi2family(afi);

	rn = srcdest_rnode_get(zvrf->table[afi][safi], &p, NULL);
	zebra_rib_create_dest(rn);
}

int gtest_vrf_new(struct vrf *vrf)
{
	struct zebra_vrf *zvrf;


	zvrf = zebra_vrf_alloc(vrf);
	zvrf->zns = new zebra_ns;

	otable_init(&zvrf->other_tables);

	router_id_init(zvrf);

	/* Initiate Table Manager per ZNS */
	table_manager_enable(zvrf);

	return 0;
}

/* Callback upon disabling a VRF. */
int gtest_vrf_disable(struct vrf *vrf)
{
	struct zebra_vrf *zvrf = (zebra_vrf *)vrf->info;
	struct interface *ifp;
	afi_t afi;
	safi_t safi;

	assert(zvrf);
	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("VRF %s id %u is now inactive",
			   zvrf_alias_name(zvrf), zvrf_id(zvrf));

	/* Stop any VxLAN-EVPN processing. */
	zebra_vxlan_vrf_disable(zvrf);

	/* Remove all routes. */
	for (int i = 1; i <= 2; i++) {
		route_table_finish(zvrf->rnh_table[afi_t(i)]);
		zvrf->rnh_table[afi_t(i)] = NULL;
		route_table_finish(zvrf->rnh_table_multicast[afi_t(i)]);
		zvrf->rnh_table_multicast[afi_t(i)] = NULL;

		for (int j = 1; j <= 2; j++) {
			rib_close_table(zvrf->table[afi_t(i)][safi_t(j)]);
		}
	}

	zebra_mpls_cleanup_tables(zvrf);
	zebra_pw_exit(zvrf);

	for (int i = 1; i <= 2; i++) {
		for (int j = 1; j <= 2; j++) {

			zebra_router_release_table(zvrf, zvrf->table_id,
						   afi_t(i), safi_t(j));
			zvrf->table[i][j] = NULL;
		}
	}

	return 0;
}

/* Callback upon enabling a VRF. */
int gtest_vrf_enable(struct vrf *vrf)
{
	struct zebra_vrf *zvrf = (zebra_vrf *)vrf->info;
	struct route_table *table;
	afi_t afi;
	safi_t safi;

	assert(zvrf);

#if defined(HAVE_RTADV)
	// rtadv_vrf_init(zvrf);
#endif

	/* Inform clients that the VRF is now active. This is an
	 * add for the clients.
	 */

	/* Allocate tables */
	for (int i = 1; i <= 2; i++) {
		for (int j = 1; j <= 2; j++) {
			zebra_vrf_table_create(zvrf, afi_t(i), safi_t(j));
		}


		table = route_table_init();
		table->cleanup = zebra_rnhtable_node_cleanup;
		zvrf->rnh_table[afi_t(i)] = table;

		table = route_table_init();
		table->cleanup = zebra_rnhtable_node_cleanup;
		zvrf->rnh_table_multicast[afi_t(i)] = table;
	}

	/* Kick off any VxLAN-EVPN processing. */
	zebra_vxlan_vrf_enable(zvrf);

	return 0;
}

int gtest_vrf_delete(struct vrf *vrf)
{
	struct zebra_vrf *zvrf = (zebra_vrf *)vrf->info;
	struct other_route_table *otable;

	assert(zvrf);
	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("VRF %s id %u deleted", zvrf_alias_name(zvrf),
			   zvrf_id(zvrf));

	table_manager_disable(zvrf);


	zebra_mpls_close_tables(zvrf);


	/* Cleanup EVPN states for vrf */
	zebra_vxlan_vrf_delete(zvrf);

	list_delete_all_node(zvrf->rid_all_sorted_list);
	list_delete_all_node(zvrf->rid_lo_sorted_list);

	list_delete_all_node(zvrf->rid6_all_sorted_list);
	list_delete_all_node(zvrf->rid6_lo_sorted_list);

	otable_fini(&zvrf->other_tables);
	vrf->info = NULL;

	return 0;
}

void print_state()
{
	std::map<uint32_t, srte_table_t> dump_srte_state;
	hash_iterate(srte_table_hash, dump_srte_hash_bucket, &dump_srte_state);

	std::vector<struct nhg_t> dump_nhg_state = NHGUtils::dump_nhgs();

	const std::vector<struct rnh_list_t> dump_rnh_table =
		RnhUtils::dump_rnh_table();
}

bool dump_and_check_state(const struct zebra_state_t &expected_state)
{
	std::map<uint32_t, srte_table_t> dump_srte_state;
	hash_iterate(srte_table_hash, dump_srte_hash_bucket, &dump_srte_state);

	std::vector<struct nhg_t> dump_nhg_state = NHGUtils::dump_nhgs();

	const std::vector<struct rnh_list_t> dump_rnh_table =
		RnhUtils::dump_rnh_table();

	const std::vector<struct api_route_t> dump_rib_state =
		RibUtils::dump_rib_state();

	bool res = true;
	if (!PolicyUtils::check_srte_states(dump_srte_state, expected_state)) {
		std::cout << "srte state not match" << std::endl;
		res = false;
	}
	if (!NHGUtils::check_nhg_state(expected_state.nhgs, dump_nhg_state)) {
		std::cout << "nhg state not match" << std::endl;
		res = false;
	}
	if (!RnhUtils::check_rnh_table(dump_rnh_table,
				       expected_state.rnh_table)) {
		std::cout << "rnh_table not match" << std::endl;
		res = false;
	}
	if (!RibUtils::check_rib_state(dump_rib_state, expected_state.rib)) {
		std::cout << "rib state not match" << std::endl;
		res = false;
	}

	return res;
}

void assert_empty_state()
{
	std::map<uint32_t, srte_table_t> dump_srte_state;
	EXPECT_NE(nullptr, srte_table_hash)
		<< "srte_table_hash cannot be null" << std::endl;
	hash_iterate(srte_table_hash, dump_srte_hash_bucket, &dump_srte_state);
	EXPECT_TRUE(dump_srte_state.empty());

	std::vector<struct nhg_t> dump_nhg_state = NHGUtils::dump_nhgs();
	EXPECT_TRUE(dump_nhg_state.empty());
	EXPECT_EQ(0, zrouter.nhgs->count);
}