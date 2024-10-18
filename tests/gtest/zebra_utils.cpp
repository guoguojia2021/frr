#include "zebra_utils.h"

#include <gtest/gtest.h>
#include <iostream>

#include "lib/hash.h"
#include "lib/nexthop.h"
#include "lib/zclient.h"
#include "libfrr.h"

#include "zebra.h"
#include "zebra/debug.h"
#include "zebra/router-id.h"
#include "zebra/table_manager.h"
#include "zebra/zapi_msg.h"
#include "zebra/zebra_mpls.h"
#include "zebra/zebra_nhg.h"
#include "zebra/zebra_nhg_private.h"
#include "zebra/zebra_rnh.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_srte.h"
#include "zebra/zebra_vxlan.h"

#include "test_model.h"
#include "common_utils.h"
#include "nhg_utils.h"
#include "policy_utils.h"
#include "rnh_utils.h"


extern long zebra_config_fib_max;


void setup_zebra_state(const struct zebra_state_t &initial_state,
		       zebra_vrf *zvrf, zserv *client)
{
	assert_empty_state();
	std::cout << "=============start from empty state==============="
		  << std::endl;

	int ret = policy_utils.add_policy_into_srte_table(initial_state);
	EXPECT_EQ(ret, 0);

	std::cout << "=============adding rnhs===============" << std::endl;
	for (const auto &rnh_list : initial_state.rnh_table) {
		struct prefix p;
		int ret = common_utils::prefix_t2prefix(&rnh_list.prefix, &p);
		EXPECT_EQ(ret, 0);

		for (auto it = rnh_list.rnh.crbegin();
		     it != rnh_list.rnh.crend(); it++) {
			std::cout << "Add rnh prefix "
				  << common_utils::addr2str(p.u.val)
				  << " color " << it->srte_color << std::endl;
			struct stream *s = RnhUtils::fill_stream_with_rnh(
				ZEBRA_NEXTHOP_REGISTER, &p, it->srte_color);
			EXPECT_NE(s, nullptr);
			struct zmsghdr hdr;
			zapi_parse_header(s, &hdr);
			hdr.length -= ZEBRA_HEADER_SIZE;
			zread_rnh_register(client, &hdr, s, zvrf);
		}
	}

	std::cout << "=============adding routes===============" << std::endl;
	std::vector<struct api_route_t> routes =
		NHGUtils::gen_route_for_nhgs(initial_state.nhgs);
	for (const auto &route : routes) {
		print_api_route(route);
	}

	// add routes
	for (const auto &route : routes) {
		struct zapi_route api_route =
			common_utils::get_zapi_route_from_t(route);
		struct stream *s =
			common_utils::fill_stream_with_route(&api_route);
		EXPECT_NE(s, nullptr);

		zread_route_add(policy_utils.get_mock_client(), NULL, s,
				policy_utils.get_mock_zvrf());
		std::cout << "zread_route_add issued" << std::endl;
	}

	std::cout << "===========validate initial state============="
		  << std::endl;
	EXPECT_TRUE(dump_and_check_state(initial_state));
}


void setup_global_env()
{
	// Needed for nhgs-related test cases
	// Otherwise, zebra_rib.c reports
	// "%%MAXPFXEXCEEDTHRESHOLD: The number of prefixes exceeded the
	// threshold."
	zebra_config_fib_max = 16;

	zebra_srte_init();
}


void setup_env()
{
	vrf_init(gtest_vrf_new, gtest_vrf_enable, gtest_vrf_disable,
		 gtest_vrf_delete);
	zrouter.nhgs =
		hash_create_size(8, zebra_nhg_hash_key, zebra_nhg_hash_equal,
				 "Zebra Router Nexthop Groups");
	zrouter.nhgs_id =
		hash_create_size(8, zebra_nhg_id_key, zebra_nhg_hash_id_equal,
				 "Zebra Router Nexthop Groups ID index");
	struct zebra_vrf *zvrf = (zebra_vrf *)vrf_info_lookup(VPN_VRF_ID);
	policy_utils.init();
	policy_utils.set_zvrf(zvrf);
	nhg_utils.init();
	nhg_utils.set_zvrf(zvrf);
}


void teardown_env()
{
	vrf_terminate();
	hash_clean(zrouter.nhgs_id, zebra_nhg_hash_free);
	hash_free(zrouter.nhgs_id);
	hash_clean(zrouter.nhgs, NULL);
	hash_free(zrouter.nhgs);
	struct zebra_router_table *zrt, *tmp;
	RB_FOREACH_SAFE (zrt, zebra_router_table_head, &zrouter.tables, tmp) {
		route_table_finish(zrt->table);
		RB_REMOVE(zebra_router_table_head, &zrouter.tables, zrt);
	}
	hash_iterate(srte_table_hash, free_srte_table_hash, NULL);
}


void perform_action(const struct step_action_t &action, zserv *client,
		    zebra_vrf *zvrf)
{
	struct zapi_sr_policy zp = {};
	struct stream *s;
	struct prefix p;
	int ret;
	struct zmsghdr hdr;
	switch (action.action) {
	case Action::POLICY_DEL:
		ret = policy_utils.get_input_policy_from_case_api_policy_t(
			&zp, &action.input_policy);
		EXPECT_EQ(ret, 0);
		s = policy_utils.fill_stream_with_policy(&zp);
		EXPECT_NE(s, nullptr);

		std::cout << "zread_srv6_policy_delete issued: color "
			  << action.input_policy.color << " prefix "
			  << common_utils::addr2str(
				     action.input_policy.endpoint.endpoint)
			  << "/" << action.input_policy.endpoint.prefixlen
			  << std::endl;
		zread_srv6_policy_delete(client, NULL, s, zvrf);
		break;
	case Action::POLICY_SET:
		std::cout << "policy_set not supported yet" << std::endl;
		break;
	case Action::RNH_REGISTER:
		ret = common_utils::prefix_t2prefix(
			&action.input_rnh.resolved_route, &p);
		EXPECT_EQ(ret, 0);

		std::cout << "zread_rnh_register issued: color "
			  << action.input_rnh.srte_color << " resolved_route "
			  << common_utils::addr2str(p.u.val) << std::endl;
		s = RnhUtils::fill_stream_with_rnh(ZEBRA_NEXTHOP_REGISTER, &p,
						   action.input_rnh.srte_color);
		EXPECT_NE(s, nullptr);

		zapi_parse_header(s, &hdr);
		zread_rnh_register(client, &hdr, s, zvrf);
		break;
	case Action::RNH_UNREGISTER:
		ret = common_utils::prefix_t2prefix(
			&action.input_rnh.resolved_route, &p);
		EXPECT_EQ(ret, 0);

		std::cout << "zread_rnh_unregister issued: color "
			  << action.input_rnh.srte_color << " resolved_route "
			  << common_utils::addr2str(p.u.val) << std::endl;

		s = RnhUtils::fill_stream_with_rnh(ZEBRA_NEXTHOP_UNREGISTER, &p,
						   action.input_rnh.srte_color);
		EXPECT_NE(s, nullptr);

		zapi_parse_header(s, &hdr);
		zread_rnh_unregister(client, &hdr, s, zvrf);

		break;
	case Action::ROUTE_ADD:
		std::cout << "route_add not supported yet" << std::endl;
		break;
	case Action::ROUTE_DEL:
		std::cout << "route_del not supported yet" << std::endl;
		break;
	}
}
