#include "test_zread_route_del.h"

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


void ZreadRouteDelTest::SetUp()
{
	setup_env();
}


void ZreadRouteDelTest::TearDown()
{
	teardown_env();
}


TEST_P(ZreadRouteDelTest, zread_route_del)
{
	struct test_case_route_del_t test_case = GetParam();

	assert_empty_state();
	std::cout << "=============start from empty state==============="
		  << std::endl;

	int ret = policy_utils.add_policy_into_srte_table(
		test_case.initial_state);

	EXPECT_EQ(ret, 0);

	std::cout << "=============adding initial routes==============="
		  << std::endl;
	// std::vector<struct api_route_t> routes =
	//  	NHGUtils::gen_route_for_nhgs(test_case.initial_state.nhgs);

	// add routes
	zebra_vrf *zvrf = policy_utils.get_mock_zvrf();
	zserv *client = policy_utils.get_mock_client();
	for (const auto &route : test_case.initial_state.route_nhg_map) {
		struct zapi_route api_route =
			common_utils::get_route_multi_policies(route);

		struct stream *s =
			common_utils::fill_stream_with_route(&api_route);
		EXPECT_NE(s, nullptr);

		zread_route_add(policy_utils.get_mock_client(), NULL, s,
				policy_utils.get_mock_zvrf());
	}

	std::cout << "===========check test result: initial state============="
		  << std::endl;
	EXPECT_TRUE(dump_and_check_state(test_case.initial_state));

	std::cout << "============put in test data============" << std::endl;

	// add route

	struct zapi_route api_route =
		common_utils::get_del_route(test_case.input_route);

	struct stream *s = common_utils::fill_stream_with_route(&api_route);
	EXPECT_NE(s, nullptr);

	zread_route_del(policy_utils.get_mock_client(), NULL, s,
			policy_utils.get_mock_zvrf());
	std::cout << "zread_route_del issued" << std::endl;

	std::cout << "===========check test result=============" << std::endl;
	EXPECT_TRUE(dump_and_check_state(test_case.final_state));
}


INSTANTIATE_TEST_CASE_P(zread_route_del, ZreadRouteDelTest,
			::testing::ValuesIn(read_all_test_cases_route_del(
				"resources/formatted_routedel.json")));
