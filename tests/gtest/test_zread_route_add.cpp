#include "test_zread_route_add.h"

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
#include "rib_utils.h"
#include "zebra_utils.h"


void ZreadRouteAddTest::SetUp()
{
	setup_env();
}


void ZreadRouteAddTest::TearDown()
{
	teardown_env();
}


TEST_P(ZreadRouteAddTest, zread_route_add)
{
	struct test_case_route_add_t test_case = GetParam();
	std::cout << "test case #" << test_case.test_id << std::endl;

	setup_zebra_state(test_case.initial_state);

	std::cout << "============put in test data============" << std::endl;
	gtest_route_add(test_case.input_route);

	std::cout << "===========check test result=============" << std::endl;
	EXPECT_TRUE(compare_zebra_state(test_case.final_state));
	EXPECT_TRUE(compare_msg_fifo(test_case.msg_fifo));
}


INSTANTIATE_TEST_CASE_P(RouteAddTestSuite, ZreadRouteAddTest,
			::testing::ValuesIn(read_all_test_cases_route_add(
				"resources/formatted_routeadd.json")));