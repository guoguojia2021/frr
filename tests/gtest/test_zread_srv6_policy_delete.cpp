//
// Created by lsn on 2024/10/24.
//
#include "test_zread_srv6_policy_delete.h"


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

#include "common_utils.h"
#include "nhg_utils.h"
#include "policy_utils.h"
#include "test_model.h"
#include "zebra_utils.h"


void ZreadSrv6PolicyDeleteTest::SetUp()
{
	setup_env();
}

void ZreadSrv6PolicyDeleteTest::TearDown()
{
	teardown_env();
}


TEST_P(ZreadSrv6PolicyDeleteTest, PolicyDel)
{
	struct test_case_policy_set_del_t case_data = GetParam();
	std::cout << "test case #" << case_data.test_id << std::endl;
	int ret = 0;

	setup_zebra_state(case_data.initial_state);

	std::cout << "============put in test data============" << std::endl;
	gtest_policy_del(case_data.input_policy);

	std::cout << "===========check test result=============" << std::endl;
	EXPECT_TRUE(compare_zebra_state(case_data.final_state));
	EXPECT_TRUE(compare_msg_fifo(case_data.msg_fifo));
}


INSTANTIATE_TEST_SUITE_P(PolicyDelTestSuite, ZreadSrv6PolicyDeleteTest,
			 ::testing::ValuesIn(read_all_test_cases_policy_set_del(
				 "resources/formatted_policydel.json")));