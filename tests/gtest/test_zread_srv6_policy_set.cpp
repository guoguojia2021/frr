//
// Created by lsn on 2024/10/24.
//
#include "test_zread_srv6_policy_set.h"


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


void ZreadSrv6PolicySetTest::SetUp()
{
	setup_env();
}


void ZreadSrv6PolicySetTest::TearDown()
{
	teardown_env();
}


TEST_P(ZreadSrv6PolicySetTest, PolicySet)
{
	struct test_case_policy_set_del_t case_data = GetParam();
	std::cout << "test case #" << case_data.test_id << std::endl;
	int ret = 0;

	zebra_vrf *zvrf = policy_utils.get_mock_zvrf();
	zserv *client = policy_utils.get_mock_client();
	setup_zebra_state(case_data.initial_state, zvrf, client);

	std::cout << "============put in test data============" << std::endl;

	struct zapi_sr_policy zp = {};
	ret = policy_utils.get_input_policy_from_case_api_policy_t(
		&zp, &(case_data.input_policy));
	EXPECT_EQ(ret, 0);

	struct stream *s = policy_utils.fill_stream_with_policy(&zp);
	EXPECT_NE(s, nullptr);

	zread_srv6_policy_set(NULL, NULL, s, policy_utils.get_mock_zvrf());
	std::cout << "===========check test result=============" << std::endl;
	EXPECT_TRUE(dump_and_check_state(case_data.final_state));
}


INSTANTIATE_TEST_SUITE_P(PolicySetTestSuite, ZreadSrv6PolicySetTest,
			 ::testing::ValuesIn(read_all_test_cases_policy_set_del(
				 "resources/formatted_policyset.json")));