/*
 * Illustration of nhg_entry shapes
 * */


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


extern unsigned long zebra_config_fib_max;

class ZebraNhgsExample : public ::testing::Test
{
      protected:
	void SetUp() override;
	void TearDown() override;

	static void SetUpTestSuite()
	{
		zebra_srte_init();
	}
};


void ZebraNhgsExample::SetUp()
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
	zebra_config_fib_max = 10;
	policy_utils.init();
	policy_utils.set_zvrf(zvrf);
	nhg_utils.init();
	nhg_utils.set_zvrf(zvrf);
}


void ZebraNhgsExample::TearDown()
{
	hash_clean(zrouter.nhgs_id, zebra_nhg_hash_free);
	hash_free(zrouter.nhgs_id);
	hash_clean(zrouter.nhgs, NULL);
	hash_free(zrouter.nhgs);
	vrf_terminate();
	struct zebra_router_table *zrt, *tmp;
	RB_FOREACH_SAFE (zrt, zebra_router_table_head, &zrouter.tables, tmp) {
		route_table_finish(zrt->table);
		RB_REMOVE(zebra_router_table_head, &zrouter.tables, zrt);
	}
	hash_iterate(srte_table_hash, free_srte_table_hash, NULL);
}

static const char *route_prefixes[] = {"2.2.0.0/24", "2.2.1.0/24",
				       "2.2.2.0/24"};

/*
 * The nhg_entry for different policies are independent, even when
 * both rely on sidlist "b".
 * */
TEST_F(ZebraNhgsExample, SinglePolicySingleRoute)
{
	std::vector<test_case_policy_set_del_t> cases =
		read_all_test_cases_policy_set_del(
			"resources/zebra_nhgs_example/single_policy_route.json");
	test_case_policy_set_del_t test_case = cases[0];

	assert_empty_state();
	std::cout << "=============start from empty state==============="
		  << std::endl;

	int ret = policy_utils.add_policy_into_srte_table(
		test_case.initial_state);
	EXPECT_EQ(ret, 0);

	std::cout << "=============adding routes===============" << std::endl;
	// compute routes needed to initialize nhgs state
	std::vector<struct api_route_t> routes =
		NHGUtils::gen_route_for_nhgs(test_case.initial_state.nhgs);
	for (const auto &route : routes) {
		print_api_route(route);
	}

	// add routes
	zebra_vrf *zvrf = policy_utils.get_mock_zvrf();
	zserv *client = policy_utils.get_mock_client();
	for (const auto &route : routes) {
		struct zapi_route api_route =
			common_utils::get_zapi_route_from_t(route);
		struct stream *s = common_utils::fill_stream_with_route(&api_route);
		EXPECT_NE(s, nullptr);

		zread_route_add(policy_utils.get_mock_client(), NULL, s, policy_utils.get_mock_zvrf());
		std::cout << "zread_route_add issued" << std::endl;
	}

	std::cout << "===========check test result: initial state============="
		  << std::endl;
	EXPECT_TRUE(dump_and_check_state(test_case.initial_state));
}


/*
 * One route resolves to two policies
 * */
TEST_F(ZebraNhgsExample, MultiPolicySingleRoute)
{
	std::vector<test_case_policy_set_del_t> cases =
		read_all_test_cases_policy_set_del(
			"resources/zebra_nhgs_example/multi_policy_route.json");
	test_case_policy_set_del_t test_case = cases[0];

	assert_empty_state();
	std::cout << "=============start from empty state==============="
		  << std::endl;

	int ret = policy_utils.add_policy_into_srte_table(
		test_case.initial_state);
	EXPECT_EQ(ret, 0);

	std::cout << "=============adding routes===============" << std::endl;
	std::vector<struct api_route_t> routes =
		NHGUtils::gen_route_for_nhgs(test_case.initial_state.nhgs);
	for (const auto &route : routes) {
		print_api_route(route);
	}

	// add routes
	zebra_vrf *zvrf = policy_utils.get_mock_zvrf();
	zserv *client = policy_utils.get_mock_client();
	for (const auto &route : routes) {
		struct zapi_route api_route =
			common_utils::get_zapi_route_from_t(route);
		struct stream *s = common_utils::fill_stream_with_route(&api_route);
		EXPECT_NE(s, nullptr);

		zread_route_add(policy_utils.get_mock_client(), NULL, s, policy_utils.get_mock_zvrf());
		std::cout << "zread_route_add issued" << std::endl;
	}

	std::cout << "===========check test result: initial state============="
		  << std::endl;
	EXPECT_TRUE(dump_and_check_state(test_case.initial_state));
}


/*
 * Two routes resolve to three policies
 * */
TEST_F(ZebraNhgsExample, MultiPolicyMultiRoute)
{
	std::vector<test_case_policy_set_del_t> cases =
		read_all_test_cases_policy_set_del(
			"resources/zebra_nhgs_example/multi_policy_multi_route.json");
	test_case_policy_set_del_t test_case = cases[0];

	assert_empty_state();
	std::cout << "=============start from empty state==============="
		  << std::endl;

	int ret = policy_utils.add_policy_into_srte_table(
		test_case.initial_state);
	EXPECT_EQ(ret, 0);

	std::cout << "=============adding routes===============" << std::endl;
	std::vector<struct api_route_t> routes =
		NHGUtils::gen_route_for_nhgs(test_case.initial_state.nhgs);
	for (const auto &route : routes) {
		print_api_route(route);
	}

	// add routes
	zebra_vrf *zvrf = policy_utils.get_mock_zvrf();
	zserv *client = policy_utils.get_mock_client();
	for (const auto &route : routes) {
		struct zapi_route api_route =
			common_utils::get_zapi_route_from_t(route);
		struct stream *s = common_utils::fill_stream_with_route(&api_route);
		EXPECT_NE(s, nullptr);

		zread_route_add(policy_utils.get_mock_client(), NULL, s, policy_utils.get_mock_zvrf());
		std::cout << "zread_route_add issued" << std::endl;
	}

	std::cout << "===========check test result: initial state============="
		  << std::endl;
	EXPECT_TRUE(dump_and_check_state(test_case.initial_state));
}


/*
 * Route 10 resolves to policies 2 and 3
 * Route 20 resolves to policy 4
 * */
TEST_F(ZebraNhgsExample, MultiPolicyHybridRoute)
{
	std::vector<test_case_policy_set_del_t> cases =
		read_all_test_cases_policy_set_del(
			"resources/zebra_nhgs_example/multi_policy_multi_route.json");
	test_case_policy_set_del_t test_case = cases[1];

	assert_empty_state();
	std::cout << "=============start from empty state==============="
		  << std::endl;

	int ret = policy_utils.add_policy_into_srte_table(
		test_case.initial_state);
	EXPECT_EQ(ret, 0);

	std::cout << "=============adding routes===============" << std::endl;
	std::vector<struct api_route_t> routes =
		NHGUtils::gen_route_for_nhgs(test_case.initial_state.nhgs);
	for (const auto &route : routes) {
		print_api_route(route);
	}

	// add routes
	zebra_vrf *zvrf = policy_utils.get_mock_zvrf();
	zserv *client = policy_utils.get_mock_client();
	for (const auto &route : routes) {
		struct zapi_route api_route =
			common_utils::get_zapi_route_from_t(route);
		struct stream *s = common_utils::fill_stream_with_route(&api_route);
		EXPECT_NE(s, nullptr);

		zread_route_add(policy_utils.get_mock_client(), NULL, s, policy_utils.get_mock_zvrf());
		std::cout << "zread_route_add issued" << std::endl;
	}

	std::cout << "===========check test result: initial state============="
		  << std::endl;
	EXPECT_TRUE(dump_and_check_state(test_case.initial_state));
}


/*
 * WIP: Issues with identical sidlists, pending feedback -- Thu, Feb 13
 * */

TEST_F(ZebraNhgsExample, AddSameSidlistOnce)
{
	std::vector<test_case_policy_set_del_t> cases =
		read_all_test_cases_policy_set_del(
			"resources/zebra_nhgs_example/identical_sidlist_update.json");
	test_case_policy_set_del_t test_case = cases[0];

	assert_empty_state();
	std::cout << "=============start from empty state==============="
		  << std::endl;

	std::cout << "============put in test data============" << std::endl;
	zebra_vrf *zvrf = policy_utils.get_mock_zvrf();
	zserv *client = policy_utils.get_mock_client();

	struct zapi_sr_policy zp;
	int ret = policy_utils.get_input_policy_from_case_api_policy_t(
		&zp, &(test_case.input_policy));
	EXPECT_EQ(ret, 0);

	struct stream *s = policy_utils.fill_stream_with_policy(&zp);
	EXPECT_NE(s, nullptr);
	zread_srv6_policy_set(NULL, NULL, s, zvrf);

	std::cout << "=============adding routes===============" << std::endl;
	std::vector<struct api_route_t> routes =
		NHGUtils::gen_route_for_nhgs(test_case.final_state.nhgs);
	for (const auto &route : routes) {
		print_api_route(route);
	}

	// add routes
	for (const auto &route : routes) {
		struct zapi_route api_route =
			common_utils::get_zapi_route_from_t(route);
		struct stream *s = common_utils::fill_stream_with_route(&api_route);
		EXPECT_NE(s, nullptr);

		zread_route_add(policy_utils.get_mock_client(), NULL, s, policy_utils.get_mock_zvrf());
		std::cout << "zread_route_add issued" << std::endl;
	}

	std::cout << "===========check test result=============" << std::endl;
	EXPECT_TRUE(dump_and_check_state(test_case.final_state));
}


TEST_F(ZebraNhgsExample, AddOneSameSidlist)
{
	GTEST_SKIP() << "Issue acknowledged, pending review";
	std::vector<test_case_policy_set_del_t> cases =
		read_all_test_cases_policy_set_del(
			"resources/zebra_nhgs_example/identical_sidlist_update.json");
	test_case_policy_set_del_t test_case = cases[1];

	assert_empty_state();
	std::cout << "=============start from empty state==============="
		  << std::endl;

	int ret = policy_utils.add_policy_into_srte_table(
		test_case.initial_state);
	EXPECT_EQ(ret, 0);

	std::cout << "=============adding routes===============" << std::endl;
	std::vector<struct api_route_t> routes =
		NHGUtils::gen_route_for_nhgs(test_case.initial_state.nhgs);
	for (const auto &route : routes) {
		print_api_route(route);
	}

	// add routes
	zebra_vrf *zvrf = policy_utils.get_mock_zvrf();
	zserv *client = policy_utils.get_mock_client();
	for (const auto &route : routes) {
		struct zapi_route api_route =
			common_utils::get_zapi_route_from_t(route);
		struct stream *s = common_utils::fill_stream_with_route(&api_route);
		EXPECT_NE(s, nullptr);

		zread_route_add(policy_utils.get_mock_client(), NULL, s, policy_utils.get_mock_zvrf());
		std::cout << "zread_route_add issued" << std::endl;
	}

	std::cout << "===========validate initial state============="
		  << std::endl;
	EXPECT_TRUE(dump_and_check_state(test_case.initial_state));

	std::cout << "============put in test data============" << std::endl;
	struct zapi_sr_policy zp;
	ret = policy_utils.get_input_policy_from_case_api_policy_t(
		&zp, &(test_case.input_policy));
	EXPECT_EQ(ret, 0);

	struct stream *s = policy_utils.fill_stream_with_policy(&zp);
	EXPECT_NE(s, nullptr);
	zread_srv6_policy_set(NULL, NULL, s, zvrf);

	std::cout << "===========check test result=============" << std::endl;
	EXPECT_TRUE(dump_and_check_state(test_case.final_state));
}


TEST_F(ZebraNhgsExample, DelOneSameSidlist)
{
	GTEST_SKIP() << "Issue acknowledged, pending review";
	std::vector<test_case_policy_set_del_t> cases =
		read_all_test_cases_policy_set_del(
			"resources/zebra_nhgs_example/identical_sidlist_update.json");
	test_case_policy_set_del_t test_case = cases[2];

	assert_empty_state();
	std::cout << "=============start from empty state==============="
		  << std::endl;

	int ret = policy_utils.add_policy_into_srte_table(
		test_case.initial_state);
	EXPECT_EQ(ret, 0);

	std::cout << "=============adding routes===============" << std::endl;
	std::vector<struct api_route_t> routes =
		NHGUtils::gen_route_for_nhgs(test_case.initial_state.nhgs);
	for (const auto &route : routes) {
		print_api_route(route);
	}

	// add routes
	zebra_vrf *zvrf = policy_utils.get_mock_zvrf();
	zserv *client = policy_utils.get_mock_client();
	for (const auto &route : routes) {
		struct zapi_route api_route =
			common_utils::get_zapi_route_from_t(route);
		struct stream *s = common_utils::fill_stream_with_route(&api_route);
		EXPECT_NE(s, nullptr);

		zread_route_add(policy_utils.get_mock_client(), NULL, s, policy_utils.get_mock_zvrf());
		std::cout << "zread_route_add issued" << std::endl;
	}

	std::cout << "===========validate initial state============="
		  << std::endl;
	EXPECT_TRUE(dump_and_check_state(test_case.initial_state));

	std::cout << "============put in test data============" << std::endl;
	struct zapi_sr_policy zp;
	ret = policy_utils.get_input_policy_from_case_api_policy_t(
		&zp, &(test_case.input_policy));
	EXPECT_EQ(ret, 0);

	struct stream *s = policy_utils.fill_stream_with_policy(&zp);
	EXPECT_NE(s, nullptr);
	zread_srv6_policy_set(NULL, NULL, s, zvrf);

	std::cout << "===========check test result=============" << std::endl;
	EXPECT_TRUE(dump_and_check_state(test_case.final_state));
}


/*
 * Route 10 resolves to policies 2 and 3
 * Route 20 resolves to policy 4
 * Add: Route 30 resolves to policy 3 and 4
 * */
TEST_F(ZebraNhgsExample, MultiPolicyHybridRouteAddRoute)
{
	std::vector<test_case_route_add_t> cases =
		read_all_test_cases_route_add(
			"resources/zebra_nhgs_example/route_add.json");
	test_case_route_add_t test_case = cases[0];

	assert_empty_state();
	std::cout << "=============start from empty state==============="
		  << std::endl;

	int ret = policy_utils.add_policy_into_srte_table(
		test_case.initial_state);

	EXPECT_EQ(ret, 0);

	std::cout << "===========check test result: initial state============="
		  << std::endl;
	EXPECT_TRUE(dump_and_check_state(test_case.initial_state));

	std::cout << "=============adding routes===============" << std::endl;
	// std::vector<struct api_route_t> routes =
	//  	NHGUtils::gen_route_for_nhgs(test_case.initial_state.nhgs);

	// add routes
	zebra_vrf *zvrf = policy_utils.get_mock_zvrf();
	zserv *client = policy_utils.get_mock_client();
	for (const auto &route : test_case.initial_state.route_nhg_map) {
		struct zapi_route api_route =
			common_utils::get_route_multi_policies(route);
		struct stream *s = common_utils::fill_stream_with_route(&api_route);
		EXPECT_NE(s, nullptr);

		zread_route_add(policy_utils.get_mock_client(), NULL, s, policy_utils.get_mock_zvrf());
		std::cout << "zread_route_add issued" << std::endl;
	}


	std::cout << "============put in test data============" << std::endl;

	// add route

	struct zapi_route api_route =
		common_utils::get_route_multi_policies(test_case.input_route);
	struct stream *s = common_utils::fill_stream_with_route(&api_route);
	EXPECT_NE(s, nullptr);

	zread_route_add(policy_utils.get_mock_client(), NULL, s, policy_utils.get_mock_zvrf());
	std::cout << "zread_route_add issued" << std::endl;

	std::cout << "===========check test result=============" << std::endl;
	EXPECT_TRUE(dump_and_check_state(test_case.final_state));
}


int main(int argc, char **argv)
{
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}