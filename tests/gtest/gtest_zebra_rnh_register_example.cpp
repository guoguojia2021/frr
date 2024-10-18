#include <gtest/gtest.h>
#include <iostream>

#include "lib/hash.h"
#include "lib/nexthop.h"
#include "libfrr.h"

#include "zebra.h"
#include "zebra/debug.h"
#include "zebra/router-id.h"
#include "zebra/table_manager.h"
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
#include "zebra_utils.h"


class ZebraRnhRegisterExample : public ::testing::Test
{
      protected:
	void SetUp() override
	{
		setup_env();
	}

	void TearDown() override
	{
		teardown_env();
	}

	static void SetUpTestSuite()
	{
		zebra_srte_init();
	}
};


TEST_F(ZebraRnhRegisterExample, RegisterExistingPolicy)
{
	std::map<int, test_case_rnh_register> cases =
		read_all_test_cases_nexthop_register(
			"resources/zebra_rnh_examples/register_existing.json");
	test_case_rnh_register test_case = cases[0];

	zebra_vrf *zvrf = policy_utils.get_mock_zvrf();
	zserv *client = policy_utils.get_mock_client();
	setup_zebra_state(test_case.initial_state, zvrf, client);

	std::cout << "============put in test data============" << std::endl;
	struct prefix p;
	int ret =
		common_utils::prefix_t2prefix(&test_case.input_rnh.prefix, &p);
	EXPECT_EQ(ret, 0);


	struct stream *s = RnhUtils::fill_stream_with_rnh(
		ZEBRA_NEXTHOP_REGISTER, &p, test_case.input_rnh.srte_color);
	EXPECT_NE(s, nullptr);
	struct zmsghdr hdr;
	zapi_parse_header(s, &hdr);
	zread_rnh_register(policy_utils.get_mock_client(), &hdr, s,
			   policy_utils.get_mock_zvrf());

	std::cout << "===========check test result=============" << std::endl;
	EXPECT_TRUE(dump_and_check_state(test_case.final_state));
}


/*
 * Add a new rnh to the head of the existing rnh_vec
 * */
TEST_F(ZebraRnhRegisterExample, RegisterTwoNexthops)
{
	std::map<int, test_case_rnh_register> cases =
		read_all_test_cases_nexthop_register(
			"resources/zebra_rnh_examples/register_existing.json");
	test_case_rnh_register test_case = cases[10];

	zebra_vrf *zvrf = policy_utils.get_mock_zvrf();
	zserv *client = policy_utils.get_mock_client();
	setup_zebra_state(test_case.initial_state, zvrf, client);

	std::cout << "============put in test data============" << std::endl;
	struct prefix p;
	int ret =
		common_utils::prefix_t2prefix(&test_case.input_rnh.prefix, &p);
	EXPECT_EQ(ret, 0);


	struct stream *s = RnhUtils::fill_stream_with_rnh(
		ZEBRA_NEXTHOP_REGISTER, &p, test_case.input_rnh.srte_color);
	EXPECT_NE(s, nullptr);
	struct zmsghdr hdr;
	zapi_parse_header(s, &hdr);
	zread_rnh_register(policy_utils.get_mock_client(), &hdr, s,
			   policy_utils.get_mock_zvrf());

	std::cout << "===========check test result=============" << std::endl;
	EXPECT_TRUE(dump_and_check_state(test_case.final_state));
}


/*
 * Add an already-registered rnh, no change to zebra state
 * */
TEST_F(ZebraRnhRegisterExample, RegisterOverride)
{
	std::map<int, test_case_rnh_register> cases =
		read_all_test_cases_nexthop_register(
			"resources/zebra_rnh_examples/register_existing.json");
	test_case_rnh_register test_case = cases[20];

	zebra_vrf *zvrf = policy_utils.get_mock_zvrf();
	zserv *client = policy_utils.get_mock_client();
	setup_zebra_state(test_case.initial_state, zvrf, client);

	std::cout << "============put in test data============" << std::endl;
	struct prefix p;
	int ret =
		common_utils::prefix_t2prefix(&test_case.input_rnh.prefix, &p);
	EXPECT_EQ(ret, 0);


	struct stream *s = RnhUtils::fill_stream_with_rnh(
		ZEBRA_NEXTHOP_REGISTER, &p, test_case.input_rnh.srte_color);
	EXPECT_NE(s, nullptr);
	struct zmsghdr hdr;
	zapi_parse_header(s, &hdr);
	zread_rnh_register(policy_utils.get_mock_client(), &hdr, s,
			   policy_utils.get_mock_zvrf());

	std::cout << "===========check test result=============" << std::endl;
	EXPECT_TRUE(dump_and_check_state(test_case.final_state));
}


/*
 * Add a non-existent rnh, results in some intermediate changes.
 * Add a corresponding policy, final states include the complete rnh setup.
 * */
TEST_F(ZebraRnhRegisterExample, RegisterNX)
{
	std::map<int, test_case_rnh_register> cases =
		read_all_test_cases_nexthop_register(
			"resources/zebra_rnh_examples/register_nx.json");
	test_case_rnh_register test_case = cases[0];

	zebra_vrf *zvrf = policy_utils.get_mock_zvrf();
	zserv *client = policy_utils.get_mock_client();
	setup_zebra_state(test_case.initial_state, zvrf, client);

	std::cout << "============put in test data============" << std::endl;
	struct prefix p;
	int ret =
		common_utils::prefix_t2prefix(&test_case.input_rnh.prefix, &p);
	EXPECT_EQ(ret, 0);

	struct stream *s;
	s = RnhUtils::fill_stream_with_rnh(ZEBRA_NEXTHOP_REGISTER, &p,
					   test_case.input_rnh.srte_color);
	EXPECT_NE(s, nullptr);
	struct zmsghdr hdr;
	zapi_parse_header(s, &hdr);
	zread_rnh_register(policy_utils.get_mock_client(), &hdr, s,
			   policy_utils.get_mock_zvrf());

	std::cout << "===========check test result=============" << std::endl;
	bool intermediate = dump_and_check_state(test_case.final_state);
	// EXPECT_TRUE(intermediate);

	std::cout << "===========read in policy data=============" << std::endl;
	std::vector<test_case_policy_set_del_t> policies =
		read_all_test_cases_policy_set_del(
			"resources/zebra_rnh_examples/register_nx_policy.json");
	struct zapi_sr_policy zp;
	ret = policy_utils.get_input_policy_from_case_api_policy_t(
		&zp, &(policies[0].input_policy));
	EXPECT_EQ(ret, 0);
	s = policy_utils.fill_stream_with_policy(&zp);
	EXPECT_NE(s, nullptr);

	std::cout << "===========policy set=============" << std::endl;
	zread_srv6_policy_set(NULL, NULL, s, zvrf);

	std::cout << "===========check test result=============" << std::endl;
	EXPECT_TRUE(dump_and_check_state(test_case.final_state));
}


/*
 * Registered rnh resolve to an UP color-only policy
 * */
TEST_F(ZebraRnhRegisterExample, UpColorOnly)
{
	std::map<int, test_case_rnh_register> cases =
		read_all_test_cases_nexthop_register(
			"resources/zebra_rnh_examples/register_color_only.json");
	test_case_rnh_register test_case = cases[300];

	zebra_vrf *zvrf = policy_utils.get_mock_zvrf();
	zserv *client = policy_utils.get_mock_client();
	setup_zebra_state(test_case.initial_state, zvrf, client);

	std::cout << "============put in test data============" << std::endl;
	struct prefix p;
	int ret =
		common_utils::prefix_t2prefix(&test_case.input_rnh.prefix, &p);
	EXPECT_EQ(ret, 0);


	struct stream *s = RnhUtils::fill_stream_with_rnh(
		ZEBRA_NEXTHOP_REGISTER, &p, test_case.input_rnh.srte_color);
	EXPECT_NE(s, nullptr);
	struct zmsghdr hdr;
	zapi_parse_header(s, &hdr);
	zread_rnh_register(policy_utils.get_mock_client(), &hdr, s,
			   policy_utils.get_mock_zvrf());

	std::cout << "===========check test result=============" << std::endl;
	EXPECT_TRUE(dump_and_check_state(test_case.final_state));
}


/*
 * Registered rnh resolves to an INIT color-only policy
 * */
TEST_F(ZebraRnhRegisterExample, InitColorOnly)
{
	std::map<int, test_case_rnh_register> cases =
		read_all_test_cases_nexthop_register(
			"resources/zebra_rnh_examples/register_color_only.json");
	test_case_rnh_register test_case = cases[301];

	zebra_vrf *zvrf = policy_utils.get_mock_zvrf();
	zserv *client = policy_utils.get_mock_client();
	setup_zebra_state(test_case.initial_state, zvrf, client);

	std::cout << "============put in test data============" << std::endl;
	struct prefix p;
	int ret =
		common_utils::prefix_t2prefix(&test_case.input_rnh.prefix, &p);
	EXPECT_EQ(ret, 0);


	struct stream *s = RnhUtils::fill_stream_with_rnh(
		ZEBRA_NEXTHOP_REGISTER, &p, test_case.input_rnh.srte_color);
	EXPECT_NE(s, nullptr);
	struct zmsghdr hdr;
	zapi_parse_header(s, &hdr);
	zread_rnh_register(policy_utils.get_mock_client(), &hdr, s,
			   policy_utils.get_mock_zvrf());

	std::cout << "===========check test result=============" << std::endl;
	EXPECT_TRUE(dump_and_check_state(test_case.final_state));
}


/*
 * Register rnh to an empty state
 * */
TEST_F(ZebraRnhRegisterExample, Empty)
{
	std::map<int, test_case_rnh_register> cases =
		read_all_test_cases_nexthop_register(
			"resources/zebra_rnh_examples/register_color_only.json");
	test_case_rnh_register test_case = cases[302];

	zebra_vrf *zvrf = policy_utils.get_mock_zvrf();
	zserv *client = policy_utils.get_mock_client();
	setup_zebra_state(test_case.initial_state, zvrf, client);

	std::cout << "============put in test data============" << std::endl;
	struct prefix p;
	int ret =
		common_utils::prefix_t2prefix(&test_case.input_rnh.prefix, &p);
	EXPECT_EQ(ret, 0);

	struct stream *s;
	s = RnhUtils::fill_stream_with_rnh(ZEBRA_NEXTHOP_REGISTER, &p,
					   test_case.input_rnh.srte_color);
	EXPECT_NE(s, nullptr);
	struct zmsghdr hdr;
	zapi_parse_header(s, &hdr);
	zread_rnh_register(policy_utils.get_mock_client(), &hdr, s,
			   policy_utils.get_mock_zvrf());

	std::cout << "===========check step 1 result=============" << std::endl;
	dump_and_check_state(test_case.final_state);

	std::cout << "===========read in policy data=============" << std::endl;
	std::vector<test_case_policy_set_del_t> policies =
		read_all_test_cases_policy_set_del(
			"resources/zebra_rnh_examples/register_nx_policy.json");
	struct zapi_sr_policy zp;
	ret = policy_utils.get_input_policy_from_case_api_policy_t(
		&zp, &(policies[1].input_policy));
	EXPECT_EQ(ret, 0);
	s = policy_utils.fill_stream_with_policy(&zp);
	EXPECT_NE(s, nullptr);

	std::cout << "===========policy set=============" << std::endl;
	zread_srv6_policy_set(NULL, NULL, s, zvrf);

	std::cout << "===========check test result=============" << std::endl;
	EXPECT_TRUE(dump_and_check_state(test_case.final_state));
}


/*
 * Examples: whether existing rnhs affect policy's deletion
 * */
TEST_F(ZebraRnhRegisterExample, SetThenDel)
{
	std::map<int, multi_test_case_t> cases = read_multi_test_cases_map(
		"resources/zebra_rnh_examples/set_then_del.json");
	multi_test_case_t test_case = cases[0];

	zebra_vrf *zvrf = policy_utils.get_mock_zvrf();
	zserv *client = policy_utils.get_mock_client();
	setup_zebra_state(test_case.initial_state, zvrf, client);

	for (int i = 0; i < test_case.input_actions.size(); i++) {
		std::cout << "============ Step " << i
			  << "============" << std::endl;
		perform_action(test_case.input_actions[i], client, zvrf);
	}

	std::cout << "===========check test result=============" << std::endl;
	EXPECT_TRUE(dump_and_check_state(test_case.final_state));
}

TEST_F(ZebraRnhRegisterExample, SetThenDel2)
{
	std::map<int, multi_test_case_t> cases = read_multi_test_cases_map(
		"resources/zebra_rnh_examples/set_then_del.json");
	multi_test_case_t test_case = cases[1];

	zebra_vrf *zvrf = policy_utils.get_mock_zvrf();
	zserv *client = policy_utils.get_mock_client();
	setup_zebra_state(test_case.initial_state, zvrf, client);

	for (int i = 0; i < test_case.input_actions.size(); i++) {
		std::cout << "============ Step " << i
			  << "============" << std::endl;
		perform_action(test_case.input_actions[i], client, zvrf);

		if (i == 0 || i == 1) {
			print_state();
		}
	}

	std::cout << "===========check test result=============" << std::endl;
	EXPECT_TRUE(dump_and_check_state(test_case.final_state));
}


int main(int argc, char **argv)
{
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
