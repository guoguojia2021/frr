#include <iostream>
#include <gtest/gtest.h>

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


class SampleMultiStep : public ::testing::Test
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
		setup_global_env();
	}
};

/*
 * #0, policy_del followed by route_del cleans up the associated nhg_entry.
 * */
TEST_F(SampleMultiStep, PolicyDelThenSet)
{
	std::map<int, multi_test_case_t> cases =
		read_multi_test_cases_map("resources/sample_multi_step.json");
	multi_test_case_t test_case = cases[0];

	setup_zebra_state(test_case.initial_state);

	std::cout << "============put in test data============" << std::endl;

	for (int i = 0; i < test_case.input_actions.size(); i++) {
		std::cout << "============ Step " << i
			  << "============" << std::endl;
		perform_action(test_case.input_actions[i]);

		if (i + 1 < test_case.input_actions.size()) {
			std::cout << "============print state============"
				  << std::endl;
			print_state();
		}
	}

	std::cout << "===========check test result=============" << std::endl;
	EXPECT_TRUE(dump_and_check_state(test_case.final_state));
}


/*
 * #10, policy_del, policy_set, route_del, then route_add
 * */
TEST_F(SampleMultiStep, PolicySetThenRouteDel)
{
	std::map<int, multi_test_case_t> cases =
		read_multi_test_cases_map("resources/sample_multi_step.json");
	multi_test_case_t test_case = cases[10];

	setup_zebra_state(test_case.initial_state);

	std::cout << "============put in test data============" << std::endl;

	for (int i = 0; i < test_case.input_actions.size(); i++) {
		std::cout << "============ Step " << i
			  << "============" << std::endl;
		perform_action(test_case.input_actions[i]);

		if (i + 1 < test_case.input_actions.size()) {
			std::cout << "============print state============"
				  << std::endl;
			print_state();
		}
	}

	std::cout << "===========check test result=============" << std::endl;
	EXPECT_TRUE(dump_and_check_state(test_case.final_state));
}


/*
 * #20, policy_del followed by route_del cleans up the associated nhg_entry.
 * There exists color-only policy
 * */
TEST_F(SampleMultiStep, PolicyDelThenSetWithColorOnly)
{
	std::map<int, multi_test_case_t> cases =
		read_multi_test_cases_map("resources/sample_multi_step.json");
	multi_test_case_t test_case = cases[20];

	setup_zebra_state(test_case.initial_state);

	std::cout << "============put in test data============" << std::endl;

	for (int i = 0; i < test_case.input_actions.size(); i++) {
		std::cout << "============ Step " << i
			  << "============" << std::endl;
		perform_action(test_case.input_actions[i]);

		if (i + 1 < test_case.input_actions.size()) {
			std::cout << "============print state============"
				  << std::endl;
			print_state();
		}
	}

	std::cout << "===========check test result=============" << std::endl;
	EXPECT_TRUE(dump_and_check_state(test_case.final_state));
}


/*
 * #30, policy_del, policy_set, route_del, route_add
 * There exsits color-only policy in the system
 * */
TEST_F(SampleMultiStep, PolicySetThenRouteDelWithColorOnly)
{
	std::map<int, multi_test_case_t> cases =
		read_multi_test_cases_map("resources/sample_multi_step.json");
	multi_test_case_t test_case = cases[30];

	setup_zebra_state(test_case.initial_state);

	std::cout << "============put in test data============" << std::endl;

	for (int i = 0; i < test_case.input_actions.size(); i++) {
		std::cout << "============ Step " << i
			  << "============" << std::endl;
		perform_action(test_case.input_actions[i]);

		if (i + 1 < test_case.input_actions.size()) {
			std::cout << "============print state============"
				  << std::endl;
			print_state();
		}
	}

	std::cout << "===========check test result=============" << std::endl;
	EXPECT_TRUE(dump_and_check_state(test_case.final_state));
}


/*
 * #40, policy_del only
 * */
TEST_F(SampleMultiStep, PolicyDel)
{
	std::map<int, multi_test_case_t> cases =
		read_multi_test_cases_map("resources/sample_multi_step.json");
	multi_test_case_t test_case = cases[40];

	setup_zebra_state(test_case.initial_state);

	std::cout << "============put in test data============" << std::endl;

	for (int i = 0; i < test_case.input_actions.size(); i++) {
		std::cout << "============ Step " << i
			  << "============" << std::endl;
		perform_action(test_case.input_actions[i]);
	}

	std::cout << "===========check test result=============" << std::endl;
	EXPECT_TRUE(compare_zebra_state(test_case.final_state));
}


int main(int argc, char **argv)
{
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}