#include "pathd_srte_no_policy_test.h"

#include <gtest/gtest.h>
#include "pathd_utils.h"
#include "test_model.h"


void PathdSrteNoPolicyTest::SetUp()
{
	pathd_setup_env();
}

void PathdSrteNoPolicyTest::TearDown()
{
	pathd_teardown_env();
}

TEST_P(PathdSrteNoPolicyTest, SrtePolicyDestroy)
{
	struct test_case_srte_no_policy_t test_case = GetParam();
	GTEST_LOG_(INFO) << "Test case #" << test_case.test_id;
	int ret = 0;

	// initial state setup
	EXPECT_EQ(setup_pathd_state(test_case.initial_state), 0);

	std::cout << "Initial state: " << std::endl;
	wrapper_show();

	// Call API
	GTEST_LOG_(INFO) << "Calling api_srte_no_policy color "
			 << test_case.input_policy.color << ", endpoint "
			 << test_case.input_policy.endpoint;
	ret = api_srte_no_policy(test_case.input_policy.color,
				 test_case.input_policy.endpoint);
	EXPECT_EQ(ret, 0);

	std::cout << "Final state: " << std::endl;
	wrapper_show();

	// Check final state
	GTEST_LOG_(INFO) << "Checking final state";
	EXPECT_TRUE(compare_dumped_pathd_state(test_case.final_state));
}


INSTANTIATE_TEST_SUITE_P(PathdSrteNoPolicyTestSuite, PathdSrteNoPolicyTest,
			 ::testing::ValuesIn(read_all_tests_srte_no_policy(
				 "resources/formatted_srte_no_policy.json")));