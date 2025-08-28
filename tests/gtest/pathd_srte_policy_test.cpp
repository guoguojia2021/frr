#include "pathd_srte_policy_test.h"

#include <gtest/gtest.h>
#include "pathd_utils.h"
#include "test_model.h"


void PathdSrtePolicyTest::SetUp()
{
	pathd_setup_env();
}

void PathdSrtePolicyTest::TearDown()
{
	pathd_teardown_env();
}

TEST_P(PathdSrtePolicyTest, SrtePolicyCreate)
{
	struct test_case_srte_policy_t test_case = GetParam();
	GTEST_LOG_(INFO) << "Test case #" << test_case.test_id;
	int ret = 0;

	// initial state setup
	EXPECT_EQ(setup_pathd_state(test_case.initial_state), 0);

	std::cout << "Initial state: " << std::endl;
	wrapper_show();

	// Call API
	GTEST_LOG_(INFO) << "Calling api_srte_policy color "
			 << test_case.input_policy.color << ", endpoint "
			 << test_case.input_policy.endpoint;
	ret = api_srte_policy(test_case.input_policy.color,
			      test_case.input_policy.endpoint);
	EXPECT_EQ(ret, 0);

	std::cout << "Final state: " << std::endl;
	wrapper_show();

	// Check final state
	GTEST_LOG_(INFO) << "Checking final state";
	EXPECT_TRUE(compare_dumped_pathd_state(test_case.final_state));
}


INSTANTIATE_TEST_SUITE_P(PathdSrtePolicyTestSuite, PathdSrtePolicyTest,
			 ::testing::ValuesIn(read_all_tests_srte_policy(
				 "resources/formatted_srte_policy.json")));