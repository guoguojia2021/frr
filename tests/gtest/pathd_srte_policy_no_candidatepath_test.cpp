#include "pathd_srte_policy_no_candidatepath_test.h"

#include <gtest/gtest.h>
#include "pathd_utils.h"
#include "test_model.h"


void PathdSrtePolicyNoCandidatePathTest::SetUp()
{
	pathd_setup_env();
}

void PathdSrtePolicyNoCandidatePathTest::TearDown()
{
	pathd_teardown_env();
}

TEST_P(PathdSrtePolicyNoCandidatePathTest, SrtePolicyCandidatePathDestroy)
{
	struct test_case_srte_policy_no_candidate_path_t test_case = GetParam();
	GTEST_LOG_(INFO) << "Test case #" << test_case.test_id;
	int ret = 0;

	// initial state setup
	EXPECT_EQ(setup_pathd_state(test_case.initial_state), 0);

	std::cout << "Initial state: " << std::endl;
	wrapper_show();

	// Call API
	GTEST_LOG_(INFO) << "Calling api_srte_policy_no_candidate_path color "
			 << test_case.input_candidate_path.color
			 << ", endpoint "
			 << test_case.input_candidate_path.endpoint
			 << ", preference "
			 << test_case.input_candidate_path.preference
			 << ", candidate_name "
			 << test_case.input_candidate_path.candidate_name;
	ret = api_srte_policy_no_candidate_path(
		test_case.input_candidate_path.color,
		test_case.input_candidate_path.endpoint,
		test_case.input_candidate_path.preference,
		test_case.input_candidate_path.candidate_name);
	EXPECT_EQ(ret, 0);

	std::cout << "Final state: " << std::endl;
	wrapper_show();

	// Check final state
	GTEST_LOG_(INFO) << "Checking final state";
	EXPECT_TRUE(compare_dumped_pathd_state(test_case.final_state));
}


INSTANTIATE_TEST_SUITE_P(
	PathdSrtePolicyNoCandidatePathTestSuite,
	PathdSrtePolicyNoCandidatePathTest,
	::testing::ValuesIn(read_all_tests_srte_policy_no_candidate_path(
		"resources/formatted_srte_policy_no_candidatepath.json")));