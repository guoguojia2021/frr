#include "pathd_segment_list_test.h"

#include <gtest/gtest.h>
#include "pathd_utils.h"
#include "test_model.h"


void PathdSegmentListTest::SetUp()
{
	pathd_setup_env();
}

void PathdSegmentListTest::TearDown()
{
	pathd_teardown_env();
}

TEST_P(PathdSegmentListTest, SegmentListCreate)
{
	struct test_case_segment_list_t test_case = GetParam();
	GTEST_LOG_(INFO) << "Test case #" << test_case.test_id;
	int ret = 0;

	// initial state setup
	EXPECT_EQ(setup_pathd_state(test_case.initial_state), 0);

	std::cout << "Initial state: " << std::endl;
	wrapper_show();

	// Call API
	GTEST_LOG_(INFO) << "Calling api_segment_list name "
			 << test_case.input_segment_list.name;
	ret = api_segment_list(test_case.input_segment_list.name);
	EXPECT_EQ(ret, 0);

	std::cout << "Final state: " << std::endl;
	wrapper_show();

	// Check final state
	GTEST_LOG_(INFO) << "Checking final state";
	EXPECT_TRUE(compare_dumped_pathd_state(test_case.final_state));
}


INSTANTIATE_TEST_SUITE_P(PathdSegmentListTestSuite, PathdSegmentListTest,
			 ::testing::ValuesIn(read_all_tests_segment_list(
				 "resources/formatted_segmentlist.json")));