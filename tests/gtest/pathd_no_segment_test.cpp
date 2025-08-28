#include "pathd_no_segment_test.h"

#include <gtest/gtest.h>
#include "pathd_utils.h"
#include "test_model.h"


void PathdNoSegmentTest::SetUp()
{
	pathd_setup_env();
}

void PathdNoSegmentTest::TearDown()
{
	pathd_teardown_env();
}

TEST_P(PathdNoSegmentTest, SegmentListSegmentDestroy)
{
	struct test_case_segment_list_no_segment_t test_case = GetParam();
	GTEST_LOG_(INFO) << "Test case #" << test_case.test_id;
	int ret = 0;

	// initial state setup
	EXPECT_EQ(setup_pathd_state(test_case.initial_state), 0);

	std::cout << "Initial state: " << std::endl;
	wrapper_show();

	// Call API
	struct api_segment_list_no_segment_t &arg = test_case.input_segment;
	GTEST_LOG_(INFO) << "Calling api_segment_list_no_segment: name "
			 << arg.name << ", index " << arg.index;
	// May return error due to validation failures, which is expected
	// behavior
	ret = api_segment_list_no_segment(arg.name, arg.index);

	std::cout << "Final state: " << std::endl;
	wrapper_show();

	// Check final state
	GTEST_LOG_(INFO) << "Checking final state";
	EXPECT_TRUE(compare_dumped_pathd_state(test_case.final_state));
}


INSTANTIATE_TEST_SUITE_P(
	PathdNoSegmentTestSuite, PathdNoSegmentTest,
	::testing::ValuesIn(read_all_tests_no_segment(
		"resources/formatted_segmentlist_no_segment.json")));
