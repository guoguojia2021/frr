//
// Created by mengqi.liu on 5/23/25.
//

#include <iostream>
#include <gtest/gtest.h>

#include "pathd/pathd.h"

#include "pathd_utils.h"
#include "pathd_segment_list_test.h"
#include "pathd_segment_test.h"
#include "pathd_no_segment_list_test.h"
#include "pathd_no_segment_test.h"
#include "pathd_srte_policy_test.h"
#include "pathd_srte_no_policy_test.h"
#include "pathd_srte_policy_candidatepath_test.h"
#include "pathd_srte_policy_no_candidatepath_test.h"


/*
 * A simple dummy test to verify the test framework is working.
 *
 * segment-list abc
 *   index 10 ipv6-address 1000::178
 * exit
 * policy color 100 endpoint ::
 *   candidate-path preference 1 name a explicit segment-list abc weight 1
 * */
TEST(PathdTest, SegmentListEnter)
{
	pathd_setup_env();
	api_segment_list("abc");
	api_segment_list_segment("abc", 10, "1000::178");
	api_segment_list_segment("abc", 20, "2000::178");

	api_segment_list("b");
	api_segment_list_segment("b", 30, "3000::178");
	api_segment_list_segment("b", 20, "4000::178");

	api_segment_list("c");
	api_segment_list_segment("c", 10, "3000::178");

	api_srte_policy(1, "::");
	struct PolicyCandidatePathParams param = {
		1,	  // color
		"::",	  // endpoint
		1,	  // preference
		"path_a", // path_name
		"abc",	  // segment_list_name
		1	  // weight
	};
	int result = api_srte_policy_candidate_path(1,	      // color
						    "::",     // endpoint
						    1,	      // preference
						    "path_a", // path_name
						    "abc" // segment_list_name
	);

	struct PolicyCandidatePathParams param2 = {
		1,	  // color
		"::",	  // endpoint
		2,	  // preference
		"path_b", // path_name
		"b",	  // segment_list_name
		1	  // weight
	};
	result = api_srte_policy_candidate_path(1,	  // color
						"::",	  // endpoint
						2,	  // preference
						"path_b", // path_name
						"b"	  // segment_list_name
	);

	struct PolicyCandidatePathParams param3 = {
		1,	  // color
		"::",	  // endpoint
		3,	  // preference
		"path_c", // path_name
		"c",	  // segment_list_name
		1	  // weight
	};
	result = api_srte_policy_candidate_path(1,	  // color
						"::",	  // endpoint
						3,	  // preference
						"path_c", // path_name
						"c"	  // segment_list_name
	);

	EXPECT_EQ(1, 1); // This test will always pass
	pathd_teardown_env();
}


/*
 * When a new config fails the validation test, pathd's state does not change
 * */
TEST(PathdTest, ValidationError)
{
	pathd_setup_env();
	api_segment_list("abc");
	api_segment_list_segment("abc", 10, "1000::178");

	api_srte_policy(1, "::");
	struct PolicyCandidatePathParams param = {
		1,	  // color
		"::",	  // endpoint
		1,	  // preference
		"path_a", // path_name
		"abc",	  // segment_list_name
		1	  // weight
	};
	int ret = api_srte_policy_candidate_path(1,	   // color
						 "::",	   // endpoint
						 1,	   // preference
						 "path_a", // path_name
						 "abc"	   // segment_list_name
	);

	std::cout << "Initial setup complete" << std::endl;
	struct pathd_state_t s = dump_pathd_state();
	wrapper_show();

	api_segment_list("abc");
	ret = api_segment_list_segment("abc", 20, "1000::178");
	EXPECT_NE(ret, 0)
		<< "Should report error when adding to an in-use segment_list"
		<< std::endl;

	std::cout << "After segment add attempt" << std::endl;
	wrapper_show();
	EXPECT_TRUE(compare_dumped_pathd_state(s));

	// OK to update existing index
	ret = api_segment_list_segment("abc", 10, "2000::178");
	s.segment_lists.front().segments.front().v6Address = "2000::178";
	wrapper_show();
	EXPECT_TRUE(compare_dumped_pathd_state(s));

	pathd_teardown_env();
}
