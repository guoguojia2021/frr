#ifndef GTEST_PATHD_PATHD_SRTE_POLICY_NO_CANDIDATE_PATH_TEST_H
#define GTEST_PATHD_PATHD_SRTE_POLICY_NO_CANDIDATE_PATH_TEST_H

#include <gtest/gtest.h>
#include "test_model.h"


class PathdSrtePolicyNoCandidatePathTest
    : public ::testing::TestWithParam<test_case_srte_policy_no_candidate_path_t>
{
      protected:
	void SetUp() override;
	void TearDown() override;
};


#endif // GTEST_PATHD_PATHD_SRTE_POLICY_NO_CANDIDATE_PATH_TEST_H
