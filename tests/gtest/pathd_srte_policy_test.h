#ifndef GTEST_PATHD_PATHD_SRTE_POLICY_TEST_H
#define GTEST_PATHD_PATHD_SRTE_POLICY_TEST_H

#include <gtest/gtest.h>
#include "test_model.h"


class PathdSrtePolicyTest
    : public ::testing::TestWithParam<test_case_srte_policy_t>
{
      protected:
	void SetUp() override;
	void TearDown() override;
};


#endif // GTEST_PATHD_PATHD_SRTE_POLICY_TEST_H
