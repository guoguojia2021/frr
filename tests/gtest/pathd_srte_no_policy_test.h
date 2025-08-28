#ifndef GTEST_PATHD_PATHD_SRTE_NO_POLICY_TEST_H
#define GTEST_PATHD_PATHD_SRTE_NO_POLICY_TEST_H

#include <gtest/gtest.h>
#include "test_model.h"


class PathdSrteNoPolicyTest
    : public ::testing::TestWithParam<test_case_srte_no_policy_t>
{
      protected:
	void SetUp() override;
	void TearDown() override;
};


#endif // GTEST_PATHD_PATHD_SRTE_NO_POLICY_TEST_H
