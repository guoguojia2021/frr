#ifndef GTEST_PATHD_PATHD_NO_SEGMENT_LIST_TEST_H
#define GTEST_PATHD_PATHD_NO_SEGMENT_LIST_TEST_H

#include <gtest/gtest.h>
#include "test_model.h"


class PathdNoSegmentListTest
    : public ::testing::TestWithParam<test_case_no_segment_list_t>
{
      protected:
	void SetUp() override;
	void TearDown() override;
};


#endif // GTEST_PATHD_PATHD_NO_SEGMENT_LIST_TEST_H
