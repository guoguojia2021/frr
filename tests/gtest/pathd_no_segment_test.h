#ifndef GTEST_PATHD_PATHD_NO_SEGMENT_TEST_H
#define GTEST_PATHD_PATHD_NO_SEGMENT_TEST_H

#include <gtest/gtest.h>
#include "test_model.h"


class PathdNoSegmentTest : public ::testing::TestWithParam<
				   struct test_case_segment_list_no_segment_t>
{
      protected:
	void SetUp() override;
	void TearDown() override;
};


#endif // GTEST_PATHD_PATHD_NO_SEGMENT_TEST_H
