#ifndef GTEST_ALIBGP_TEST_ZREAD_RNH_REGISTER_H
#define GTEST_ALIBGP_TEST_ZREAD_RNH_REGISTER_H

#include <gtest/gtest.h>
#include "zebra/zebra_srte.h"

#include "test_model.h"
#include "zebra_utils.h"


class ZreadRnhRegisterTest
    : public ::testing::TestWithParam<test_case_rnh_register>
{
      protected:
	void SetUp() override
	{
		setup_env();
	}

	void TearDown() override
	{
		teardown_env();
	}

	static void SetUpTestSuite()
	{
		setup_global_env();
	}
};

#endif // GTEST_ALIBGP_TEST_ZREAD_RNH_REGISTER_H
