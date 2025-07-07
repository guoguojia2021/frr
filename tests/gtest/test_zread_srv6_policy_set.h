#ifndef TEST_ZREAD_SRV6_POLICY_SET_H
#define TEST_ZREAD_SRV6_POLICY_SET_H


#include <gtest/gtest.h>

#include "zebra/zebra_srte.h"

#include "test_model.h"
#include "zebra_utils.h"


class ZreadSrv6PolicySetTest
    : public ::testing::TestWithParam<test_case_policy_set_del_t>
{
      protected:
	void SetUp() override;
	void TearDown() override;
	static void SetUpTestSuite()
	{
		setup_global_env();
	}
};

#endif