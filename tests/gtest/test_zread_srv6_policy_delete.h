#ifndef TEST_ZRAED_SRV6_POLICY_DELETE_H
#define TEST_ZRAED_SRV6_POLICY_DELETE_H

#include <gtest/gtest.h>

#include "zebra/zebra_srte.h"

#include "test_model.h"
#include "zebra_utils.h"


class ZreadSrv6PolicyDeleteTest
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
