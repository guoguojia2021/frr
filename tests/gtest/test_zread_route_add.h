#ifndef TEST_ZREAD_ROUTE_ADD_H
#define TEST_ZREAD_ROUTE_ADD_H

#include <gtest/gtest.h>
#include "zebra/zebra_srte.h"

#include "test_model.h"
#include "nhg_utils.h"
#include "zebra_utils.h"


class ZreadRouteAddTest : public ::testing::TestWithParam<test_case_route_add_t>
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