#ifndef TEST_ZREAD_ROUTE_DEL_H
#define TEST_ZREAD_ROUTE_DEL_H

#include <gtest/gtest.h>
#include "zebra/zebra_srte.h"

#include "test_model.h"
#include "nhg_utils.h"
#include "zebra_utils.h"


class ZreadRouteDelTest : public ::testing::TestWithParam<test_case_route_del_t>
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