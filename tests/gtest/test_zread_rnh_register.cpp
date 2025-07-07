#include "test_zread_rnh_register.h"

#include <iostream>
#include <vector>
#include <map>

#include "zebra/zapi_msg.h"

#include "policy_utils.h"
#include "common_utils.h"
#include "rnh_utils.h"
#include "msg_utils.h"
#include "test_model.h"


TEST_P(ZreadRnhRegisterTest, Register)
{
	struct test_case_rnh_register test_case = GetParam();
	std::cout << "zread_rnh_register, Test #" << test_case.test_id
		  << std::endl;
	int ret = 0;

	setup_zebra_state(test_case.initial_state);

	std::cout << "============put in test data============" << std::endl;
	gtest_rnh_register(test_case.input_rnh);

	std::cout << "===========check test result=============" << std::endl;
	EXPECT_TRUE(compare_zebra_state(test_case.final_state));
	EXPECT_TRUE(compare_msg_fifo(test_case.msg_fifo));
}

INSTANTIATE_TEST_SUITE_P(RegisterTestSuite, ZreadRnhRegisterTest,
			 ::testing::ValuesIn(read_test_case_rnh_register_vec(
				 "resources/formatted_rnh_register.json")));
