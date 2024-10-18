#include "test_zread_rnh_unregister.h"

#include <iostream>
#include <vector>
#include <map>

#include "zebra/zapi_msg.h"

#include "policy_utils.h"
#include "common_utils.h"
#include "rnh_utils.h"
#include "test_model.h"


static std::vector<test_case_rnh_register>
load_test_cases(const std::string &json_file_path)
{
	std::vector<test_case_rnh_register> res;

	std::map<int, test_case_rnh_register> rnh_cases_map =
		read_all_test_cases_nexthop_register(json_file_path);
	for (const auto &pair : rnh_cases_map) {
		res.push_back(pair.second);
	}

	std::cout << "Loaded " << res.size() << " test cases from "
		  << json_file_path << std::endl;

	return res;
}


TEST_P(ZreadRnhUnRegisterTest, Unregister)
{
	struct test_case_rnh_register test_case = GetParam();
	std::cout << "zread_rnh_unregister, Test #" << test_case.test_id
		  << std::endl;
	int ret = 0;

	zebra_vrf *zvrf = policy_utils.get_mock_zvrf();
	zserv *client = policy_utils.get_mock_client();
	setup_zebra_state(test_case.initial_state, zvrf, client);

	std::cout << "============put in test data============" << std::endl;
	struct prefix p;
	ret = common_utils::prefix_t2prefix(&test_case.input_rnh.prefix, &p);
	EXPECT_EQ(ret, 0);

	struct stream *s = RnhUtils::fill_stream_with_rnh(
		ZEBRA_NEXTHOP_UNREGISTER, &p, test_case.input_rnh.srte_color);
	EXPECT_NE(s, nullptr);
	struct zmsghdr hdr;
	zapi_parse_header(s, &hdr);
	hdr.length -= ZEBRA_HEADER_SIZE;
	zread_rnh_unregister(policy_utils.get_mock_client(), &hdr, s,
			     policy_utils.get_mock_zvrf());

	std::cout << "===========check test result=============" << std::endl;
	EXPECT_TRUE(dump_and_check_state(test_case.final_state));
}

INSTANTIATE_TEST_SUITE_P(UnregisterTestSuite, ZreadRnhUnRegisterTest,
			 ::testing::ValuesIn(load_test_cases(
				 "resources/formatted_rnh_unregister.json")));
