#ifndef TEST_MODEL_H
#define TEST_MODEL_H

#include <vector>
#include <string>
#include <cstdint>
#include <map>

struct srv6_sidlist_t {
	std::string sidlist_name;
	uint8_t weight;
	// segment omitted
};

struct prefix_t {
	// We follow big-endian representation for IPv6 addresses
	uint16_t prefixlen;
	uint8_t endpoint[16];
};

struct api_policy_t {
	uint32_t color;
	struct prefix_t endpoint;
	std::vector<srv6_sidlist_t> sidlists;
};

enum policy_status_t { INIT = 0, DOWN, UP };

struct rnh_t {
	struct prefix_t prefix;
	struct prefix_t resolved_route;
	uint32_t srte_color;
};

struct policy_t {
	uint32_t color;
	struct prefix_t policy_table_key;
	policy_status_t status;
	std::vector<srv6_sidlist_t> segment_list;
	std::vector<rnh_t> nht;
};

struct srte_table_t {
	uint32_t color;
	std::vector<policy_t> policies;
};

struct nexthop_t {
	uint8_t gate[16];
	uint32_t color;

	/*
	 * For leaf type nexthop_t, sidlist_name is non-empty, resolved is
	 * empty.
	 *
	 * For root type nexthop_t, sidlist_name is empty, resolved is non-empty
	 * and contains only leaf-type members.
	 * */
	std::string sidlist_name;
	std::vector<nexthop_t> resolved;
};

struct nhg_t {
	/*
	 * For sidlist-level nhg_t, nexthop is of leaf type, seg_depends is
	 * empty.
	 *
	 * For policy-level nhg_t, nexthop is of root type, seg_depends is
	 * non-empty and contains only sidlist-level members.
	 *
	 * For route-level nhg_t, shared_seg_depends is non-empty.
	 * */
	std::vector<nexthop_t> resolved_nexthops;
	std::vector<nhg_t> seg_depends;

	// Specify shape only, not for verbatim comparison with actual C states
	bool contains_id;
	int internal_id;
	std::vector<int> shared_seg_depends;
};

struct rnh_list_t {
	struct prefix_t prefix;
	std::vector<rnh_t> rnh;
};

struct api_route_nexthop_t {
	uint8_t gate[16];
	uint32_t color;
};

struct api_route_t {
	struct prefix_t prefix;
	std::vector<struct api_route_nexthop_t> api_nexthops;
};
struct api_route_del_t {
	struct prefix_t prefix;
};

struct zebra_state_t {
	std::vector<srte_table_t> policy_route_table;
	std::vector<nhg_t> nhgs;
	std::vector<rnh_list_t> rnh_table;
	std::vector<api_route_t> route_nhg_map;
};

struct test_case_policy_set_del_t {
	int test_id;
	struct zebra_state_t initial_state;
	struct api_policy_t input_policy;
	struct zebra_state_t final_state;
};

struct test_case_route_add_t {
	int test_id;
	struct zebra_state_t initial_state;
	struct api_route_t input_route;
	struct zebra_state_t final_state;
};

struct api_rnh_t {
	struct prefix_t prefix;
	uint32_t srte_color;
};

struct test_case_rnh_register {
	int test_id;
	struct zebra_state_t initial_state;
	struct api_rnh_t input_rnh;
	struct zebra_state_t final_state;
};

struct test_case_route_del_t {
	int test_id;
	struct zebra_state_t initial_state;
	struct api_route_del_t input_route;
	struct zebra_state_t final_state;
};

std::vector<test_case_policy_set_del_t>
read_all_test_cases_policy_set_del(const std::string &json_file_path);

std::map<int, test_case_policy_set_del_t>
read_policy_set_del_test_cases_map(const std::string &json_file_path);

std::vector<test_case_route_add_t>
read_all_test_cases_route_add(const std::string &json_file_path);

std::map<int, test_case_rnh_register>
read_all_test_cases_nexthop_register(const std::string &json_file_path);

std::vector<test_case_route_del_t>
read_all_test_cases_route_del(const std::string &json_file_path);

void print_nexthops(const struct nexthop_t &n);

void print_api_policy(const struct api_policy_t &api_policy);
void print_api_route(const struct api_route_t &route);


/*
 * Multi-step test case
 * */

enum class Action {
	// API calls
	POLICY_SET,
	POLICY_DEL,
	ROUTE_ADD,
	ROUTE_DEL,
	RNH_REGISTER,
	RNH_UNREGISTER,
};

struct step_action_t {
	Action action;
	struct api_policy_t input_policy;
	// TODO: input_route
	struct rnh_t input_rnh;
};

struct multi_test_case_t {
	int test_id;
	struct zebra_state_t initial_state;
	std::vector<struct step_action_t> input_actions;
	struct zebra_state_t final_state;
};


std::map<int, multi_test_case_t>
read_multi_test_cases_map(const std::string &json_file_path);

std::vector<multi_test_case_t>
read_multi_test_cases_vec(const std::string &json_file_path);


#endif // TEST_MODEL_H
