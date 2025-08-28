#ifndef GTEST_PATHD_MOCK_CANDIDATE_CONFIG_H
#define GTEST_PATHD_MOCK_CANDIDATE_CONFIG_H


#include <vector>
#include "test_model.h"
#include "pathd_utils.h"

enum change_type_t {
	CHANGE_SEGMENT_LIST,
	CHANGE_SEGMENT_LIST_SEGMENT,
	CHANGE_POLICY,
	CHANGE_CANDIDATE_PATH
};
enum change_op_t { CHANGE_OP_CREATE, CHANGE_OP_DEL, CHANGE_OP_MOD };

struct segment_list_change_t {
	std::string segment_list_name;
};

struct segment_change_t {
	std::string segment_list_name;
	uint32_t segment_index;
	std::string segment_v6Address;
};

struct policy_change_t {
	uint32_t color;
	std::string endpoint;
};
struct cpath_change_t {
	uint32_t color;
	std::string endpoint;
	uint32_t preference;
	std::string candidate_name;
	std::string segment_list_name;
};
struct no_segment_list_change_t {
	std::string segment_list_name;
};
struct no_segment_change_t {
	std::string segment_list_name;
	uint32_t segment_index;
};
struct no_policy_change_t {
	uint32_t color;
	std::string endpoint;
};
struct no_cpath_change_t {
	uint32_t color;
	std::string endpoint;
	uint32_t preference;
	std::string candidate_name;
};
struct change_t {
	enum change_type_t ty;
	enum change_op_t op;

	struct segment_list_change_t segment_list;
	struct segment_change_t segment;
	struct policy_change_t policy;
	struct cpath_change_t candidate_path;
	struct no_segment_list_change_t no_segment_list;
	struct no_segment_change_t no_segment;
	struct no_policy_change_t no_policy;
	struct no_cpath_change_t no_candidate_path;
};

void reset_candidate_config();

std::vector<struct change_t> config_segment_list(const std::string &name);

std::vector<struct change_t>
config_segment_list_segment(const std::string &name, uint32_t index,
			    const std::string &addr);

std::vector<struct change_t> config_policy(uint32_t color,
					   const std::string &endpoint);

std::vector<struct change_t> config_policy_candidate_path(
	uint32_t color, const std::string &endpoint, uint32_t preference,
	const std::string &candidate_name, const std::string &segment_list_name);

std::vector<struct change_t> config_no_segment_list(const std::string &name);
std::vector<struct change_t>
config_segment_list_no_segment(const std::string &name, uint32_t index);

std::vector<struct change_t> config_no_policy(uint32_t color,
					      const std::string &endpoint);
std::vector<struct change_t>
config_policy_no_candidate_path(uint32_t color, const std::string &endpoint,
				uint32_t preference,
				const std::string &candidate_name);
#endif // GTEST_PATHD_MOCK_CANDIDATE_CONFIG_H
