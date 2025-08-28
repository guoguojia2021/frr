#ifndef GTEST_PATHD_PATHD_UTILS_H
#define GTEST_PATHD_PATHD_UTILS_H

#include <string>
#include "test_model.h"

struct PolicyCandidatePathParams {
	uint32_t color;
	std::string endpoint;
	uint32_t preference;
	std::string candidate_name;
	std::string segment_list_name;
	uint32_t weight;
};


int api_segment_list(const std::string &name);
int api_segment_list_segment(const std::string &name, uint32_t index,
			     const std::string &ip_addr);
int api_srte_policy(uint32_t color, const std::string &endpoint);
int api_srte_policy_candidate_path(uint32_t color,
				      const std::string &endpoint,
				      uint32_t preference,
				      const std::string &candidate_name,
					  const std::string &segment_list_name);
int api_no_segment_list(const std::string &name);
int api_segment_list_no_segment(const std::string &name, uint32_t index);
int api_srte_no_policy(uint32_t color, const std::string &endpoint);
int api_srte_policy_no_candidate_path(uint32_t color,
				      const std::string &endpoint,
				      uint32_t preference,
				      const std::string &candidate_name);
void wrapper_apply_changes();
void wrapper_show();

void pathd_setup_env();
void pathd_teardown_env();
int setup_pathd_state(const struct pathd_state_t &state);

struct pathd_state_t dump_pathd_state();
bool compare_pathd_state(const struct pathd_state_t &actual,
			 const struct pathd_state_t &expected);
bool compare_dumped_pathd_state(const struct pathd_state_t &expected);

std::vector<struct path_policy_t> dump_policies();
bool compare_policy(const struct path_policy_t &a, const struct path_policy_t &b);

#endif // GTEST_PATHD_PATHD_UTILS_H
