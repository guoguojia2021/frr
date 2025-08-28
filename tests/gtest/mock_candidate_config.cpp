#include "mock_candidate_config.h"


// Ignores runtime values such as flags, refCount
static struct pathd_state_t candidate_config;

void reset_candidate_config()
{
	candidate_config = {};
}

std::vector<struct change_t> config_segment_list(const std::string &name)
{
	std::vector<change_t> res;

	// If segment_list already exists, return empty changes
	for (auto &segment_list : candidate_config.segment_lists) {
		if (segment_list.name == name) {
			return res;
		}
	}

	// Otherwise, update candidate_config with a new segment_list
	struct segment_list_t segment_list = {};
	segment_list.name = name;
	candidate_config.segment_lists.push_back(segment_list);

	// Return one change: create segment_list
	struct change_t change = {};
	change.op = CHANGE_OP_CREATE;
	change.ty = CHANGE_SEGMENT_LIST;
	change.segment_list.segment_list_name = name;
	res.push_back(change);

	return res;
}

static struct change_t change_create_segment(const std::string &name,
					     uint32_t index)
{
	struct change_t change = {};

	change.ty = CHANGE_SEGMENT_LIST_SEGMENT;
	change.op = CHANGE_OP_CREATE;
	change.segment.segment_list_name = name;
	change.segment.segment_index = index;

	return change;
}

static struct change_t change_modify_segment(const std::string &name,
					     uint32_t index,
					     const std::string &addr)
{
	struct change_t change = {};

	change.ty = CHANGE_SEGMENT_LIST_SEGMENT;
	change.op = CHANGE_OP_MOD;
	change.segment.segment_list_name = name;
	change.segment.segment_index = index;
	change.segment.segment_v6Address = addr;

	return change;
}

std::vector<struct change_t>
config_segment_list_segment(const std::string &name, uint32_t index,
			    const std::string &addr)
{
	std::vector<change_t> res;

	// Find the segment_list with given name
	for (auto &segment_list : candidate_config.segment_lists) {
		if (segment_list.name == name) {
			// If segment_list already has an identical segment,
			// return empty changes
			for (auto &segment : segment_list.segments) {
				if (segment.index == index) {
					if (segment.v6Address != addr) {
						// Modify segment
						segment.v6Address = addr;
						res.push_back(
							change_modify_segment(
								name, index,
								addr));
					}
					return res;
				}
			}

			// Otherwise, update candidate_config with a new segment
			struct segment_t segment = {};
			segment.index = index;
			segment.v6Address = addr;
			segment_list.segments.push_back(segment);

			res.push_back(change_create_segment(name, index));
			res.push_back(change_modify_segment(name, index, addr));
		}
	}

	return res;
}

std::vector<struct change_t> config_policy(uint32_t color,
					   const std::string &endpoint)
{
	std::vector<change_t> res;

	// If policy already exists, return empty changes
	for (auto &policy : candidate_config.policies) {
		if (policy.color == color && policy.endpoint == endpoint) {
			return res;
		}
	}

	// Otherwise, update candidate_config with a new policy
	struct path_policy_t policy = {};
	policy.color = color;
	policy.endpoint = endpoint;
	candidate_config.policies.push_back(policy);

	// Return one change: create policy
	struct change_t change = {};
	change.op = CHANGE_OP_CREATE;
	change.ty = CHANGE_POLICY;
	change.policy.color = color;
	change.policy.endpoint = endpoint;
	res.push_back(change);

	return res;
}
static struct change_t change_create_cpath(uint32_t color,
					   const std::string &endpoint,
					   uint32_t preference,
					   const std::string &candidate_name,
					   const std::string &segment_list_name)
{
	struct change_t change = {};

	change.ty = CHANGE_CANDIDATE_PATH;
	change.op = CHANGE_OP_CREATE;
	change.candidate_path.color = color;
	change.candidate_path.endpoint = endpoint;
	change.candidate_path.preference = preference;
	change.candidate_path.candidate_name = candidate_name;
	change.candidate_path.segment_list_name = segment_list_name;

	return change;
}

static struct change_t change_modify_cpath(uint32_t color,
					   const std::string &endpoint,
					   uint32_t preference,
					   const std::string &candidate_name,
					   const std::string &segment_list_name)
{
	struct change_t change = {};

	change.ty = CHANGE_CANDIDATE_PATH;
	change.op = CHANGE_OP_MOD;
	change.candidate_path.color = color;
	change.candidate_path.endpoint = endpoint;
	change.candidate_path.preference = preference;
	change.candidate_path.candidate_name = candidate_name;
	change.candidate_path.segment_list_name = segment_list_name;

	return change;
}

std::vector<struct change_t> config_policy_candidate_path(
	uint32_t color, const std::string &endpoint, uint32_t preference,
	const std::string &candidate_name, const std::string &segment_list_name)
{
	std::vector<change_t> res;


	for (auto &policy : candidate_config.policies) {
		if (policy.color == color && policy.endpoint == endpoint) {

			// cpath的preference和name是它的key，可以更新它的segment-list和bfd名字
			for (auto &path : policy.candidate_paths) {
				if (path.candidate_name == candidate_name) {
					if (path.preference == preference) {
						if (path.segment_list_name !=
						    segment_list_name) {
							// 配置cpath前，需要先配置segment-list
							for (auto &segment_list :
							     candidate_config
								     .segment_lists) {
								if (segment_list
									    .name ==
								    segment_list_name) {
									path.segment_list_name =
										segment_list_name;
									res.push_back(change_modify_cpath(
										color,
										endpoint,
										preference,
										candidate_name,
										segment_list_name));
									break;
								}
							}
						}
					}
					// cpath的name是唯一的，不能相同
					return res;
				}
			}
			// Otherwise, update candidate_config with a new
			// policy_candidate_path
			struct candidate_t cpath = {};
			cpath.candidate_name = candidate_name;
			cpath.preference = preference;
			cpath.segment_list_name = segment_list_name;
			policy.candidate_paths.push_back(cpath);

			res.push_back(change_create_cpath(
				color, endpoint, preference, candidate_name,
				segment_list_name));
			res.push_back(change_modify_cpath(
				color, endpoint, preference, candidate_name,
				segment_list_name));
		}
	}

	return res;
}
static struct change_t change_no_segment(const std::string &name,
					 uint32_t index)
{
	struct change_t change = {};

	change.ty = CHANGE_SEGMENT_LIST_SEGMENT;
	change.op = CHANGE_OP_DEL;
	change.no_segment.segment_index = index;
	change.no_segment.segment_list_name = name;

	return change;
}
static struct change_t change_no_segment_list(const std::string &name)
{
	struct change_t change = {};

	change.ty = CHANGE_SEGMENT_LIST;
	change.op = CHANGE_OP_DEL;
	change.no_segment_list.segment_list_name = name;

	return change;
}
std::vector<struct change_t> config_no_segment_list(const std::string &name)
{
	std::vector<change_t> res;

	// 删除segment-list前，需要先删除所有引用该segment-list的cpath
	for (auto &policy : candidate_config.policies) {
		for (auto &cpath : policy.candidate_paths) {
			if (cpath.segment_list_name == name) {
				return res;
			}
		}
	}

	for (auto it = candidate_config.segment_lists.begin();
	     it != candidate_config.segment_lists.end();) {
		if (it->name == name) {
			for (auto seg_it = it->segments.begin();
			     seg_it != it->segments.end();) {
				seg_it = it->segments.erase(seg_it);
			}
			res.push_back(change_no_segment_list(name));
			it = candidate_config.segment_lists.erase(it);
		} else {
			++it;
		}
	}

	return res;
}

std::vector<struct change_t>
config_segment_list_no_segment(const std::string &name, uint32_t index)
{
	std::vector<change_t> res;

	// Find the segment_list with given name
	for (auto it = candidate_config.segment_lists.begin();
	     it != candidate_config.segment_lists.end();) {
		if (it->name == name) {
			for (auto seg_it = it->segments.begin();
			     seg_it != it->segments.end();) {
				if (seg_it->index == index) {
					res.push_back(change_no_segment(
						name, seg_it->index));
					seg_it = it->segments.erase(seg_it);
					break;
				} else {
					++seg_it;
				}
			}
			break;
		} else {
			++it;
		}
	}

	return res;
}
static struct change_t change_no_cpath(uint32_t color,
				       const std::string &endpoint,
				       uint32_t preference,
				       const std::string &candidate_name)
{
	struct change_t change = {};

	change.ty = CHANGE_CANDIDATE_PATH;
	change.op = CHANGE_OP_DEL;
	change.no_candidate_path.color = color;
	change.no_candidate_path.endpoint = endpoint;
	change.no_candidate_path.preference = preference;
	change.no_candidate_path.candidate_name = candidate_name;

	return change;
}
static struct change_t change_no_policy(uint32_t color,
					const std::string &endpoint)
{
	struct change_t change = {};

	change.ty = CHANGE_POLICY;
	change.op = CHANGE_OP_DEL;
	change.no_policy.color = color;
	change.no_policy.endpoint = endpoint;

	return change;
}
std::vector<struct change_t> config_no_policy(uint32_t color,
					      const std::string &endpoint)
{
	std::vector<change_t> res;

	for (auto it = candidate_config.policies.begin();
	     it != candidate_config.policies.end();) {
		if (it->color == color && it->endpoint == endpoint) {
			for (auto cpath_it = it->candidate_paths.begin();
			     cpath_it != it->candidate_paths.end();) {
				cpath_it = it->candidate_paths.erase(cpath_it);
			}
			res.push_back(change_no_policy(color, endpoint));
			it = candidate_config.policies.erase(it);
		} else {
			++it;
		}
	}

	return res;
}
std::vector<struct change_t>
config_policy_no_candidate_path(uint32_t color, const std::string &endpoint,
				uint32_t preference, const std::string &candidate_name)
{
	std::vector<struct change_t> res;

	for (auto it = candidate_config.policies.begin();
	     it != candidate_config.policies.end();) {
		if (it->color == color && it->endpoint == endpoint) {
			for (auto cpath_it = it->candidate_paths.begin();
			     cpath_it != it->candidate_paths.end();) {
				if (cpath_it->preference == preference &&
				    cpath_it->candidate_name ==
					    candidate_name) {
					res.push_back(change_no_cpath(
						color, endpoint, preference,
						candidate_name));
					cpath_it = it->candidate_paths.erase(
						cpath_it);
					break;
				} else {
					++cpath_it;
				}
			}
			break;
		} else {
			++it;
		}
	}
	return res;
}