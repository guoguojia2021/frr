#include "pathd_utils.h"

#include <gtest/gtest.h>
#include <iostream>
#include <unordered_map>
#include <cstring>
#include "pathd/pathd.h"
#include "pathd/path_sbfd.h"
#include "lib/openbsd-tree.h"
#include "lib/zebra.h"
#include "lib/prefix.h"
#include "lib/northbound.h"
#include "test_model.h"
#include "segment_utils.h"
#include "policy_utils.h"
#include "mock_candidate_config.h"

/*
 * Mock nb_running_set_entry, nb_running_get_entry
 * */


static std::unordered_map<std::string, void *> running_config_map;


/*
 * E.g., xpath: /frr-pathd:pathd/srte/segment-list[name='a']/segment[index='10']
 * returns /frr-pathd:pathd/srte/segment-list[name='a']
 * */
static std::string xpath_parent(const std::string &xpath)
{
	bool inSingleQuote = false;
	bool inDoubleQuote = false;
	int lastSlashOutsideQuotes = -1;

	for (size_t i = 0; i < xpath.size(); i++) {
		char c = xpath[i];

		if (c == '\'') {
			if (!inDoubleQuote)
				inSingleQuote = !inSingleQuote;
		} else if (c == '"') {
			if (!inSingleQuote)
				inDoubleQuote = !inDoubleQuote;
		} else if (c == '/' && !inSingleQuote && !inDoubleQuote) {
			lastSlashOutsideQuotes = i;
		}
	}

	// If no slash found outside of quotes, or it's at position 0, return
	// empty
	if (lastSlashOutsideQuotes <= 0)
		return "";

	return xpath.substr(0, lastSlashOutsideQuotes);
}


void mock_nb_running_set_entry(const std::string &xpath, void *data)
{
	running_config_map[xpath] = data;
}


void *mock_nb_running_get_entry(const std::string &xpath)
{
	std::string current_xpath = xpath;

	while (!current_xpath.empty()) {
		auto it = running_config_map.find(current_xpath);
		if (it != running_config_map.end()) {
			return it->second; // Found
		}

		current_xpath = xpath_parent(current_xpath);
	}

	return nullptr; // Not found
}

void *mock_nb_running_unset_entry(const std::string &xpath)
{
	auto it = running_config_map.find(xpath);
	if (it != running_config_map.end()) {
		void *data = it->second;
		running_config_map.erase(it);
		return data;
	}
	return nullptr;
}

// see path_nb_config.c :: pathd_srte_segment_list_create
// Additional modifications: pathd_srte_segment_list_originator_modify,
// 			pathd_srte_segment_list_protocol_origin_modify
static int mock_pathd_srte_segment_list_create(const std::string &name,
					       enum nb_event event)
{
	if (event != NB_EV_APPLY)
		return NB_OK;

	struct srte_segment_list *segment_list;
	segment_list = srte_segment_list_add(name.c_str());
	segment_list->protocol_origin = SRTE_ORIGIN_LOCAL;
	strncpy(segment_list->originator, "config",
		sizeof(segment_list->originator) - 1);
	segment_list->originator[sizeof(segment_list->originator) - 1] = '\0';

	std::string xpath =
		"/frr-pathd:pathd/srte/segment-list[name='" + name + "']";

	mock_nb_running_set_entry(xpath, segment_list);
	SET_FLAG(segment_list->flags, F_SEGMENT_LIST_NEW);
	SET_FLAG(segment_list->flags, F_SEGMENT_LIST_MODIFIED);

	return 0;
}

// see path_nb_config.c :: pathd_srte_segment_list_destroy
static int mock_pathd_srte_segment_list_destroy(const std::string &name,
						enum nb_event event)
{
	if (event != NB_EV_APPLY)
		return NB_OK;

	struct srte_segment_list *segment_list;

	std::string xpath =
		"/frr-pathd:pathd/srte/segment-list[name='" + name + "']";

	segment_list = static_cast<struct srte_segment_list *>(
		mock_nb_running_unset_entry(xpath));
	SET_FLAG(segment_list->flags, F_SEGMENT_LIST_DELETED);

	return 0;
}

static int mock_pathd_srte_segment_list_segment_create(const std::string &name,
						       uint32_t index,
						       enum nb_event event)
{
	std::string xpath = "/frr-pathd:pathd/srte/segment-list[name='" + name +
			    "']/segment[index='" + std::to_string(index) + "']";
	struct srte_segment_list *segment_list =
		static_cast<struct srte_segment_list *>(
			mock_nb_running_get_entry(xpath_parent(xpath)));

	if (event == NB_EV_VALIDATE) {
		if (segment_list != nullptr && (segment_list->refcount > 0)) {
			std::cout
				<< "The Segment List is being used, cannot add new index"
				<< std::endl;
			return NB_ERR_RESOURCE;
		}
	} else if (event == NB_EV_APPLY) {
		struct srte_segment_entry *segment =
			srte_segment_entry_add(segment_list, index);
		mock_nb_running_set_entry(xpath, segment);
		SET_FLAG(segment_list->flags, F_SEGMENT_LIST_MODIFIED);
	}

	return 0;
}


/*
 * XPath: /frr-pathd:pathd/srte/segment-list/segment/srv6-sid-value
 */
static int mock_pathd_srte_segment_list_segment_v6_sid_value_modify(
	const std::string &name, uint32_t index, const std::string &ip_addr,
	enum nb_event event)
{
	if (event != NB_EV_APPLY)
		return 0;

	struct ipaddr sid_value;
	if (str2ipaddr(ip_addr.c_str(), &sid_value) != 0) {
		std::cout
			<< "mock_pathd_srte_segment_list_segment_v6_sid_value_modify: "
			   "invalid IP address"
			<< std::endl;
		return -1;
	}

	// /frr-pathd:pathd/srte/segment-list[name='abc']/segment[index='10']/srv6-sid-value
	std::string xpath = "/frr-pathd:pathd/srte/segment-list[name='" + name +
			    "']/segment[index='" + std::to_string(index) + "']";
	struct srte_segment_entry *segment =
		static_cast<struct srte_segment_entry *>(
			mock_nb_running_get_entry(xpath));
	segment->sid_type = SRTE_SEGMENT_SID_TYPE_V6;
	segment->srv6_sid_value = sid_value;
	SET_FLAG(segment->segment_list->flags, F_SEGMENT_LIST_MODIFIED);

	return 0;
}


static int mock_pathd_srte_segment_list_segment_destroy(const std::string &name,
							uint32_t index,
							enum nb_event event)
{
	std::string xpath = "/frr-pathd:pathd/srte/segment-list[name='" + name +
			    "']/segment[index='" + std::to_string(index) + "']";
	struct srte_segment_entry *segment;

	switch (event) {
	case NB_EV_VALIDATE:
		segment = static_cast<struct srte_segment_entry *>(
			mock_nb_running_get_entry(xpath));
		if (segment && is_refcounter_retain(segment->segment_list)) {
			std::cout
				<< "The Segment List is being used, cannot delete index."
				<< std::endl;

			return NB_ERR_RESOURCE;
		}
		break;
	case NB_EV_APPLY:
		segment = static_cast<struct srte_segment_entry *>(
			mock_nb_running_unset_entry(xpath));
		SET_FLAG(segment->segment_list->flags, F_SEGMENT_LIST_MODIFIED);
		srte_segment_entry_del(segment);
		break;
	default:
		break;
	}
	return NB_OK;
}

/*
 * Adapted from path_nb_config.c:: pathd_srte_policy_create
 * XPath: /frr-pathd:pathd/srte/policy
 * */
static int mock_pathd_srte_policy_create(uint32_t color,
					 const std::string &endpoint_str,
					 enum nb_event event)
{
	struct srte_policy *policy;
	struct prefix endpoint;

	if (event != NB_EV_APPLY)
		return 0;

	str2prefix(endpoint_str.c_str(), &endpoint);

	std::cout << "endpoint.family = " << (int)(endpoint.family)
		  << std::endl;

	/* set prefixlen to 0 if address is 0.0.0.0 or :: */
	if (endpoint.family == AF_INET &&
	    endpoint.u.prefix4.s_addr == INADDR_ANY &&
	    endpoint.prefixlen == IPV4_MAX_BITLEN)
		endpoint.prefixlen = 0;

	if (endpoint.family == AF_INET6 &&
	    IPV6_ADDR_SAME(&endpoint.u.prefix6, &in6addr_any) &&
	    endpoint.prefixlen == IPV6_MAX_BITLEN)
		endpoint.prefixlen = 0;

	policy = srte_policy_add(color, &endpoint, SRTE_ORIGIN_LOCAL, NULL);

	// XPath: /frr-pathd:pathd/srte/policy[color='1'][endpoint='::']
	std::string xpath = "/frr-pathd:pathd/srte/policy[color='" +
			    std::to_string(color) + "'][endpoint='" +
			    endpoint_str + "']";
	mock_nb_running_set_entry(xpath, policy);
	SET_FLAG(policy->flags, F_POLICY_NEW);

	return 0;
}


/*
 * Adapted from path_nb_config.c::
 * pathd_srte_policy_candidate_path_create Xpath
 * /frr-pathd:pathd/srte/policy[color='1'][endpoint='::']/candidate-path[preference='1'][name='a']
 * */
static int mock_pathd_srte_policy_candidate_path_create(
	uint32_t color, const std::string &endpoint, uint32_t preference,
	const std::string &candidate_name, const std::string &segment_list_name,
	enum nb_event event)
{
	struct srte_policy *policy;
	struct srte_candidate *candidate;
	const char *name, *segname;

	// Construct xpath from arguments in the form as
	// /frr-pathd:pathd/srte/policy[color='1'][endpoint='::']/candidate-path[preference='1'][name='a']
	std::string xpath = "/frr-pathd:pathd/srte/policy[color='" +
			    std::to_string(color) + "'][endpoint='" + endpoint +
			    "']/candidate-path[preference='" +
			    std::to_string(preference) + "'][name='" +
			    candidate_name + "']";
	std::cout << "mock_pathd_srte_policy_candidate_path_create: xpath "
		  << xpath << std::endl;

	struct srte_candidate *candidate_tmp;

	policy = static_cast<struct srte_policy *>(
		mock_nb_running_get_entry(xpath_parent(xpath)));
	std::cout
		<< "mock_pathd_srte_policy_candidate_path_create: found policy "
		<< policy << std::endl;

	if (event == NB_EV_VALIDATE) {
		if (policy == NULL)
			return NB_OK;

		segname = segment_list_name.c_str();

		RB_FOREACH (candidate_tmp, srte_candidate_head,
			    &policy->candidate_paths) {

			if (candidate_tmp->segment_list == NULL)
				continue;

			if (strcmp(candidate_tmp->segment_list->name,
				   segname) == 0 &&
			    candidate_tmp->preference == preference) {
				std::cout
					<< "One policy not allow config the same segment-list"
					<< std::endl;
				return NB_ERR_VALIDATION;
			}
		}

		return NB_OK;
	} else if (event == NB_EV_APPLY) {
		name = candidate_name.c_str();
		candidate = srte_candidate_add(policy, preference,
					       SRTE_ORIGIN_LOCAL, NULL, name);
		candidate->weight = 1; // default
		mock_nb_running_set_entry(xpath, candidate);
		SET_FLAG(candidate->flags, F_CANDIDATE_NEW);

		if (candidate->policy->bfd_config) {
			candidate->policy_bfd_ops = CANDIDATE_SBFD_NEW;
		}

		SET_FLAG(candidate->policy->flags, F_POLICY_MODIFIED);

		// mock pathd_srte_policy_candidate_path_protocol_origin_modify
		candidate->protocol_origin = SRTE_ORIGIN_LOCAL;
		candidate->lsp->protocol_origin = SRTE_ORIGIN_LOCAL;
		SET_FLAG(candidate->flags, F_CANDIDATE_MODIFIED);

		// mock pathd_srte_policy_candidate_path_originator_modify
		const char *originator = "config";
		strlcpy(candidate->originator, originator,
			sizeof(candidate->originator));
		strlcpy(candidate->lsp->originator, originator,
			sizeof(candidate->lsp->originator));
		SET_FLAG(candidate->flags, F_CANDIDATE_MODIFIED);

		// mock pathd_srte_policy_candidate_path_type_modify
		if (candidate &&
		    candidate->type != SRTE_CANDIDATE_TYPE_UNDEFINED) {
			std::cout << "The candidate type is fixed!"
				  << std::endl;
			return NB_ERR_RESOURCE;
		}
		candidate->type = SRTE_CANDIDATE_TYPE_EXPLICIT;
		SET_FLAG(candidate->flags, F_CANDIDATE_MODIFIED);
	}

	return NB_OK;
}


static int mock_pathd_srte_policy_candidate_path_segment_list_name_modify(
	uint32_t color, const std::string &endpoint, uint32_t preference,
	const std::string &candidate_name, const std::string &segment_list_name,
	enum nb_event event)
{
	struct srte_candidate *candidate;
	const char *segname;
	
	// Construct xpath from arguments in the form as
	// /frr-pathd:pathd/srte/policy[color='1'][endpoint='::']/candidate-path[preference='1'][name='a']
	std::string xpath = "/frr-pathd:pathd/srte/policy[color='" +
			    std::to_string(color) + "'][endpoint='" + endpoint +
			    "']/candidate-path[preference='" +
			    std::to_string(preference) + "'][name='" +
			    candidate_name + "']";
	std::cout
		<< "mock_pathd_srte_policy_candidate_path_segment_list_name_modify: xpath "
		<< xpath << std::endl;
	if (event != NB_EV_APPLY)
		return 0;
	candidate = static_cast<struct srte_candidate *>(
		mock_nb_running_get_entry(xpath));
	segname = segment_list_name.c_str();

	/* old sidlist */
	if (candidate->segment_list) {
		if (candidate->policy->bfd_config) {
			sr_config_sbfd_remove(candidate->segment_list,
					      candidate->policy);
			candidate->status = SRTE_DETECT_NONE;
		}

		refcounter_decrease(candidate->segment_list);
		SET_FLAG(candidate->segment_list->flags, F_SEGMENT_LIST_REF);
		candidate->segment_list = NULL;
	}

	/* new sidlist */
	candidate->segment_list = srte_segment_list_find(segname);
	refcounter_increase(candidate->segment_list);

	candidate->lsp->segment_list = candidate->segment_list;
	if (!candidate->segment_list)
		return NB_OK;

	SET_FLAG(candidate->flags, F_CANDIDATE_MODIFIED);
	SET_FLAG(candidate->segment_list->flags, F_SEGMENT_LIST_REF);

	// sbfd enabled
	if (candidate->policy->bfd_config) {
		candidate->policy_bfd_ops = CANDIDATE_SBFD_MODIFIED;
	}

	SET_FLAG(candidate->policy->flags, F_POLICY_MODIFIED);
	return NB_OK;
}

// see path_nb_config.c :: pathd_srte_policy_destroy
static int mock_pathd_srte_policy_destroy(uint32_t color,
					  const std::string &endpoint_str,
					  enum nb_event event)
{
	struct srte_policy *policy;

	if (event != NB_EV_APPLY)
		return NB_OK;

	std::string xpath = "/frr-pathd:pathd/srte/policy[color='" +
			    std::to_string(color) + "'][endpoint='" +
			    endpoint_str + "']";

	policy = static_cast<struct srte_policy *>(
		mock_nb_running_unset_entry(xpath));
	SET_FLAG(policy->flags, F_POLICY_DELETED);

	return NB_OK;
}

// see path_nb_config.c ::
// pathd_srte_policy_candidate_path_segment_list_name_destroy
static int pathd_srte_policy_candidate_path_destroy(

	uint32_t color, const std::string &endpoint, uint32_t preference,
	const std::string &candidate_name, enum nb_event event)
{
	struct srte_candidate *candidate;

	if (event != NB_EV_APPLY)
		return NB_OK;
	std::string xpath = "/frr-pathd:pathd/srte/policy[color='" +
			    std::to_string(color) + "'][endpoint='" + endpoint +
			    "']/candidate-path[preference='" +
			    std::to_string(preference) + "'][name='" +
			    candidate_name + "']";
	candidate = static_cast<struct srte_candidate *>(
		mock_nb_running_unset_entry(xpath));

	SET_FLAG(candidate->flags, F_CANDIDATE_DELETED);
	if (candidate->policy->bfd_config) {
		candidate->policy_bfd_ops = CANDIDATE_SBFD_DELETED;
	}
	SET_FLAG(candidate->policy->flags, F_POLICY_MODIFIED);

	return NB_OK;
}
static int
apply_change(const struct change_t &change,
	     const std::function<bool(change_type_t, change_op_t)> &is_valid,
	     enum nb_event phase)
{
	if (!is_valid(change.ty, change.op)) {
		GTEST_LOG_(ERROR)
			<< "Invalid combination of change_type and change_op: "
			<< change.ty << ", " << change.op;
		return -1;
	}

	int ret;
	const struct segment_list_change_t &segment_list_args =
		change.segment_list;
	const struct segment_change_t &segment_args = change.segment;
	const struct policy_change_t &policy_args = change.policy;
	const struct cpath_change_t &candidate_path_args =
		change.candidate_path;
	const struct no_segment_list_change_t &no_segment_list_args =
		change.no_segment_list;
	const struct no_segment_change_t &no_segment_args = change.no_segment;
	const struct no_policy_change_t &no_policy_args = change.no_policy;
	const struct no_cpath_change_t &no_candidate_path_args =
		change.no_candidate_path;

	switch (change.ty) {
	case CHANGE_SEGMENT_LIST:
		switch (change.op) {
		case CHANGE_OP_CREATE:
			ret = mock_pathd_srte_segment_list_create(
				segment_list_args.segment_list_name, phase);
			break;
		case CHANGE_OP_MOD:
			GTEST_LOG_(ERROR)
				<< "Unsupported change op on SEGMENT_LIST: "
				<< change.op;
			break;
		case CHANGE_OP_DEL:
			ret = mock_pathd_srte_segment_list_destroy(
				no_segment_list_args.segment_list_name, phase);
		}
		break;
	case CHANGE_SEGMENT_LIST_SEGMENT:
		switch (change.op) {
		case CHANGE_OP_CREATE:
			ret = mock_pathd_srte_segment_list_segment_create(
				segment_args.segment_list_name,
				segment_args.segment_index, phase);
			break;
		case CHANGE_OP_MOD:
			ret = mock_pathd_srte_segment_list_segment_v6_sid_value_modify(
				segment_args.segment_list_name,
				segment_args.segment_index,
				segment_args.segment_v6Address, phase);
			break;
		case CHANGE_OP_DEL:
			ret = mock_pathd_srte_segment_list_segment_destroy(
				no_segment_args.segment_list_name,
				no_segment_args.segment_index, phase);
		}
		break;
	case CHANGE_POLICY:
		switch (change.op) {
		case CHANGE_OP_CREATE:
			ret = mock_pathd_srte_policy_create(
				policy_args.color, policy_args.endpoint, phase);
			break;
		case CHANGE_OP_MOD:
			GTEST_LOG_(ERROR) << "Unsupported change op on POLICY: "
					  << change.op;
			break;
		case CHANGE_OP_DEL:
			ret = mock_pathd_srte_policy_destroy(
				no_policy_args.color, no_policy_args.endpoint,
				phase);
		}
		break;
	case CHANGE_CANDIDATE_PATH:
		switch (change.op) {
		case CHANGE_OP_CREATE:
			ret = mock_pathd_srte_policy_candidate_path_create(
				candidate_path_args.color,
				candidate_path_args.endpoint,
				candidate_path_args.preference,
				candidate_path_args.candidate_name,
				candidate_path_args.segment_list_name, phase);
			break;
		case CHANGE_OP_MOD:
			ret = mock_pathd_srte_policy_candidate_path_segment_list_name_modify(
				candidate_path_args.color,
				candidate_path_args.endpoint,
				candidate_path_args.preference,
				candidate_path_args.candidate_name,
				candidate_path_args.segment_list_name, phase);
			break;
		case CHANGE_OP_DEL:
			ret = pathd_srte_policy_candidate_path_destroy(
				no_candidate_path_args.color,
				no_candidate_path_args.endpoint,
				no_candidate_path_args.preference,
				no_candidate_path_args.candidate_name, phase);
		}
		break;
	}

	return ret;
}


int api_segment_list(const std::string &name)
{
	std::vector<change_t> changes = config_segment_list(name);
	auto validator = [](change_type_t ty, change_op_t op) {
		return (ty == CHANGE_SEGMENT_LIST && op == CHANGE_OP_CREATE);
	};

	// validation
	for (const auto &change : changes) {
		int ret = apply_change(change, validator, NB_EV_VALIDATE);
		if (ret != 0) {
			GTEST_LOG_(INFO)
				<< "Validation failed, no change applied: ty "
				<< change.ty << ", op " << change.op;
			return ret;
		}
	}

	// apply
	for (const auto &change : changes) {
		int ret = apply_change(change, validator, NB_EV_APPLY);
		if (ret != 0) {
			GTEST_LOG_(ERROR) << "Failed to apply change: ty "
					  << change.ty << ", op " << change.op;
			return ret;
		}
	}

	srte_apply_changes();

	return 0;
}


int api_segment_list_segment(const std::string &name, uint32_t index,
			     const std::string &ip_addr)
{
	std::vector<change_t> changes =
		config_segment_list_segment(name, index, ip_addr);
	auto validator = [](change_type_t ty, change_op_t op) {
		return (ty == CHANGE_SEGMENT_LIST_SEGMENT &&
			op == CHANGE_OP_CREATE) ||
		       (ty == CHANGE_SEGMENT_LIST_SEGMENT &&
			op == CHANGE_OP_MOD);
	};

	// validation
	for (const auto &change : changes) {
		int ret = apply_change(change, validator, NB_EV_VALIDATE);
		if (ret != 0) {
			GTEST_LOG_(INFO)
				<< "Validation fails, no change applied: ty "
				<< change.ty << ", op " << change.op;
			return ret;
		}
	}

	// apply
	for (const auto &change : changes) {
		int ret = apply_change(change, validator, NB_EV_APPLY);
		if (ret != 0) {
			GTEST_LOG_(ERROR) << "Failed to apply change: ty "
					  << change.ty << ", op " << change.op;
			return ret;
		}
	}

	srte_apply_changes();

	return 0;
}
int api_srte_policy(uint32_t color, const std::string &endpoint_str)
{
	std::vector<struct change_t> changes =
		config_policy(color, endpoint_str);
	auto validator = [](change_type_t ty, change_op_t op) {
		return (ty == CHANGE_POLICY && op == CHANGE_OP_CREATE);
	};

	// validation
	for (const auto &change : changes) {
		int ret = apply_change(change, validator, NB_EV_VALIDATE);
		if (ret != 0) {
			GTEST_LOG_(INFO)
				<< "Validation fails, no change applied: ty "
				<< change.ty << ", op " << change.op;
			return ret;
		}
	}

	// apply
	for (const auto &change : changes) {
		int ret = apply_change(change, validator, NB_EV_APPLY);
		if (ret != 0) {
			GTEST_LOG_(ERROR) << "Failed to apply change: ty "
					  << change.ty << ", op " << change.op;
			return ret;
		}
	}

	srte_apply_changes();

	return 0;
}

int api_srte_policy_candidate_path(uint32_t color, const std::string &endpoint,
				   uint32_t preference,
				   const std::string &candidate_name,
				   const std::string &segment_list_name)
{
	std::vector<struct change_t> changes = config_policy_candidate_path(
		color, endpoint, preference, candidate_name, segment_list_name);
	auto validator = [](change_type_t ty, change_op_t op) {
		return (ty == CHANGE_CANDIDATE_PATH &&
			op == CHANGE_OP_CREATE) ||
		       (ty == CHANGE_CANDIDATE_PATH && op == CHANGE_OP_MOD);
	};

	// validation
	for (const auto &change : changes) {
		int ret = apply_change(change, validator, NB_EV_VALIDATE);
		if (ret != 0) {
			GTEST_LOG_(INFO)
				<< "Validation fails, no change applied: ty "
				<< change.ty << ", op " << change.op;
			return ret;
		}
	}

	// apply
	for (const auto &change : changes) {
		int ret = apply_change(change, validator, NB_EV_APPLY);
		if (ret != 0) {
			GTEST_LOG_(ERROR) << "Failed to apply change: ty "
					  << change.ty << ", op " << change.op;
			return ret;
		}
	}

	srte_apply_changes();

	return 0;
}
int api_no_segment_list(const std::string &name)
{
	std::vector<change_t> changes = config_no_segment_list(name);
	auto validator = [](change_type_t ty, change_op_t op) {
		return (ty == CHANGE_SEGMENT_LIST && op == CHANGE_OP_DEL);
	};

	// validation
	for (const auto &change : changes) {
		int ret = apply_change(change, validator, NB_EV_VALIDATE);
		if (ret != 0) {
			GTEST_LOG_(INFO)
				<< "Validation failed, no change applied: ty "
				<< change.ty << ", op " << change.op;
			return ret;
		}
	}

	// apply
	for (const auto &change : changes) {
		int ret = apply_change(change, validator, NB_EV_APPLY);
		if (ret != 0) {
			GTEST_LOG_(ERROR) << "Failed to apply change: ty "
					  << change.ty << ", op " << change.op;
			return ret;
		}
	}

	srte_apply_changes();

	return 0;
}
int api_segment_list_no_segment(const std::string &name, uint32_t index)
{
	std::vector<change_t> changes =
		config_segment_list_no_segment(name, index);
	auto validator = [](change_type_t ty, change_op_t op) {
		return (ty == CHANGE_SEGMENT_LIST_SEGMENT &&
			op == CHANGE_OP_DEL);
	};

	// validation
	for (const auto &change : changes) {
		int ret = apply_change(change, validator, NB_EV_VALIDATE);
		if (ret != 0) {
			GTEST_LOG_(INFO)
				<< "Validation fails, no change applied: ty "
				<< change.ty << ", op " << change.op;
			return ret;
		}
	}

	// apply
	for (const auto &change : changes) {
		int ret = apply_change(change, validator, NB_EV_APPLY);
		if (ret != 0) {
			GTEST_LOG_(ERROR) << "Failed to apply change: ty "
					  << change.ty << ", op " << change.op;
			return ret;
		}
	}

	srte_apply_changes();

	return 0;
}
int api_srte_no_policy(uint32_t color, const std::string &endpoint_str)
{
	std::vector<struct change_t> changes =
		config_no_policy(color, endpoint_str);
	auto validator = [](change_type_t ty, change_op_t op) {
		return (ty == CHANGE_POLICY && op == CHANGE_OP_DEL);
	};

	// validation
	for (const auto &change : changes) {
		int ret = apply_change(change, validator, NB_EV_VALIDATE);
		if (ret != 0) {
			GTEST_LOG_(INFO)
				<< "Validation fails, no change applied: ty "
				<< change.ty << ", op " << change.op;
			return ret;
		}
	}

	// apply
	for (const auto &change : changes) {
		int ret = apply_change(change, validator, NB_EV_APPLY);
		if (ret != 0) {
			GTEST_LOG_(ERROR) << "Failed to apply change: ty "
					  << change.ty << ", op " << change.op;
			return ret;
		}
	}

	srte_apply_changes();

	return 0;
}
int api_srte_policy_no_candidate_path(uint32_t color,
				      const std::string &endpoint,
				      uint32_t preference,
				      const std::string &candidate_name)
{
	std::vector<struct change_t> changes = config_policy_no_candidate_path(
		color, endpoint, preference, candidate_name);
	auto validator = [](change_type_t ty, change_op_t op) {
		return (ty == CHANGE_CANDIDATE_PATH && op == CHANGE_OP_DEL);
	};

	// validation
	for (const auto &change : changes) {
		int ret = apply_change(change, validator, NB_EV_VALIDATE);
		if (ret != 0) {
			GTEST_LOG_(INFO)
				<< "Validation fails, no change applied: ty "
				<< change.ty << ", op " << change.op;
			return ret;
		}
	}

	// apply
	for (const auto &change : changes) {
		int ret = apply_change(change, validator, NB_EV_APPLY);
		if (ret != 0) {
			GTEST_LOG_(ERROR) << "Failed to apply change: ty "
					  << change.ty << ", op " << change.op;
			return ret;
		}
	}

	srte_apply_changes();

	return 0;
}
void wrapper_apply_changes()
{
	srte_apply_changes();
}


void wrapper_show()
{
	show_nonstatic();
}

extern struct srte_segment_list_head srte_segment_lists;
extern struct srte_policy_head srte_policies;

void pathd_setup_env()
{
	// Reset mock state
	running_config_map.clear();
	reset_candidate_config();

	srte_segment_lists = RB_INITIALIZER(&srte_segment_lists);
	srte_policies = RB_INITIALIZER(&srte_policies);
}

void pathd_teardown_env()
{
}

/*
 * dump & compare state
 * */
struct pathd_state_t dump_pathd_state()
{
	struct pathd_state_t state = {};
	state.segment_lists = dump_segment_lists();
	state.policies = dump_policies();

	return state;
}

bool compare_pathd_state(const struct pathd_state_t &actual,
			 const struct pathd_state_t &expected)
{
	if (actual.segment_lists.size() != expected.segment_lists.size()) {
		std::cout << "Mismatch: segment_list count ("
			  << actual.segment_lists.size() << " vs "
			  << expected.segment_lists.size() << ")" << std::endl;
		return false;
	}

	for (size_t i = 0; i < actual.segment_lists.size(); ++i) {
		const auto &actual_list = actual.segment_lists[i];
		const auto &expected_list = expected.segment_lists[i];

		if (!compare_segment_list(actual_list, expected_list)) {
			std::cout << "Mismatch at " << i
				  << "-th segment_list, name "
				  << actual_list.name << " & "
				  << expected_list.name << std::endl;
			return false;
		}
	}

	// Compare policies
	if (actual.policies.size() != expected.policies.size()) {
		std::cout << "Mismatch: policies count ("
			  << actual.policies.size() << " vs "
			  << expected.policies.size() << ")" << std::endl;
		return false;
	}

	for (size_t i = 0; i < actual.policies.size(); ++i) {
		const auto &actual_policy = actual.policies[i];
		const auto &expected_policy = expected.policies[i];

		if (!compare_policy(actual_policy, expected_policy)) {
			std::cout << "Mismatch at " << i
				  << "-th policy, endpoint="
				  << actual_policy.endpoint
				  << ", color=" << actual_policy.color
				  << std::endl;
			return false;
		}
	}

	return true;
}

bool compare_dumped_pathd_state(const struct pathd_state_t &expected)
{
	struct pathd_state_t actual = dump_pathd_state();
	return compare_pathd_state(actual, expected);
}

/*
 * pathd initial state setup
 * */
static int setup_segment_list(const struct segment_list_t &segment_list)
{
	int ret = api_segment_list(segment_list.name);
	if (ret != 0) {
		std::cout << "api_segment_list: failed" << std::endl;
		return ret;
	}
	srte_apply_changes();

	for (const auto &segment : segment_list.segments) {
		ret = api_segment_list_segment(segment_list.name, segment.index,
					       segment.v6Address);
		if (ret != 0) {
			std::cout
				<< "api_segment_list_segment: failed at index "
				<< segment.index << std::endl;
			return ret;
		}
		srte_apply_changes();
	}

	return ret;
}

static int setup_policy(const struct path_policy_t &policy)
{
	// Create the base policy
	int ret = api_srte_policy(policy.color, policy.endpoint);
	if (ret != 0) {
		std::cerr << "Failed to create policy: color=" << policy.color
			  << ", endpoint=" << policy.endpoint << std::endl;
		return ret;
	}
	wrapper_apply_changes();

	// Add each candidate path
	for (const auto &candidate : policy.candidate_paths) {
		struct PolicyCandidatePathParams param = {
			policy.color,
			policy.endpoint,
			candidate.preference,
			candidate.candidate_name,
			candidate.segment_list_name,
			1 // weight (default
			  // value as per
			  // test examples)
		};


		ret = api_srte_policy_candidate_path(
			policy.color, policy.endpoint, candidate.preference,
			candidate.candidate_name, candidate.segment_list_name);
		if (ret != 0) {
			std::cerr << "Failed to add candidate path '"
				  << candidate.candidate_name
				  << "' to policy: color=" << policy.color
				  << ", endpoint=" << policy.endpoint
				  << std::endl;
			return ret;
		}
		wrapper_apply_changes();
	}
	return 0;
}

int setup_pathd_state(const struct pathd_state_t &state)
{
	int ret;
	for (const auto &segment_list : state.segment_lists) {
		ret = setup_segment_list(segment_list);
		if (ret != 0) {
			GTEST_LOG_(ERROR)
				<< "setup_segment_list: failed at segment_list "
				<< segment_list.name;
			return ret;
		}
	}

	// Setup policies
	for (const auto &policy : state.policies) {
		ret = setup_policy(policy);
		if (ret != 0) {
			GTEST_LOG_(ERROR)
				<< "setup_policy: failed for policy with endpoint "
				<< policy.endpoint << " and color "
				<< policy.color;
			return ret;
		}
	}

	if (compare_dumped_pathd_state(state)) {
		GTEST_LOG_(INFO)
			<< "============== setup_pathd_state validated ===============";
		return 0;
	} else {
		GTEST_LOG_(ERROR)
			<< "============== setup_pathd_state failed ===============";
		return -1;
	}
}
