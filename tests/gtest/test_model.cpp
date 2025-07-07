#include "test_model.h"

#include <iostream>
#include <cstring>
#include <map>
#include <gtest/gtest.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <json-c/json.h>
#include <arpa/inet.h>

#ifdef __cplusplus
}
#endif

#include "lib/zclient.h"


using namespace std;

static void parse_json_sidlist(json_object *obj, srv6_sidlist_t *res)
{
	json_object_object_foreach(obj, key, val)
	{
		if (strcmp(key, "Name") == 0) {
			res->sidlist_name = json_object_get_string(val);
		} else if (strcmp(key, "Weight") == 0) {
			res->weight = json_object_get_int(val);
		} else if (strcmp(key, "Srv6SidListBackup") == 0) {
			if (json_object_get_int(val) == 1)
				res->flags |= SRV6_SID_LIST_BACKUP;
		} else if (strcmp(key, "Segment") == 0) {
			// skip for now
		} else {
			std::cerr << "Unhandled key in SIDLIST JSON: " << key
				  << std::endl;
		}
	}
}


static void parse_json_ipv6_prefix(const char *str, prefix_t *prefix)
{
	char buffer[64];
	strncpy(buffer, str, 64);

	// We assume an individual address by default
	prefix->prefixlen = 128;
	char *slash = strchr(buffer, '/');
	if (slash) {
		prefix->prefixlen = std::stoi(slash + 1);
		*slash = '\0';
	}
	inet_pton(AF_INET6, buffer, prefix->endpoint);
}


static void parse_json_input_policy(json_object *obj, api_policy_t *res)
{
	json_object_object_foreach(obj, key, val)
	{
		if (strcmp(key, "Color") == 0) {
			res->color = json_object_get_int64(val);
		} else if (strcmp(key, "Endpoint") == 0) {
			parse_json_ipv6_prefix(json_object_get_string(val),
					       &res->endpoint);
		} else if (strcmp(key, "Srv6Tunnel") == 0) {
			if (json_object_is_type(val, json_type_array)) {
				size_t path_num = json_object_array_length(val);
				for (int i = 0; i < path_num; i++) {
					res->sidlists.push_back({});
					parse_json_sidlist(
						json_object_array_get_idx(val,
									  i),
						&res->sidlists[i]);
				}
			}
		} else {
			std::cerr << "Unhandled key in API_POLICY JSON: " << key
				  << std::endl;
		}
	}
}


static int interpret_policy_status(const char *s)
{
	static std::map<std::string, int> status_map = {
		{"INIT", 0}, {"DOWN", 1}, {"UP", 2}};

	std::string sstr(s);
	auto it = status_map.find(sstr);
	if (it != status_map.end()) {
		return it->second;
	} else {
		std::cerr << "Unknown policy status " << sstr << std::endl;
		return -1;
	}
}


static void parse_json_rnh(json_object *obj, rnh_t &res)
{
	json_object_object_foreach(obj, key, val)
	{
		if (strcmp(key, "Prefix") == 0) {
			parse_json_ipv6_prefix(json_object_get_string(val),
					       &res.prefix);
		} else if (strcmp(key, "ResolvedRoute") == 0) {
			parse_json_ipv6_prefix(json_object_get_string(val),
					       &res.resolved_route);
		} else if (strcmp(key, "Color") == 0) {
			res.srte_color = json_object_get_int64(val);
		} else {
			std::cerr << "Unhandled key in RNH JSON: " << key
				  << std::endl;
		}
	}
}


static void parse_json_zebra_policy(json_object *obj, policy_t *res)
{
	json_object_object_foreach(obj, key, val)
	{
		if (strcmp(key, "Color") == 0) {
			res->color = json_object_get_int64(val);
		} else if (strcmp(key, "PolicyTableKey") == 0) {
			parse_json_ipv6_prefix(json_object_get_string(val),
					       &res->policy_table_key);
		} else if (strcmp(key, "Status") == 0) {
			int status_value = interpret_policy_status(
				json_object_get_string(val));
			if (status_value >= 0) {
				res->status = static_cast<policy_status_t>(
					status_value);
			}
		} else if (strcmp(key, "Srv6SegmentList") == 0) {
			size_t sidlist_num = json_object_array_length(val);
			for (int i = 0; i < sidlist_num; i++) {
				res->segment_list.push_back({});
				parse_json_sidlist(
					json_object_array_get_idx(val, i),
					&res->segment_list[i]);
			}
		} else if (strcmp(key, "Nht") == 0) {
			size_t nht_num = json_object_array_length(val);
			for (int i = 0; i < nht_num; i++) {
				res->nht.push_back({});
				parse_json_rnh(
					json_object_array_get_idx(val, i),
					res->nht.back());
			}
		} else {
			std::cerr << "Unhandled key in POLICY JSON: " << key
				  << std::endl;
		}
	}
}


static void parse_json_srte_table(json_object *obj, srte_table_t *res)
{
	json_object_object_foreach(obj, key, val)
	{
		if (strcmp(key, "Color") == 0) {
			res->color = json_object_get_int64(val);
		} else if (strcmp(key, "Table") == 0) {
			json_object_object_foreach(val, table_key, table_val)
			{
				if (strcmp(table_key, "Policies") == 0) {
					size_t policy_num =
						json_object_array_length(
							table_val);
					for (int i = 0; i < policy_num; i++) {
						res->policies.push_back({});
						parse_json_zebra_policy(
							json_object_array_get_idx(
								table_val, i),
							&res->policies[i]);
					}
				} else {
					std::cerr
						<< "Unhandled key in SRTE_TABLE.TABLE JSON: "
						<< key << std::endl;
				}
			}
		} else {
			std::cerr << "Unhandled key in SRTE_TABLE JSON: " << key
				  << std::endl;
		}
	}
}


static void parse_json_nexthop(json_object *obj, nexthop_t *res)
{
	json_object_object_foreach(obj, key, val)
	{
		if (strcmp(key, "SrteColor") == 0) {
			res->color = json_object_get_int64(val);
		} else if (strcmp(key, "GateIpv6") == 0) {
			struct prefix_t p;
			parse_json_ipv6_prefix(json_object_get_string(val), &p);
			if (p.prefixlen != 128) {
				std::cout << "Nexthop p.prefixLen changed from "
					  << p.prefixlen << " to 128"
					  << std::endl;
				p.prefixlen = 128;
			}
			std::memcpy(res->gate, p.endpoint, sizeof(res->gate));
		} else if (strcmp(key, "SidlistName") == 0) {
			res->sidlist_name = json_object_get_string(val);
		} else if (strcmp(key, "NexthopFlagIsBackup") == 0) {
			if (json_object_get_int(val) == 1)
				res->flags |= NEXTHOP_FLAG_IS_BACKUP;
		} else if (strcmp(key, "Resolved") == 0) {
			size_t resolved_num = json_object_array_length(val);
			for (int i = 0; i < resolved_num; i++) {
				res->resolved.push_back({});
				parse_json_nexthop(
					json_object_array_get_idx(val, i),
					&res->resolved[i]);
			}
		} else {
			std::cerr
				<< "Unhandled key in ZEBRA_STATE JSON: " << key
				<< std::endl;
		}
	}
}


static void parse_json_nhg_entry(json_object *obj, nhg_t &res)
{
	json_object_object_foreach(obj, key, val)
	{
		if (strcmp(key, "Nexthop") == 0 ||
		    strcmp(key, "Nexthops") == 0) {
			if (json_object_is_type(val, json_type_array)) {
				int nexthop_num = json_object_array_length(val);
				for (int i = 0; i < nexthop_num; i++) {
					res.resolved_nexthops.push_back({0});
					parse_json_nexthop(
						json_object_array_get_idx(val,
									  i),
						&res.resolved_nexthops[i]);
				}
			} else {
				res.resolved_nexthops.push_back({0});
				parse_json_nexthop(val,
						   &res.resolved_nexthops[0]);
			}
		} else if (strcmp(key, "SegDepends") == 0) {
			size_t depends_num = json_object_array_length(val);
			for (int i = 0; i < depends_num; i++) {
				res.seg_depends.emplace_back();
				parse_json_nhg_entry(
					json_object_array_get_idx(val, i),
					res.seg_depends[i]);
			}
		} else if (strcmp(key, "SegDependsID") == 0) {
			size_t depends_num = json_object_array_length(val);
			for (int i = 0; i < depends_num; i++) {
				struct json_object *element =
					json_object_array_get_idx(val, i);
				int v = json_object_get_int(element);
				res.shared_seg_depends.push_back(v);
			}
		} else if (strcmp(key, "ID") == 0) {
			int id = json_object_get_int(val);
			res.contains_id = true;
			res.internal_id = id;
		} else {
			std::cerr << "Unhandled key in NHG_ENTRY JSON: " << key
				  << std::endl;
		}
	}
}


static void parse_json_rnh_route_node_list(json_object *obj, rnh_list_t &res)
{
	struct json_object *rnh_array;
	EXPECT_TRUE(json_object_object_get_ex(obj, "RnhList", &rnh_array));

	size_t rnh_num = json_object_array_length(rnh_array);
	for (int j = 0; j < rnh_num; j++) {
		res.rnh.push_back({});
		parse_json_rnh(json_object_array_get_idx(rnh_array, j),
			       res.rnh[j]);
	}

	struct json_object *prefix_object;
	EXPECT_TRUE(json_object_object_get_ex(obj, "Prefix", &prefix_object));
	parse_json_ipv6_prefix(json_object_get_string(prefix_object),
			       &res.prefix);
}


static void parse_json_route_nexthops_t(json_object *obj, nhe_t *res)
{
	prefix_t prefix;
	json_object_object_foreach(obj, key, val)
	{
		if (strcmp(key, "SrteColor") == 0) {
			res->color = json_object_get_int64(val);
		} else if (strcmp(key, "GateIpv6") == 0) {
			parse_json_ipv6_prefix(json_object_get_string(val),
					       &prefix);
			std::memcpy(res->gate, prefix.endpoint, 16);
		} else {
			std::cerr << "Unhandled key in route_nexthops JSON: "
				  << key << std::endl;
		}
	}
}
static void parse_json_input_routeadd(json_object *obj, api_route_t *res)
{
	json_object_object_foreach(obj, key, val)
	{
		if (strcmp(key, "RoutePrefix") == 0) {
			parse_json_ipv6_prefix(json_object_get_string(val),
					       &res->prefix);
		} else if (strcmp(key, "NexthopTops") == 0) {
			size_t nexthop_num = json_object_array_length(val);
			for (int i = 0; i < nexthop_num; i++) {
				res->route_entry.push_back({});
				parse_json_route_nexthops_t(
					json_object_array_get_idx(val, i),
					&res->route_entry.back());
			}
		} else {
			std::cerr
				<< "Unhandled key in INPUT ROUTE JSON: " << key
				<< std::endl;
		}
	}
}
static void parse_json_input_routedel(json_object *obj, api_route_del_t *res)
{
	json_object_object_foreach(obj, key, val)
	{
		if (strcmp(key, "RoutePrefix") == 0) {
			parse_json_ipv6_prefix(json_object_get_string(val),
					       &res->prefix);
		} else {
			std::cerr
				<< "Unhandled key in INPUT ROUTE JSON: " << key
				<< std::endl;
		}
	}
}

static void parse_json_zebra_state(json_object *obj, zebra_state_t *res)
{
	json_object_object_foreach(obj, key, val)
	{
		if (strcmp(key, "PolicyRouteTable") == 0) {
			size_t length = json_object_array_length(val);
			for (int i = 0; i < length; i++) {
				res->policy_route_table.push_back({});
				parse_json_srte_table(
					json_object_array_get_idx(val, i),
					&res->policy_route_table[i]);
			}
		} else if (strcmp(key, "Nhgs") == 0) {
			size_t length = json_object_array_length(val);
			for (int i = 0; i < length; i++) {
				res->nhgs.emplace_back();
				parse_json_nhg_entry(
					json_object_array_get_idx(val, i),
					res->nhgs[i]);
			}
		} else if (strcmp(key, "Rnhs") == 0) {
			size_t length = json_object_array_length(val);
			for (int i = 0; i < length; i++) {
				res->rnh_table.push_back({});
				parse_json_rnh_route_node_list(
					json_object_array_get_idx(val, i),
					res->rnh_table[i]);
			}
		} else if (strcmp(key, "RouteNhgMaps") == 0) {
			size_t route_num = json_object_array_length(val);
			for (int j = 0; j < route_num; j++) {
				res->rib.push_back({});
				parse_json_input_routeadd(
					json_object_array_get_idx(val, j),
					&res->rib[j]);
			}
		} else {
			std::cerr
				<< "Unhandled key in ZEBRA_STATE JSON: " << key
				<< std::endl;
		}
	}
}

static void parse_json_msg_nexthop_update(json_object *obj,
					  struct msg_nexthop_update_t &res)
{
	json_object_object_foreach(obj, key, val)
	{
		if (strcmp(key, "MatchPrefix") == 0) {
			parse_json_ipv6_prefix(json_object_get_string(val),
					       &res.match);
		} else if (strcmp(key, "NhrPrefix") == 0) {
			parse_json_ipv6_prefix(json_object_get_string(val),
					       &res.nhr.prefix);
		} else if (strcmp(key, "NhrColor") == 0) {
			res.nhr.srte_color = json_object_get_int64(val);
		} else if (strcmp(key, "Nexthops") == 0) {
			int size = json_object_array_length(val);
			for (int i = 0; i < size; i++) {
				struct nexthop_t nh = {};
				parse_json_nexthop(
					json_object_array_get_idx(val, i), &nh);

				struct nhe_t nhe = {};
				std::memcpy(nhe.gate, nh.gate, 16);
				nhe.color = nh.color;
				res.nhr.route_entry.push_back(nhe);
			}
		} else {
			std::cerr << "Unhandled key in Msg.NexthopUpdate JSON: "
				  << key << std::endl;
		}
	}
}

static void parse_json_policy_notify(json_object *obj,
				     struct msg_policy_status_t &res)
{
	json_object_object_foreach(obj, key, val)
	{
		if (strcmp(key, "Status") == 0) {
			res.status = json_object_get_int(val);
		} else if (strcmp(key, "Prefix") == 0) {
			parse_json_ipv6_prefix(json_object_get_string(val),
					       &res.prefix);
		} else if (strcmp(key, "Color") == 0) {
			res.color = json_object_get_int64(val);
		} else {
			std::cerr << "Unhandled key in Msg.PolicyNotify JSON: "
				  << key << std::endl;
		}
	}
}

static std::vector<struct msg_t>
parse_json_msg_fifo(json_object *json_msg_array)
{
	std::vector<struct msg_t> res;

	for (int i = 0; i < json_object_array_length(json_msg_array); i++) {
		struct msg_t msg = {};
		json_object *json_msg =
			json_object_array_get_idx(json_msg_array, i);

		json_object *cmd;
		if (json_object_object_get_ex(json_msg, "Command", &cmd)) {
			msg.command = json_object_get_int(cmd);
		} else {
			std::cerr << "Key 'Command' not found in MsgFifo JSON: "
				  << std::endl;
			continue;
		}

		json_object *data;
		if (msg.command == ZEBRA_NEXTHOP_UPDATE) {
			json_object_object_get_ex(json_msg, "NexthopUpdate",
						  &data);
			parse_json_msg_nexthop_update(data, msg.nexthop_update);
		} else if (msg.command == ZEBRA_SR_POLICY_NOTIFY_STATUS) {
			json_object_object_get_ex(json_msg, "PolicyNotify",
						  &data);
			parse_json_policy_notify(data,
						 msg.policy_notify_status);
		} else {
			std::cerr << "Unhandled command in MsgFifo JSON: "
				  << msg.command << std::endl;
		}

		res.push_back(msg);
	}

	return res;
}


static json_object *load_json_object(const std::string &json_file_path)
{
	json_object *jobj = json_object_from_file(json_file_path.c_str());
	if (jobj == nullptr) {
		std::cerr << "Failed to load json_object from file: "
			  << json_file_path << std::endl;
		return nullptr;
	}

	if (!json_object_is_type(jobj, json_type_array)) {
		std::cerr << "Expected a JSON array in file " << json_file_path
			  << std::endl;
		json_object_put(jobj);
		return nullptr;
	}

	return jobj;
}


std::map<int, test_case_policy_set_del_t>
read_policy_set_del_test_cases_map(const std::string &json_file_path)
{
	std::map<int, test_case_policy_set_del_t> res;

	json_object *jobj = load_json_object(json_file_path);
	size_t test_num = json_object_array_length(jobj);
	for (int i = 0; i < test_num; i++) {
		json_object *json_test_case =
			json_object_array_get_idx(jobj, i);
		test_case_policy_set_del_t test_case = {0};

		json_object_object_foreach(json_test_case, key, val)
		{
			if (strcmp(key, "TestId") == 0) {
				test_case.test_id = json_object_get_int(val);
			} else if (strcmp(key, "InitialState") == 0) {
				parse_json_zebra_state(
					val, &test_case.initial_state);
			} else if (strcmp(key, "Policy") == 0) {
				parse_json_input_policy(
					val, &test_case.input_policy);
			} else if (strcmp(key, "FinalState") == 0) {
				parse_json_zebra_state(val,
						       &test_case.final_state);
			} else if (strcmp(key, "MsgFifo") == 0) {
				test_case.msg_fifo = parse_json_msg_fifo(val);
			} else {
				std::cerr << "Unhandled key in TestCase JSON: "
					  << key << std::endl;
			}
		}
		res[test_case.test_id] = test_case;
	}

	return res;
}


/*
 * Returns an empty vector if errors occur.
 * */
std::vector<test_case_policy_set_del_t>
read_all_test_cases_policy_set_del(const std::string &json_file_path)
{
	std::vector<test_case_policy_set_del_t> res;

	std::map<int, test_case_policy_set_del_t> cases_map =
		read_policy_set_del_test_cases_map(json_file_path);
	for (auto const &pair : cases_map) {
		res.push_back(pair.second);
	}

	std::cout << "Loaded " << res.size() << " test cases from "
		  << json_file_path << std::endl;

	return res;
}


/*
 * Returns an empty vector if errors occur.
 * */
std::vector<test_case_route_add_t>
read_all_test_cases_route_add(const std::string &json_file_path)
{
	std::vector<test_case_route_add_t> res;

	json_object *jobj = load_json_object(json_file_path);
	size_t test_num = json_object_array_length(jobj);
	for (int i = 0; i < test_num; i++) {
		json_object *json_test_case =
			json_object_array_get_idx(jobj, i);
		test_case_route_add_t test_case = {0};

		json_object_object_foreach(json_test_case, key, val)
		{
			if (strcmp(key, "TestId") == 0) {
				test_case.test_id = json_object_get_int(val);
			} else if (strcmp(key, "InitialState") == 0) {
				parse_json_zebra_state(
					val, &test_case.initial_state);
			} else if (strcmp(key, "RouteAdd") == 0) {
				parse_json_input_routeadd(
					val, &test_case.input_route);
			} else if (strcmp(key, "FinalState") == 0) {
				parse_json_zebra_state(val,
						       &test_case.final_state);
			} else if (strcmp(key, "MsgFifo") == 0) {
				test_case.msg_fifo = parse_json_msg_fifo(val);
			} else {
				std::cerr << "Unhandled key in TestCase JSON: "
					  << key << std::endl;
			}
		}
		res.push_back(test_case);
	}
	return res;
}

/*
 * Returns an empty vector if errors occur.
 * */
std::vector<test_case_route_del_t>
read_all_test_cases_route_del(const std::string &json_file_path)
{
	std::vector<test_case_route_del_t> res;

	json_object *jobj = json_object_from_file(json_file_path.c_str());
	if (jobj == nullptr) {
		std::cerr << "Failed to load json_object from file: "
			  << json_file_path << std::endl;
		return res;
	}

	if (!json_object_is_type(jobj, json_type_array)) {
		std::cerr << "Expected a JSON array in file " << json_file_path
			  << std::endl;
		json_object_put(jobj);
		return res;
	}

	size_t test_num = json_object_array_length(jobj);
	for (int i = 0; i < test_num; i++) {
		json_object *json_test_case =
			json_object_array_get_idx(jobj, i);
		test_case_route_del_t test_case = {0};

		json_object_object_foreach(json_test_case, key, val)
		{
			if (strcmp(key, "TestId") == 0) {
				test_case.test_id = json_object_get_int(val);
			} else if (strcmp(key, "InitialState") == 0) {
				parse_json_zebra_state(
					val, &test_case.initial_state);
			} else if (strcmp(key, "RouteDel") == 0) {
				parse_json_input_routedel(
					val, &test_case.input_route);
			} else if (strcmp(key, "FinalState") == 0) {
				parse_json_zebra_state(val,
						       &test_case.final_state);
			} else if (strcmp(key, "MsgFifo") == 0) {
				test_case.msg_fifo = parse_json_msg_fifo(val);
			} else {
				std::cerr << "Unhandled key in TestCase JSON: "
					  << key << std::endl;
			}
		}
		res.push_back(test_case);
	}
	return res;
}

static void parse_json_input_rnh(json_object *obj, struct rnh_t &res)
{
	json_object_object_foreach(obj, key, val)
	{
		if (strcmp(key, "Color") == 0) {
			res.srte_color = json_object_get_int64(val);
		} else if (strcmp(key, "ResolvedRoute") == 0) {
			parse_json_ipv6_prefix(json_object_get_string(val),
					       &res.resolved_route);
		} else {
			std::cerr << "Unhandled key in INPUT_RNH JSON: " << key
				  << std::endl;
		}
	}
}

static void parse_json_api_rnh(json_object *obj, struct api_rnh_t &res)
{
	json_object_object_foreach(obj, key, val)
	{
		if (strcmp(key, "Color") == 0) {
			res.srte_color = json_object_get_int64(val);
		} else if (strcmp(key, "Prefix") == 0) {
			parse_json_ipv6_prefix(json_object_get_string(val),
					       &res.prefix);
		} else {
			std::cerr << "Unhandled key in API_RNH JSON: " << key
				  << std::endl;
		}
	}
}

std::map<int, test_case_rnh_register>
read_all_test_cases_nexthop_register(const std::string &json_file_path)
{
	std::map<int, test_case_rnh_register> res;

	json_object *jobj = load_json_object(json_file_path);
	size_t test_num = json_object_array_length(jobj);
	for (int i = 0; i < test_num; i++) {
		json_object *json_test_case =
			json_object_array_get_idx(jobj, i);
		test_case_rnh_register test_case = {0};

		json_object_object_foreach(json_test_case, key, val)
		{
			if (strcmp(key, "TestId") == 0) {
				test_case.test_id = json_object_get_int(val);
			} else if (strcmp(key, "InitialState") == 0) {
				parse_json_zebra_state(
					val, &test_case.initial_state);
			} else if (strcmp(key, "InputRnh") == 0) {
				parse_json_api_rnh(val, test_case.input_rnh);
			} else if (strcmp(key, "FinalState") == 0) {
				parse_json_zebra_state(val,
						       &test_case.final_state);
			} else if (strcmp(key, "MsgFifo") == 0) {
				test_case.msg_fifo = parse_json_msg_fifo(val);
			} else {
				std::cerr << "Unhandled key in TestCase JSON: "
					  << key << std::endl;
			}
		}
		res[test_case.test_id] = test_case;
	}

	return res;
}

std::vector<test_case_rnh_register>
read_test_case_rnh_register_vec(const std::string &json_file_path)
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

std::string prefix_t2str(const struct prefix_t &p)
{
	char buffer[INET6_ADDRSTRLEN];
	if (p.family == AF_INET) {
		inet_ntop(AF_INET, &p.endpoint, buffer, sizeof(buffer));
		return std::string(buffer) + "/" + std::to_string(p.prefixlen);
	} else {
		inet_ntop(AF_INET6, &p.endpoint, buffer, sizeof(buffer));
		return std::string(buffer) + "/" + std::to_string(p.prefixlen);
	}
}

/*
 * Printing functions mainly for debugging
 * */
static void print_nexthop(const struct nexthop_t &n, int level)
{
	char gate_str[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &n.gate, gate_str, sizeof(gate_str));

	cout << " " << string((level + 1) * 2, '-') << " nexthop"
	     << " gate: " << gate_str << " color: " << n.color
	     << " sidlist_name: " << n.sidlist_name << " flags: 0x" << std::hex
	     << n.flags << std::dec << endl;

	for (auto &r : n.resolved) {
		print_nexthop(r, level + 1);
	}
}

void print_nexthops(const struct nexthop_t &n)
{
	print_nexthop(n, 0);
}

void print_nhe(const struct nhe_t &nhe)
{
	char gate_str[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &nhe.gate, gate_str, sizeof(gate_str));

	cout << "nhe " << gate_str << " color " << nhe.color << endl;
}

void print_api_policy(const struct api_policy_t &api_policy)
{
	char buffer[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &api_policy.endpoint.endpoint, buffer,
		  sizeof(buffer));
	std::cout << "api_policy endpoint " << buffer << "/"
		  << api_policy.endpoint.prefixlen << " color "
		  << api_policy.color << endl;
	for (auto const &sidlist : api_policy.sidlists) {
		std::cout << "  -- sidlist " << sidlist.sidlist_name
			  << " weight " << static_cast<int>(sidlist.weight)
			  << endl;
	}
}

void print_api_rnh(const struct api_rnh_t &rnh)
{
	char ipv6[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, rnh.prefix.endpoint, ipv6, sizeof(ipv6));

	std::cout << "api_rnh prefix " << ipv6 << "/" << rnh.prefix.prefixlen
		  << " color " << rnh.srte_color << endl;
}

// Route prefixes are IPv6
void print_api_route(const struct api_route_t &route)
{
	char ipv6[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, route.prefix.endpoint, ipv6, sizeof(ipv6));

	std::cout << "api_route " << ipv6 << "/" << route.prefix.prefixlen;
	for (const auto &nhe : route.route_entry) {
		char gate_str[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, nhe.gate, gate_str, sizeof(gate_str));
		std::cout << " -- gate " << gate_str << " color " << nhe.color;
	}
	std::cout << std::endl;
}

void print_api_route_del(const struct api_route_del_t &route)
{
	char ipv6[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, route.prefix.endpoint, ipv6, sizeof(ipv6));

	std::cout << "api_route " << ipv6 << "/" << route.prefix.prefixlen;
	std::cout << std::endl;
}
/*
 * Multi-step test case
 * */

static void parse_json_input_action(json_object *obj,
				    struct step_action_t &step)
{
	json_object_object_foreach(obj, key, val)
	{
		if (strcmp(key, "Action") == 0) {
			const char *action_name = json_object_get_string(val);
			if (strcmp(action_name, "POLICY_DEL") == 0) {
				step.action = Action::POLICY_DEL;
			} else if (strcmp(action_name, "POLICY_SET") == 0) {
				step.action = Action::POLICY_SET;
			} else if (strcmp(action_name, "ROUTE_ADD") == 0) {
				step.action = Action::ROUTE_ADD;
			} else if (strcmp(action_name, "ROUTE_DEL") == 0) {
				step.action = Action::ROUTE_DEL;
			} else if (strcmp(action_name, "RNH_REGISTER") == 0) {
				step.action = Action::RNH_REGISTER;
			} else if (strcmp(action_name, "RNH_UNREGISTER") == 0) {
				step.action = Action::RNH_UNREGISTER;
			} else {
				std::cerr << "Unrecognized Action key in JSON: "
					  << action_name << std::endl;
				return;
			}
		} else if (strcmp(key, "Policy") == 0) {
			parse_json_input_policy(val, &step.input_policy);
		} else if (strcmp(key, "InputRnh") == 0) {
			parse_json_input_rnh(val, step.input_rnh);
		} else if (strcmp(key, "Route") == 0) {
			parse_json_input_routeadd(val, &step.input_route);
		} else {
			std::cerr << "Unhandled key in TestCase JSON: " << key
				  << std::endl;
		}
	}
}

std::map<int, multi_test_case_t>
read_multi_test_cases_map(const std::string &json_file_path)
{
	std::map<int, multi_test_case_t> res;

	json_object *jobj = load_json_object(json_file_path);
	size_t test_num = json_object_array_length(jobj);
	for (int i = 0; i < test_num; i++) {
		json_object *json_test_case =
			json_object_array_get_idx(jobj, i);
		multi_test_case_t test_case = {0};

		json_object_object_foreach(json_test_case, key, val)
		{
			if (strcmp(key, "TestId") == 0) {
				test_case.test_id = json_object_get_int(val);
			} else if (strcmp(key, "InitialState") == 0) {
				parse_json_zebra_state(
					val, &test_case.initial_state);
			} else if (strcmp(key, "InputActions") == 0) {
				size_t action_num =
					json_object_array_length(val);
				for (int i = 0; i < action_num; i++) {
					test_case.input_actions.push_back({});
					parse_json_input_action(
						json_object_array_get_idx(val,
									  i),
						test_case.input_actions.back());
				}
			} else if (strcmp(key, "FinalState") == 0) {
				parse_json_zebra_state(val,
						       &test_case.final_state);
			} else {
				std::cerr << "Unhandled key in TestCase JSON: "
					  << key << std::endl;
			}
		}
		res[test_case.test_id] = test_case;
	}

	return res;
}


std::vector<multi_test_case_t>
read_multi_test_cases_vec(const std::string &json_file_path)
{
	std::vector<multi_test_case_t> res;

	std::map<int, multi_test_case_t> cases_map =
		read_multi_test_cases_map(json_file_path);
	for (auto const &pair : cases_map) {
		res.push_back(pair.second);
	}

	std::cout << "Loaded " << res.size() << " test cases from "
		  << json_file_path << std::endl;

	return res;
}
