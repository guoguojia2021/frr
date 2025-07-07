#include "zebra_utils.h"

#include <gtest/gtest.h>
#include <iostream>
#include <string>

#include "lib/hash.h"
#include "lib/nexthop.h"
#include "lib/zclient.h"
#include "libfrr.h"

#include "zebra.h"
#include "zebra/debug.h"
#include "zebra/router-id.h"
#include "zebra/table_manager.h"
#include "zebra/zapi_msg.h"
#include "zebra/zebra_mpls.h"
#include "zebra/zebra_nhg.h"
#include "zebra/zebra_nhg_private.h"
#include "zebra/zebra_rnh.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_srte.h"
#include "zebra/zebra_vxlan.h"

#include "test_model.h"
#include "common_utils.h"
#include "nhg_utils.h"
#include "policy_utils.h"
#include "rnh_utils.h"
#include "rib_utils.h"
#include "msg_utils.h"


extern long zebra_config_fib_max;

static struct zebra_vrf *zvrf;
static struct zserv gtest_client;

void gtest_policy_set(const api_policy_t &policy)
{
	struct zapi_sr_policy zp = {};
	int ret = policy_utils.get_input_policy_from_case_api_policy_t(&zp,
								       &policy);
	EXPECT_EQ(ret, 0);
	struct stream *s = policy_utils.fill_stream_with_policy(&zp);
	EXPECT_NE(s, nullptr);

	std::cout << "Calling zread_srv6_policy_set: color " << policy.color
		  << " prefix "
		  << common_utils::addr2str(policy.endpoint.endpoint) << "/"
		  << policy.endpoint.prefixlen << std::endl
		  << " -- segment_list ";
	for (const auto &sl : policy.sidlists) {
		std::cout << "(" << sl.sidlist_name << ", weight "
			  << (int)(sl.weight) << ", flags " << std::hex
			  << sl.flags << std::dec << ") ";
	}
	std::cout << std::endl;
	zread_srv6_policy_set(&gtest_client, NULL, s, zvrf);
}

void gtest_policy_del(const api_policy_t &policy)
{
	struct zapi_sr_policy zp = {};
	int ret = policy_utils.get_input_policy_from_case_api_policy_t(&zp,
								       &policy);
	EXPECT_EQ(ret, 0);
	struct stream *s = policy_utils.fill_stream_with_policy(&zp);
	EXPECT_NE(s, nullptr);

	std::cout << "Calling zread_srv6_policy_delete: color " << policy.color
		  << " prefix "
		  << common_utils::addr2str(policy.endpoint.endpoint) << "/"
		  << policy.endpoint.prefixlen << std::endl;
	zread_srv6_policy_delete(&gtest_client, NULL, s, zvrf);
}

void gtest_rnh_register(const struct api_rnh_t &rnh)
{
	std::cout << "Calling zread_rnh_register ";
	print_api_rnh(rnh);

	struct prefix p = {};
	int ret = common_utils::prefix_t2prefix(&rnh.prefix, &p);
	EXPECT_EQ(ret, 0);

	struct stream *s = RnhUtils::fill_stream_with_rnh(
		ZEBRA_NEXTHOP_REGISTER, &p, rnh.srte_color);
	EXPECT_NE(s, nullptr);

	struct zmsghdr hdr = {};
	zapi_parse_header(s, &hdr);
	hdr.length -= ZEBRA_HEADER_SIZE;

	zread_rnh_register(&gtest_client, &hdr, s, zvrf);
}

void gtest_rnh_unregister(const struct api_rnh_t &rnh)
{
	std::cout << "Calling zread_rnh_unregister ";
	print_api_rnh(rnh);

	struct prefix p = {};
	int ret = common_utils::prefix_t2prefix(&rnh.prefix, &p);
	EXPECT_EQ(ret, 0);

	struct stream *s = RnhUtils::fill_stream_with_rnh(
		ZEBRA_NEXTHOP_UNREGISTER, &p, rnh.srte_color);
	EXPECT_NE(s, nullptr);

	struct zmsghdr hdr = {};
	zapi_parse_header(s, &hdr);
	hdr.length -= ZEBRA_HEADER_SIZE;

	zread_rnh_unregister(&gtest_client, &hdr, s, zvrf);
}

void gtest_route_add(const api_route_t &route)
{
	std::cout << "Calling zread_route_add: ";
	print_api_route(route);

	struct zapi_route api_route = RibUtils::get_route_multi_policies(route);
	struct stream *s = RibUtils::fill_stream_with_route(&api_route);
	EXPECT_NE(s, nullptr);
	zread_route_add(&gtest_client, NULL, s, zvrf);
}

void gtest_route_del(const api_route_t &route)
{
	std::cout << "Calling zread_route_del: ";
	print_api_route(route);

	struct zapi_route api_route = RibUtils::get_route_multi_policies(route);
	struct stream *s = RibUtils::fill_stream_with_route(&api_route);
	EXPECT_NE(s, nullptr);
	zread_route_del(&gtest_client, NULL, s, zvrf);
}

// Provides compatibility for .json both with and without RouteNhgMaps
// TODO: phase out later. RouteNhgMaps should be mandatory
static bool rib_specified;

void setup_zebra_state(const struct zebra_state_t &initial_state)
{
	assert_empty_state();
	std::cout << "=============start from empty state==============="
		  << std::endl;

	rib_specified = true;

	int ret = policy_utils.add_policy_into_srte_table(initial_state);
	EXPECT_EQ(ret, 0);

	std::cout << "=============adding rnhs===============" << std::endl;
	for (const auto &rnh_list : initial_state.rnh_table) {
		struct prefix p;
		int ret = common_utils::prefix_t2prefix(&rnh_list.prefix, &p);
		EXPECT_EQ(ret, 0);

		for (auto it = rnh_list.rnh.crbegin();
		     it != rnh_list.rnh.crend(); it++) {
			std::cout << "Add rnh prefix "
				  << common_utils::addr2str(p.u.val)
				  << " color " << it->srte_color << std::endl;
			struct stream *s = RnhUtils::fill_stream_with_rnh(
				ZEBRA_NEXTHOP_REGISTER, &p, it->srte_color);
			EXPECT_NE(s, nullptr);
			struct zmsghdr hdr;
			zapi_parse_header(s, &hdr);
			hdr.length -= ZEBRA_HEADER_SIZE;
			zread_rnh_register(&gtest_client, &hdr, s, zvrf);
		}
	}

	std::cout << "=============adding routes===============" << std::endl;
	std::vector<struct api_route_t> routes = initial_state.rib;
	if (routes.empty() && !initial_state.nhgs.empty()) {
		std::cout
			<< "Nhgs is non-empty while rib is empty, infer rib information instead."
			<< std::endl;
		rib_specified = false;
		routes = NHGUtils::gen_route_for_nhgs(initial_state.nhgs);
	}

	// add routes
	for (const auto &route : routes) {
		gtest_route_add(route);
	}

	std::cout << "=============clearing obuf_fifo==============="
		  << std::endl;
	std::cout << "Calling stream_fifo_clean_safe on client " << std::hex
		  << std::showbase
		  << reinterpret_cast<std::uintptr_t>(&gtest_client) << std::dec
		  << std::endl;
	stream_fifo_clean_safe(gtest_client.obuf_fifo);

	std::cout << "===========validate initial state============="
		  << std::endl;
	EXPECT_TRUE(compare_zebra_state(initial_state));
}


bool compare_zebra_state(const struct zebra_state_t &expected_state)
{
	std::map<uint32_t, srte_table_t> dump_srte_state;
	hash_iterate(srte_table_hash, dump_srte_hash_bucket, &dump_srte_state);

	std::vector<struct nhg_t> dump_nhg_state = NHGUtils::dump_nhgs();

	const std::vector<struct rnh_list_t> dump_rnh_table =
		RnhUtils::dump_rnh_table();

	const std::vector<struct api_route_t> dump_rib_state =
		RibUtils::dump_rib_state();

	bool res = true;
	if (!PolicyUtils::check_srte_states(dump_srte_state, expected_state)) {
		std::cout << "srte state not match" << std::endl;
		res = false;
	}
	if (!NHGUtils::check_nhg_state(expected_state.nhgs, dump_nhg_state)) {
		std::cout << "nhg state not match" << std::endl;
		res = false;
	}
	if (!RnhUtils::check_rnh_table(dump_rnh_table,
				       expected_state.rnh_table)) {
		std::cout << "rnh_table not match" << std::endl;
		res = false;
	}

	if (rib_specified) {
		if (!RibUtils::check_rib_state(dump_rib_state,
					       expected_state.rib)) {
			std::cout << "rib state not match" << std::endl;
			res = false;
		}
	}

	return res;
}


bool compare_msg_fifo(const std::vector<struct msg_t> &expected_msg_fifo)
{
	std::vector<struct msg_t> dump_msg_fifo = dump_messages(&gtest_client);

	if (expected_msg_fifo.size() != dump_msg_fifo.size()) {
		std::cout << "compare_msg_fifo: expected_msg_fifo size "
			  << expected_msg_fifo.size() << " dump_msg_fifo size "
			  << dump_msg_fifo.size() << std::endl;
		return false;
	}

	for (size_t i = 0; i < expected_msg_fifo.size(); i++) {
		if (!compare_msg_t(dump_msg_fifo[i], expected_msg_fifo[i])) {
			std::cout << "compare_msg_t fails at #" << i
				  << std::endl;
			return false;
		}
	}

	return true;
}


void setup_global_env()
{
	// Needed for nhgs-related test cases
	// Otherwise, zebra_rib.c reports
	// "%%MAXPFXEXCEEDTHRESHOLD: The number of prefixes exceeded the
	// threshold."
	zebra_config_fib_max = 16;

	zebra_srte_init();
}


void setup_env()
{
	vrf_init(gtest_vrf_new, gtest_vrf_enable, gtest_vrf_disable,
		 gtest_vrf_delete);
	zrouter.nhgs =
		hash_create_size(8, zebra_nhg_hash_key, zebra_nhg_hash_equal,
				 "Zebra Router Nexthop Groups");
	zrouter.nhgs_id =
		hash_create_size(8, zebra_nhg_id_key, zebra_nhg_hash_id_equal,
				 "Zebra Router Nexthop Groups ID index");
	zvrf = (zebra_vrf *)vrf_info_lookup(VPN_VRF_ID);
	policy_utils.init();
	policy_utils.set_zvrf(zvrf);
	nhg_utils.init();
	nhg_utils.set_zvrf(zvrf);

	memset(&gtest_client, 0, sizeof(zserv));
	gtest_client.obuf_fifo = stream_fifo_new();
	gtest_client.proto = ZEBRA_ROUTE_SRTE;
	zrouter.client_list = list_new();
	listnode_add(zrouter.client_list, &gtest_client);
}


void teardown_env()
{
	vrf_terminate();
	hash_clean(zrouter.nhgs_id, zebra_nhg_hash_free);
	hash_free(zrouter.nhgs_id);
	hash_clean(zrouter.nhgs, NULL);
	hash_free(zrouter.nhgs);
	struct zebra_router_table *zrt, *tmp;
	RB_FOREACH_SAFE (zrt, zebra_router_table_head, &zrouter.tables, tmp) {
		route_table_finish(zrt->table);
		RB_REMOVE(zebra_router_table_head, &zrouter.tables, zrt);
	}
	hash_iterate(srte_table_hash, free_srte_table_hash, NULL);

	stream_fifo_clean_safe(gtest_client.obuf_fifo);
}


void perform_action(const struct step_action_t &action)
{
	struct stream *s;
	struct prefix p;
	int ret;
	struct zmsghdr hdr;
	switch (action.action) {
	case Action::POLICY_DEL:
		gtest_policy_del(action.input_policy);
		break;
	case Action::POLICY_SET:
		gtest_policy_set(action.input_policy);
		break;
	case Action::RNH_REGISTER:
		ret = common_utils::prefix_t2prefix(
			&action.input_rnh.resolved_route, &p);
		EXPECT_EQ(ret, 0);

		std::cout << "zread_rnh_register issued: color "
			  << action.input_rnh.srte_color << " resolved_route "
			  << common_utils::addr2str(p.u.val) << std::endl;
		s = RnhUtils::fill_stream_with_rnh(ZEBRA_NEXTHOP_REGISTER, &p,
						   action.input_rnh.srte_color);
		EXPECT_NE(s, nullptr);

		zapi_parse_header(s, &hdr);
		zread_rnh_register(&gtest_client, &hdr, s, zvrf);
		break;
	case Action::RNH_UNREGISTER:
		ret = common_utils::prefix_t2prefix(
			&action.input_rnh.resolved_route, &p);
		EXPECT_EQ(ret, 0);

		std::cout << "zread_rnh_unregister issued: color "
			  << action.input_rnh.srte_color << " resolved_route "
			  << common_utils::addr2str(p.u.val) << std::endl;

		s = RnhUtils::fill_stream_with_rnh(ZEBRA_NEXTHOP_UNREGISTER, &p,
						   action.input_rnh.srte_color);
		EXPECT_NE(s, nullptr);

		zapi_parse_header(s, &hdr);
		zread_rnh_unregister(&gtest_client, &hdr, s, zvrf);

		break;
	case Action::ROUTE_ADD:
		gtest_route_add(action.input_route);
		break;
	case Action::ROUTE_DEL:
		gtest_route_del(action.input_route);
		break;
	}
}
