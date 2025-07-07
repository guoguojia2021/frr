/*
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <iostream>
#include <cstring>
#include <filesystem>

#ifdef __cplusplus
extern "C" {
#endif

#include <unistd.h>
#include <limits.h>
#include <arpa/inet.h>

#ifdef __cplusplus
}
#endif

#include <gtest/gtest.h>

#include "zebra.h"
#include "zebra/zebra_nhg.h"
#include "zebra/zebra_nhg_private.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_srte.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zapi_msg.h"
#include "zebra/rib.h"
#include "lib/hash.h"
#include "lib/memory.h"
#include "lib/nexthop.h"
#include "lib/srte.h"
#include "lib/stream.h"
#include "lib/vrf.h"
#include "lib/prefix.h"
#include "lib/typesafe.h"
#include "lib/libfrr.h"
#include "lib/route_types.h"

#include "test_model.h"
#include "test_zread_srv6_policy_delete.h"
#include "policy_utils.h"

#include "nhg_utils.h"

#define VPN_VRF_ID 0


static void zread_srv6_policy_del_inner(struct zapi_sr_policy *zp)
{
	zebra_sr_policy *old_policy =
		zebra_sr_policy_lookup_by_prefix(&zp->endpoint, zp->color);
	if (old_policy) {
		std::cout << "zread_srv6_policy_del issued " << std::endl;
		zebra_sr_policy_delete_by_prefix(old_policy);
	}
}


static void dump_zebra_sr_policy(struct zebra_sr_policy *policy)
{
	std::string status_str[] = {"INIT", "DOWN", "UP"};
	std::cout << " ------ policy.status = " << status_str[policy->status]
		  << std::endl;

	int path_num = policy->srv6_segment_list.path_num;
	std::cout << " ------ policy.srv6_segment_list.path_num = " << path_num
		  << std::endl;
	if (path_num > 0) {
		std::cout << " -------- { ";
		for (int i = 0; i < path_num; i++) {
			std::cout << "("
				  << policy->srv6_segment_list.sidlists[i]
					     .sidlist_name
				  << ", "
				  << (int)policy->srv6_segment_list.sidlists[i]
					     .weight
				  << ") ";
		}
		std::cout << "}" << std::endl;
	}

	struct rnh *rnh;
	char buff[64];
	if (rnh_list_count(&policy->nht) == 0) {
		std::cout << " ------ policy.nht is empty" << std::endl;
	} else {
		frr_each_safe (rnh_list, &policy->nht, rnh) {
			memset(buff, 0, sizeof(buff));
			prefix2str(&rnh->node->p, buff, sizeof(buff));
			std::cout << " -------- policy.nht: rnh.route.prefix "
				  << buff << ", ";
			memset(buff, 0, sizeof(buff));
			prefix2str(&rnh->resolved_route, buff, sizeof(buff));
			std::cout << " rnh.resolved_route " << buff
				  << std::endl;
		}
	}
}


static void dump_nexthop(const struct nexthop *n)
{
	char gate_str[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &n->gate.ipv6, gate_str, INET6_ADDRSTRLEN);

	char seg6_src[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &n->seg6_src, seg6_src, INET6_ADDRSTRLEN);

	char src[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &n->src.ipv6, src, INET6_ADDRSTRLEN);

	std::cout << " -- nexthop " << n << ", type " << n->type << ", ifindex "
		  << n->ifindex << ", flags " << n->flags << ", src " << src
		  << ", gate.ipv6 " << gate_str << ", srte_color "
		  << n->srte_color << ", srte_color_flag " << n->srte_color_flag
		  << ", seg6_sec " << seg6_src << ", sidlist_name "
		  << n->sidlist_name << std::endl;


	std::cout << " ---- nexthop.resolved " << n->resolved
		  << ", nexthop.next " << n->next;

	if (n->nh_srv6) {
		std::cout << ", nh_srv6 " << n->nh_srv6;
	}
	std::cout << std::endl;
}


static void dump_state()
{
	std::cout << "============ dump state ==============" << std::endl;

	// iterate over all srte_table
	hash_iterate(srte_table_hash, dump_srte_hash_bucket, NULL);
	std::cout << std::endl;

	// dump zebra_router.nhgs
	std::vector<struct nhg_t> nhgs = NHGUtils::dump_nhgs();
	std::cout << "============ dump complete ===========" << std::endl;
}


TEST(ZebraSample, ColorOnlyPolicyDelete)
{
	//GTEST_SKIP() << "ColorOnlyPolicyDelete test success, skip...";


	std::vector<test_case_policy_set_del_t> test_cases =
		read_all_test_cases_policy_set_del("resources/policydelete.json");
	for (int i = 0; i < test_cases.size(); i++) {
		test_case_policy_set_del_t test_case = test_cases[i];
		test_case.input_policy.endpoint.prefixlen = 0;
		memset(test_case.input_policy.endpoint.endpoint, 0, 16);

		struct zapi_sr_policy zp = {};
		policy_utils.get_input_policy_from_case_api_policy_t(
			&zp, &test_case.input_policy);

		zebra_vrf *zvrf = policy_utils.get_mock_zvrf();

		std::cout << "Initial zebra state:" << std::endl;
		dump_state();

		struct stream *s = policy_utils.fill_stream_with_policy(&zp);
		zread_srv6_policy_delete(nullptr, nullptr, s, zvrf);
		std::cout << "zread_srv6_policy_delete issued" << std::endl;

		dump_state();
	}
}

/*
TEST(ZebraSample, PolicySetThenDelete)
{
	GTEST_SKIP() << "PolicySetThenDelete test success, skip...";


	std::vector<test_case_policy_set_t> test_cases =
		read_all_test_cases_policy_set("resources/policyset.json");
	test_case_policy_set_t &test_case = test_cases[6];

	struct zapi_sr_policy zp = {};
	policy_utils.get_input_policy_from_case_api_policy_t(
		&zp, &test_case.input_policy);

	zebra_vrf *zvrf = policy_utils.get_mock_zvrf();

	std::cout << "Initial zebra state:" << std::endl;
	dump_state();

	struct stream *s = policy_utils.fill_stream_with_policy(&zp);
	zread_srv6_policy_set(nullptr, nullptr, s, zvrf);
	std::cout << "zread_srv6_policy_set issued" << std::endl;

	dump_state();

	// zread_srv6_policy_del_inner(&zp);
	// dump_state();
}
*/

static void get_input_route(struct zapi_route *api, const zapi_sr_policy &p,
			    const char *prefix_str)
{
	api->type = ZEBRA_ROUTE_BGP;
	api->message = ZAPI_MESSAGE_NEXTHOP | ZAPI_MESSAGE_SRTE;
	api->srte_color = p.color;
	api->srte_color_flag = 0;
	api->vrf_id = VPN_VRF_ID;

	// remote prefix
	str2prefix(prefix_str, &api->prefix);

	api->nexthop_num = 1;
	api->nexthops[0].type = NEXTHOP_TYPE_IPV6_SEGMENTLIST;
	api->nexthops[0].gate.ipv6 = p.endpoint.u.prefix6;
	api->nexthops[0].srte_color = p.color;
	api->nexthops[0].srte_color_flag = 1;
	api->nexthops[0].vrf_id = VPN_VRF_ID;
	api->safi = SAFI_UNICAST;
}


GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(ZreadSrv6PolicyDeleteTest);

/*
TEST(ZebraSample, PolicySetThenAddRoute)
{
	GTEST_SKIP() << "PolicySetThenAddRoute test success, skip...";


	std::vector<test_case_policy_set_t> test_cases =
		read_all_test_cases_policy_set(
			"resources/sample_policyset_routeadd.json");
	api_policy_t &t0 = test_cases[0].input_policy;

	struct zapi_sr_policy zp = {};
	policy_utils.get_input_policy_from_case_api_policy_t(
		&zp, &test_cases[0].input_policy);

	zebra_vrf *zvrf = policy_utils.get_mock_zvrf();
	zserv *client = policy_utils.get_mock_client();

	std::cout << "Initial zebra state:" << std::endl;
	dump_state();

	// policy -> [sid00]
	struct stream *s0 = policy_utils.fill_stream_with_policy(&zp);
	zread_srv6_policy_set(client, nullptr, s0, zvrf);
	std::cout << "\nzread_srv6_policy_set t0 issued" << std::endl;
	dump_state();

	// route_add
	struct zapi_route zapi = {};
	get_input_route(&zapi, zp, "2.2.2.0/24");
	std::cout << "\nCalling zread_route_add" << std::endl;
	zread_route_add_test(client, &zapi, zvrf);
	dump_state();

	// update the policy's segment list, policy -> [sid00, sid01]
	struct zapi_sr_policy zp1 = {};
	policy_utils.get_input_policy_from_case_api_policy_t(
		&zp1, &test_cases[1].input_policy);
	struct stream *s1 = policy_utils.fill_stream_with_policy(&zp1);
	zread_srv6_policy_set(client, nullptr, s1, zvrf);
	std::cout << "\nzread_srv6_policy_set t1 issued" << std::endl;
	dump_state();

	// udpate again, policy -> [sid01]
	struct zapi_sr_policy zp2 = {};
	policy_utils.get_input_policy_from_case_api_policy_t(
		&zp2, &test_cases[2].input_policy);
	struct stream *s2 = policy_utils.fill_stream_with_policy(&zp2);
	zread_srv6_policy_set(client, nullptr, s2, zvrf);
	std::cout << "\nzread_srv6_policy_set t2 issued" << std::endl;
	dump_state();
}
*/
/*
TEST(ZebraSample, DoublePolicyAndRoute)
{
	GTEST_SKIP() << "DoublePolicyAndRoute test success, skip...";

	zebra_vrf *zvrf = policy_utils.get_mock_zvrf();
	zserv *client = policy_utils.get_mock_client();

	std::vector<test_case_policy_set_t> test_cases =
		read_all_test_cases_policy_set("resources/sample_nhgs.json");

	std::cout << "Initial zebra state:" << std::endl;
	dump_state();

	// policy0 -> [sid00]
	struct zapi_sr_policy zp0 = {};
	policy_utils.get_input_policy_from_case_api_policy_t(
		&zp0, &test_cases[0].input_policy);
	struct stream *s0 = policy_utils.fill_stream_with_policy(&zp0);
	zread_srv6_policy_set(client, nullptr, s0, zvrf);
	std::cout << "\nzread_srv6_policy_set t0 issued" << std::endl;
	dump_state();

	// route_add, resolve to policy0
	struct zapi_route zapi = {};
	get_input_route(&zapi, zp0, "2.2.2.0/24");
	std::cout << "\nCalling zread_route_add 0" << std::endl;
	zread_route_add_test(client, &zapi, zvrf);
	dump_state();

	// udpate policy0 -> [sid01]
	struct zapi_sr_policy zp2 = {};
	policy_utils.get_input_policy_from_case_api_policy_t(
		&zp2, &test_cases[1].input_policy);
	struct stream *s2 = policy_utils.fill_stream_with_policy(&zp2);
	zread_srv6_policy_set(client, nullptr, s2, zvrf);
	std::cout << "\nzread_srv6_policy_set t2 issued" << std::endl;
	dump_state();
}
*/
/*
TEST(ZebraSample, JsonLoad)
{

	std::vector<test_case_policy_set_t> test_cases =
		read_all_test_cases_policy_set("resources/policyset_nhgs.json");

	std::cout << test_cases.size() <<  " cases loaded" << std::endl;
}
*/

int main(int argc, char **argv)
{
	testing::InitGoogleTest(&argc, argv);
	zrouter.nhgs =
		hash_create_size(8, zebra_nhg_hash_key, zebra_nhg_hash_equal,
				 "Zebra Router Nexthop Groups");
	zrouter.nhgs_id =
		hash_create_size(8, zebra_nhg_id_key, zebra_nhg_hash_id_equal,
				 "Zebra Router Nexthop Groups ID index");
	struct ns *default_ns;


	struct zebra_vrf zvrf;


	zvrf.vrf = new vrf;
	zvrf.vrf->vrf_id = VPN_VRF_ID;
	zvrf.zns = new zebra_ns;
	policy_utils.init();
	policy_utils.set_zvrf(&zvrf);
	nhg_utils.init();
	nhg_utils.set_zvrf(&zvrf);
	zebra_srte_init();
	return RUN_ALL_TESTS();
}
