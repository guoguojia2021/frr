//
// Created by lsn on 2024/12/2.
//

#ifndef COMMON_UTILS_H
#define COMMON_UTILS_H
#include <cstring>
#include <string>
#include <vector>
#include "lib/prefix.h"
#include "lib/zclient.h"

#include "test_model.h"
#define VPN_VRF_ID 0


class common_utils
{
      public:
	static int prefix_t2prefix(const prefix_t *addr, struct prefix *p)
	{
		char dst[128] = {0};
		p->prefixlen = addr->prefixlen;
		p->family = AF_INET6;

		inet_ntop(AF_INET6, &addr->endpoint, dst, sizeof(dst));
		return !inet_pton(AF_INET6, dst,
				  &(((struct prefix_ipv6 *)p)->prefix));
	}

	static int addr2prefix(const uint8_t *addr, struct prefix *p)
	{
		char addr_str[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, addr, addr_str, sizeof(addr_str));
		p->prefixlen = 128;
		p->family = AF_INET6;
		return !inet_pton(AF_INET6, addr_str,
				  &(((struct prefix_ipv6 *)p)->prefix));
	}

	static void v6addrcpy_ipv6(uint8_t *addr_dst,
				   const struct in6_addr &ipv6)
	{
		std::memcpy(addr_dst, &ipv6, 16);
	}

	// Returns 1 if successful
	static int v6addr2prefix_t(const struct in6_addr *src_addr,
				   struct prefix_t &dst_p)
	{
		dst_p.prefixlen = 128;
		char gate_str[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, src_addr, gate_str, sizeof(gate_str));
		return inet_pton(AF_INET6, gate_str, &dst_p.endpoint);
	}

	static std::string addr2str(const uint8_t *src_addr)
	{
		char gate_str[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, src_addr, gate_str, sizeof(gate_str));
		return std::string(gate_str);
	}

	static bool is_prefix_t_euqal(const prefix_t *a, const prefix_t *b)
	{
		char a_str[64], b_str[64];
		struct prefix a_p, b_p;
		prefix_t2prefix(a, &a_p);
		prefix2str(&a_p, a_str, sizeof(a_str));
		prefix_t2prefix(b, &b_p);
		prefix2str(&b_p, b_str, sizeof(b_str));
		int ret = strcmp(b_str, a_str);
		return (ret == 0);
	}

	static void get_input_route(struct zapi_route *api,
				    const zapi_sr_policy &p,
				    const char *prefix_str)
	{
		api->type = ZEBRA_ROUTE_BGP;
		api->message = ZAPI_MESSAGE_NEXTHOP | ZAPI_MESSAGE_SRTE;
		api->srte_color = p.color;
		api->srte_color_flag = 1;
		api->vrf_id = VPN_VRF_ID;

		// remote prefix
		str2prefix(prefix_str, &api->prefix);

		api->nexthop_num = 1;
		api->nexthops[0].type = NEXTHOP_TYPE_IPV6_SEGMENTLIST;
		struct prefix tmp_p;
		str2prefix("0::/0", &tmp_p);
		if (prefix_same(&p.endpoint, &tmp_p)) {
			struct prefix tmp_p2;
			str2prefix("1:1::/32", &tmp_p2);
			api->nexthops[0].gate.ipv6 = tmp_p2.u.prefix6;
		} else {
			api->nexthops[0].gate.ipv6 = p.endpoint.u.prefix6;
		}
		api->nexthops[0].srte_color = p.color;
		api->nexthops[0].srte_color_flag = 1;
		api->nexthops[0].flags = ZAPI_NEXTHOP_FLAG_SRTE;

		api->nexthops[0].vrf_id = VPN_VRF_ID;
		api->safi = SAFI_UNICAST;
	}

	static struct zapi_route
	get_route_single_policy(uint32_t policy_color,
				const uint8_t *policy_endpoint,
				const char *route_prefix_str)
	{
		struct zapi_route api = {0};
		api.type = ZEBRA_ROUTE_BGP;
		api.message = ZAPI_MESSAGE_NEXTHOP | ZAPI_MESSAGE_SRTE;
		//		api.srte_color = policy_color;
		//		api.srte_color_flag = 1;
		api.vrf_id = VPN_VRF_ID;

		// remote prefix
		str2prefix(route_prefix_str, &api.prefix);

		api.nexthop_num = 1;
		api.nexthops[0].type = NEXTHOP_TYPE_IPV6_SEGMENTLIST;
		api.nexthops[0].srte_color = policy_color;
		api.nexthops[0].srte_color_flag = 1;
		std::memcpy(&api.nexthops[0].gate.ipv6, policy_endpoint, 16);
		api.nexthops[0].flags = ZAPI_NEXTHOP_FLAG_SRTE;

		api.nexthops[0].vrf_id = VPN_VRF_ID;
		api.safi = SAFI_UNICAST;

		return api;
	}

	static struct zapi_route
	get_route_multi_policies(api_route_t input_route)
	{
		struct zapi_route api = {0};
		api.type = ZEBRA_ROUTE_BGP;
		api.message = ZAPI_MESSAGE_NEXTHOP | ZAPI_MESSAGE_SRTE;
		// api.srte_color = policy_color;
		// api.srte_color_flag = 1;
		api.vrf_id = VPN_VRF_ID;

		// remote prefix
		prefix_t2prefix(&input_route.prefix, &api.prefix);

		api.nexthop_num = input_route.api_nexthops.size();
		for (int i = 0; i < api.nexthop_num; i++) {
			struct api_route_nexthop_t &policy =
				input_route.api_nexthops[i];

			api.nexthops[i].type = NEXTHOP_TYPE_IPV6_SEGMENTLIST;
			api.nexthops[i].srte_color = policy.color;
			api.nexthops[i].srte_color_flag = 1;
			std::memcpy(&api.nexthops[i].gate.ipv6, policy.gate,
				    16);
			api.nexthops[i].flags = ZAPI_NEXTHOP_FLAG_SRTE;

			api.nexthops[i].vrf_id = VPN_VRF_ID;
		}
		api.safi = SAFI_UNICAST;

		return api;
	}
	static struct zapi_route
	get_del_route(api_route_del_t input_route)
	{
		struct zapi_route api = {0};
		api.type = ZEBRA_ROUTE_BGP;
		api.message = ZAPI_MESSAGE_NEXTHOP | ZAPI_MESSAGE_SRTE;
		// api.srte_color = policy_color;
		// api.srte_color_flag = 1;
		api.vrf_id = VPN_VRF_ID;

		// remote prefix
		prefix_t2prefix(&input_route.prefix, &api.prefix);
		api.safi = SAFI_UNICAST;

		return api;
	}

	static struct zapi_route
	get_zapi_route_from_t(const struct api_route_t &route);
	static struct stream *fill_stream_with_route(struct zapi_route *route)
	{
		struct stream *s;
		s = stream_new(ZEBRA_MAX_PACKET_SIZ);
		if (s == nullptr)
			return nullptr;
		zapi_route_encode(ZEBRA_ROUTE_ADD, s, route);
		struct zmsghdr hdr;
		if (!zapi_parse_header(s, &hdr))
			return nullptr;
		return s;
	}
};


int gtest_vrf_new(struct vrf *vrf);
int gtest_vrf_disable(struct vrf *vrf);
int gtest_vrf_enable(struct vrf *vrf);
int gtest_vrf_delete(struct vrf *vrf);

void print_state();
bool dump_and_check_state(const struct zebra_state_t &expected_state);
void assert_empty_state();


#endif // COMMON_UTILS_H
