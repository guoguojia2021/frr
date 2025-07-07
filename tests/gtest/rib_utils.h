#ifndef GTEST_ALIBGP_RIB_UTILS_H
#define GTEST_ALIBGP_RIB_UTILS_H
#include "test_model.h"
class RibUtils
{
      public:
	static void dump_nhe_t(struct nexthop *nh, struct nhe_t &nhe);
	static const std::vector<struct api_route_t> dump_rib_state();
	static bool
	check_route_entry(const std::vector<struct nhe_t> &dump_route_entry,
		      const std::vector<struct nhe_t> &expect_route_entry);
	static bool check_rib_state(
		const std::vector<struct api_route_t> &dump_rib_state,
		const std::vector<struct api_route_t> &expect_rib_state);
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
	get_route_multi_policies(api_route_t input_route)
	{
		struct zapi_route api = {0};
		api.type = ZEBRA_ROUTE_BGP;
		api.message = ZAPI_MESSAGE_NEXTHOP | ZAPI_MESSAGE_SRTE;
		// api.srte_color = policy_color;
		// api.srte_color_flag = 1;
		api.vrf_id = VPN_VRF_ID;
		// remote prefix
		common_utils::prefix_t2prefix(&input_route.prefix, &api.prefix);
		api.nexthop_num = input_route.route_entry.size();
		for (int i = 0; i < api.nexthop_num; i++) {
			struct nhe_t &policy =
				input_route.route_entry[i];
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
	static struct zapi_route get_del_route(api_route_del_t input_route)
	{
		struct zapi_route api = {0};
		api.type = ZEBRA_ROUTE_BGP;
		api.message = ZAPI_MESSAGE_NEXTHOP | ZAPI_MESSAGE_SRTE;
		// api.srte_color = policy_color;
		// api.srte_color_flag = 1;
		api.vrf_id = VPN_VRF_ID;
		// remote prefix
		common_utils::prefix_t2prefix(&input_route.prefix, &api.prefix);
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
#endif // GTEST_ALIBGP_RIB_UTILS_H