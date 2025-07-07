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

	// returns 0 on success
	static int prefix2_prefix_t(const struct prefix *p,
				    struct prefix_t &dst);

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
};


int gtest_vrf_new(struct vrf *vrf);
int gtest_vrf_disable(struct vrf *vrf);
int gtest_vrf_enable(struct vrf *vrf);
int gtest_vrf_delete(struct vrf *vrf);

void print_state();
bool dump_and_check_state(const struct zebra_state_t &expected_state);
void assert_empty_state();


#endif // COMMON_UTILS_H
