#ifndef GTEST_ALIBGP_RNH_UTILS_H
#define GTEST_ALIBGP_RNH_UTILS_H

#include "test_model.h"


class RnhUtils
{
      public:
	static void dump_rnh_t(struct rnh *rnh, struct rnh_t &r);

	static const std::vector<struct rnh_list_t> dump_rnh_table();

	static bool check_rnh_vec(const std::vector<struct rnh_t> &dump_nht,
				  const std::vector<struct rnh_t> &expect_nht);

	static bool
	check_rnh_table(const std::vector<struct rnh_list_t> &dump_rnh_table,
			const std::vector<struct rnh_list_t> &expect_rnh_table);

	static struct stream *zclient_send_rnh(int command, prefix *p,
					       bool resolve_via_def,
					       uint32_t type, void *userdata)
	{
		struct stream *s;
		s = stream_new(ZEBRA_MAX_PACKET_SIZ);
		if (s == nullptr)
			return nullptr;
		uint8_t flags = 0;
		struct zapi_color_para *para;

		stream_reset(s);
		zclient_create_header(s, command, VRF_DEFAULT);
		if (userdata)
			SET_FLAG(flags, NEXTHOP_REGISTER_FLAG_USERDATA);

		stream_putc(s, flags);
		stream_putc(s, (resolve_via_def) ? 1 : 0);
		stream_putw(s, SAFI_UNICAST);
		stream_putw(s, PREFIX_FAMILY(p));
		stream_putc(s, p->prefixlen);
		switch (PREFIX_FAMILY(p)) {
		case AF_INET:
			stream_put_in_addr(s, &p->u.prefix4);
			break;
		case AF_INET6:
			stream_put(s, &(p->u.prefix6), 16);
			break;
		default:
			break;
		}
		if (userdata) {
			stream_putl(s, type);
			switch (type) {
			case NEXTHOP_REGISTER_TYPE_COLOR:
				para = (zapi_color_para *)userdata;
				stream_putl(s, para->srte_color);
				stream_putc(s, para->srte_color_flag);
				break;
			default:
				zlog_err("error type with userdate:%u", type);
				break;
			}
		}
		stream_putw_at(s, 0, stream_get_endp(s));
		return s;
	}
	static struct stream *fill_stream_with_rnh(int command, prefix *p,
						   uint32_t srte_color)
	{
		uint8_t srte_color_flag = 1;
		struct stream *s;
		if (srte_color) {
			struct zapi_color_para tmp = {0};
			tmp.srte_color = srte_color;
			tmp.srte_color_flag = srte_color_flag;
			s = zclient_send_rnh(command, p, false,
					     NEXTHOP_REGISTER_TYPE_COLOR, &tmp);
		} else {
			s = zclient_send_rnh(command, p, false,
					     NEXTHOP_REGISTER_TYPE_DEFAULT,
					     NULL);
		}
		return s;
	}
};


#endif // GTEST_ALIBGP_RNH_UTILS_H
