#include "msg_utils.h"

#include <string>
#include <iostream>

#include "common_utils.h"


void print_msg_t(const struct msg_t &msg)
{
	char ipv6[INET6_ADDRSTRLEN];
	std::string status_str[] = {"INIT", "DOWN", "UP"};

	if (msg.command == ZEBRA_SR_POLICY_NOTIFY_STATUS) {
		const struct msg_policy_status_t &payload =
			msg.policy_notify_status;
		inet_ntop(AF_INET6, payload.prefix.endpoint, ipv6,
			  sizeof(ipv6));
		std::cout << "msg command ZEBRA_SR_POLICY_NOTIFY_STATUS: color "
			  << payload.color << " endpoint " << ipv6 << "/"
			  << payload.prefix.prefixlen << " status "
			  << status_str[payload.status] << std::endl;
	} else if (msg.command == ZEBRA_NEXTHOP_UPDATE) {
		const struct msg_nexthop_update_t &payload = msg.nexthop_update;
		std::cout << "msg command ZEBRA_NEXTHOP_UPDATE: prefix "
			  << prefix_t2str(payload.match) << " resolved "
			  << prefix_t2str(payload.nhr.prefix) << " srte_color "
			  << payload.nhr.srte_color << " color_flag "
			  << (int)payload.nhr.srte_color_flag << " policy_num "
			  << payload.nhr.route_entry.size() << std::endl;
		for (const auto &nhe : payload.nhr.route_entry) {
			std::cout << " -- nhe "
				  << common_utils::addr2str(nhe.gate)
				  << " color " << nhe.color << std::endl;
		}
	} else {
		std::cout << "Unrecognized msg command " << msg.command
			  << std::endl;
	}
}


static std::string interpret_command(uint16_t cmd)
{
	switch (cmd) {
	case ZEBRA_NEXTHOP_UPDATE:
		return "ZEBRA_NEXTHOP_UPDATE";
	case ZEBRA_SR_POLICY_NOTIFY_STATUS:
		return "ZEBRA_SR_POLICY_NOTIFY_STATUS";
	default:
		return "Unknown " + std::to_string(cmd);
	}
}


bool compare_msg_t(const struct msg_t &dump_msg,
		   const struct msg_t &expected_msg)
{
	if (dump_msg.command != expected_msg.command) {
		std::cout << "compare_msg_t: msg command mismatch exepcted "
			  << interpret_command(expected_msg.command)
			  << " dumped " << interpret_command(dump_msg.command)
			  << std::endl;
		return false;
	}

	if (expected_msg.command == ZEBRA_SR_POLICY_NOTIFY_STATUS) {
		const struct msg_policy_status_t &exp_payload =
			expected_msg.policy_notify_status;
		const struct msg_policy_status_t &dump_payload =
			dump_msg.policy_notify_status;
		if (exp_payload.color != dump_payload.color ||
		    exp_payload.status != dump_payload.status) {
			std::cout
				<< "compare_msg_t: msg.color or msg.status mismatch "
				<< std::endl;
			return false;
		}
		if (!common_utils::is_prefix_t_euqal(&exp_payload.prefix,
						     &dump_payload.prefix)) {
			std::cout << "compare_msg_t: msg.prefix mismatch "
				  << std::endl;
			return false;
		}
		return true;
	} else if (expected_msg.command == ZEBRA_NEXTHOP_UPDATE) {
		const struct msg_nexthop_update_t &exp_payload =
			expected_msg.nexthop_update;
		const struct msg_nexthop_update_t &dump_payload =
			dump_msg.nexthop_update;
		if (!common_utils::is_prefix_t_euqal(&exp_payload.match,
						     &dump_payload.match)) {
			std::cout << "compare_msg_t: matched_prefix mismatch "
				  << std::endl;
			return false;
		}
		if (!common_utils::is_prefix_t_euqal(
			    &exp_payload.nhr.prefix,
			    &dump_payload.nhr.prefix)) {
			std::cout
				<< "compare_msg_t: resolved_prefix mismatch, expected "
				<< prefix_t2str(exp_payload.nhr.prefix)
				<< " dumped "
				<< prefix_t2str(dump_payload.nhr.prefix)
				<< std::endl;
			return false;
		}
		if (exp_payload.nhr.srte_color != dump_payload.nhr.srte_color) {
			std::cout << "compare_msg_t: nhr.srte_color mismatch "
				  << std::endl;
			return false;
		}
		if (exp_payload.nhr.route_entry.size() !=
		    dump_payload.nhr.route_entry.size()) {
			std::cout << "compare_msg_t: route_entry.size mismatch "
				  << std::endl;
		}
		for (int i = 0; i < exp_payload.nhr.route_entry.size(); i++) {
			const struct nhe_t &exp_nhe =
				exp_payload.nhr.route_entry[i];
			const struct nhe_t &dump_nhe =
				dump_payload.nhr.route_entry[i];
			if (std::memcmp(exp_nhe.gate, dump_nhe.gate, 16) != 0 ||
			    exp_nhe.color != dump_nhe.color) {
				std::cout << "compare_msg_t: nhe mismatch"
					  << std::endl;
				std::cout << " -- expected: ";
				print_nhe(exp_nhe);
				std::cout << " -- dumped: ";
				print_nhe(dump_nhe);
				return false;
			}
		}
	} else {
		std::cout << "Unhandled command " << expected_msg.command
			  << std::endl;
		return false;
	}

	return true;
}


// Precondition: prefix written by stream_put_prefix
static struct prefix dump_compress_prefix(stream *s)
{
	struct prefix p = {};
	p.prefixlen = stream_getc(s);
	size_t psize = PSIZE(p.prefixlen);
	stream_get(&p.u.prefix, s, psize);
	return p;
}


static struct msg_t dump_message(stream *s)
{
	struct msg_t dump_msg = {};
	stream_set_getp(s, 0);

	struct zmsghdr hdr = {};
	bool hdrvalid = zapi_parse_header(s, &hdr);

	dump_msg.command = hdr.command;
	if (hdr.command == ZEBRA_SR_POLICY_NOTIFY_STATUS) {
		// zapi_msg.c ::
		// zsend_sr_policy_notify_status
		struct msg_policy_status_t &payload =
			dump_msg.policy_notify_status;
		payload.color = stream_getl(s);
		// zsend_sr_policy_notify_status => stream_put_prefix
		struct prefix p = dump_compress_prefix(s);
		p.family = AF_INET6;
		common_utils::prefix2_prefix_t(&p, payload.prefix);
		stream_forward_getp(s, SRTE_POLICY_NAME_MAX_LENGTH);
		payload.status = stream_getl(s);
	} else if (hdr.command == ZEBRA_NEXTHOP_UPDATE) {
		// zebra_srte.c ::
		// zebra_sr_policy_notify_update_client
		struct msg_nexthop_update_t &payload = dump_msg.nexthop_update;

		struct prefix match = {};
		struct zapi_route nhr = {};
		if (zapi_nexthop_update_decode(s, &match, &nhr)) {
			common_utils::prefix2_prefix_t(&match, payload.match);
			common_utils::prefix2_prefix_t(&nhr.prefix,
						       payload.nhr.prefix);
			payload.nhr.srte_color = nhr.srte_color;
			payload.nhr.srte_color_flag = nhr.srte_color_flag;
			for (int i = 0; i < nhr.nexthop_num; i++) {
				struct nhe_t nhe = {};
				nhe.color = nhr.nexthops[i].srte_color;
				std::memcpy(nhe.gate,
					    &nhr.nexthops[i].gate.ipv6, 16);
				payload.nhr.route_entry.push_back(nhe);
			}
		} else {
			std::cout
				<< "dump_message: zapi_nexthop_update_decode error"
				<< std::endl;
		}
	} else {
		std::cout << "Unhandled command " << hdr.command << std::endl;
	}

	return dump_msg;
}


std::vector<struct msg_t> dump_messages(struct zserv *client)
{
	std::vector<struct msg_t> res;

	int count = client->obuf_fifo->count;
	if (count > 0) {
		std::cout << "client at " << std::hex << std::showbase
			  << reinterpret_cast<std::uintptr_t>(client)
			  << std::dec << ", count = " << count << std::endl;

		for (int i = 0; i < count; i++) {
			struct stream *s =
				stream_fifo_pop_safe(client->obuf_fifo);
			struct msg_t dump_msg = dump_message(s);
			std::cout << "Msg #" << i << ": ";
			print_msg_t(dump_msg);
			res.push_back(dump_msg);
		}
	}

	return res;
}