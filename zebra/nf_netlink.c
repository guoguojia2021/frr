#include "zebra/nf_netlink.h"


#ifdef HAVE_NETLINK
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>
#include <libnftnl/batch.h>
#include <libnftnl/common.h>
#include <libnftnl/set.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <linux/netfilter/nf_tables.h> // enum nf_tables_msg_types - NFT_MSG_NEWRULE, etc
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "pbr.h"
#include "zclient.h"

#define PORT_INDEX_LEN 2

/** 
 * @brief Create an expression for reading from the payload
 * @param base      Type of the payload base, for example NFT_PAYLOAD_NETWORK_HEADER
 * @param offset    The offset within the payload
 * @param len       The length of the payload
 * @param dreg      The register to store the value read from the payload
 * @return A pointer to the created expression, or NULL on failure
 */
static struct nftnl_expr* create_read_expr(uint32_t base, uint32_t offset, uint32_t len, uint32_t dreg)
{
    struct nftnl_expr* expr = nftnl_expr_alloc("payload");
    if (!expr) return NULL;
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_BASE, base);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_OFFSET, offset);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_LEN, len);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_DREG, dreg);
    return expr;
}

/** 
 * @brief Create an expression for writing into the payload
 * @param base      Type of the payload base, for example NFT_PAYLOAD_NETWORK_HEADER
 * @param offset    The offset within the payload
 * @param len       The length of the payload
 * @param sreg      The register which stores the value to write into the payload
 * @return A pointer to the created expression, or NULL on failure
 */
static struct nftnl_expr* create_write_expr(uint32_t base, uint32_t offset, uint32_t len, uint32_t sreg)
{
    struct nftnl_expr* expr = nftnl_expr_alloc("payload");
    if (!expr) return NULL;
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_BASE, base);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_OFFSET, offset);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_LEN, len);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_SREG, sreg);
    return expr;
}

/** 
 * @brief Create a cmp expression 
 * @param sreg      The source register that stores the data to be compared
 * @param op        The comparison operator
 * @param data      The data to compare against
 * @param data_len  The length of the data
 * @return A pointer to the created cmp expression, or NULL on failure
 */
static struct nftnl_expr* create_cmp_expr(uint32_t sreg, uint32_t op, void* data, uint32_t data_len)
{
    struct nftnl_expr* expr = nftnl_expr_alloc("cmp");
    if (!expr) return NULL;
    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_SREG, sreg);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_OP, op);
    nftnl_expr_set_data(expr, NFTNL_EXPR_CMP_DATA, data, data_len);
    return expr;
}

static struct nftnl_expr* create_lookup_expr(uint32_t sreg, char* data)
{
    struct nftnl_expr* expr = nftnl_expr_alloc("lookup");
    if (!expr) return NULL;
    nftnl_expr_set_u32(expr, NFTNL_EXPR_LOOKUP_SREG, sreg);
    nftnl_expr_set_str(expr, NFTNL_EXPR_LOOKUP_SET, data);
    return expr;
}

static struct nftnl_expr* create_imm_verdict_expr(uint32_t verdict)
{
    struct nftnl_expr* expr = nftnl_expr_alloc("immediate");
    if (!expr) return NULL;
    nftnl_expr_set_u32(expr, NFTNL_EXPR_IMM_VERDICT, verdict);
    return expr;
}

static int encode_nfset_into_rule(struct nftnl_rule *rule, struct zebra_pbr_iptable *nft)
{
    if (!nft->ipset_name || !rule) return 0;

    int src_offset = nft->family == AF_INET ? 12 : 8;
    int dst_offset = nft->family == AF_INET ? 16 : 24;
    int ip_addr_len = nft->family == AF_INET ? 4 : 16;

    // Load the ip address to check into register 1
    struct nftnl_expr * expr = create_read_expr(NFT_PAYLOAD_NETWORK_HEADER,
                            (nft->filter_bm & (MATCH_IP_SRC_SET)) ? src_offset : dst_offset,
                            ip_addr_len,
                            NFT_REG_1);
    if (!expr) return -1;
    nftnl_rule_add_expr(rule, expr);

    if (nft->type == IPSET_NET_PORT)
    {
        if ((nft->filter_bm & MATCH_ICMP_SET) || (nft->filter_bm & MATCH_PORT_SRC_SET))
        {
            // ICMP Packet   : [Type][Code][Checksum][...]
            // TCP/UDP Packet: [SourcePort][Dst Port][...]
            expr = create_read_expr(NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2, NFT_REG_2);
            if (!expr) return -1;
            nftnl_rule_add_expr(rule, expr);
        }
        else if (nft->filter_bm & MATCH_PORT_DST_SET)
        {
            expr = create_read_expr(NFT_PAYLOAD_TRANSPORT_HEADER, 2, 2, NFT_REG_2);
            if (!expr) return -1;
            nftnl_rule_add_expr(rule, expr);
        }
    }
    else if (nft->type == IPSET_NET_NET)
    {
        expr = create_read_expr(NFT_PAYLOAD_NETWORK_HEADER, dst_offset, ip_addr_len, NFT_REG_2);
        if (!expr) return -1;
        nftnl_rule_add_expr(rule, expr);
    }
    else if (nft->type == IPSET_NET_PORT_NET)
    {
        expr = create_read_expr(NFT_PAYLOAD_NETWORK_HEADER, dst_offset, ip_addr_len, NFT_REG_2);
        if (!expr) return -1;
        nftnl_rule_add_expr(rule, expr);

        if (nft->filter_bm & MATCH_ICMP_SET || nft->filter_bm & MATCH_PORT_SRC_SET)
        {
            expr = create_read_expr(NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2, NFT_REG_3);
            if (!expr) return -1;
            nftnl_rule_add_expr(rule, expr);
        }
        else if (nft->filter_bm & MATCH_PORT_DST_SET)
        {
            expr = create_read_expr(NFT_PAYLOAD_TRANSPORT_HEADER, 2, 2, NFT_REG_3);
            if (!expr) return -1;
            nftnl_rule_add_expr(rule, expr);
        }
    }

    expr = create_lookup_expr(NFT_REG_1, nft->ipset_name);
    if (!expr) return -1;
    nftnl_rule_add_expr(rule, expr);
    return 0;
}

static int nftnl_rule_add_filters(struct nftnl_rule *rule, struct zebra_pbr_iptable *nft)
{
    if (!nft || !rule) return -1;

    struct nftnl_expr *expr;

    if (nft->filter_bm & MATCH_PROTOCOL_SET) {
        expr = nftnl_expr_alloc("meta");
        if (!expr) return -1;
        // load L4 protocol or L6 NextHeader to register 4
        nftnl_expr_set_u32(expr, NFTNL_EXPR_META_KEY, NFT_META_L4PROTO);
        nftnl_expr_set_u32(expr, NFTNL_EXPR_META_DREG, NFT_REG_4);
        nftnl_rule_add_expr(rule, expr);

        expr = create_cmp_expr(NFT_REG_4, NFT_CMP_EQ, &nft->protocol, 1);
        if (!expr) return -1;
        nftnl_rule_add_expr(rule, expr);
    }

    if (nft->filter_bm & MATCH_DSCP_SET) {
        // load ip dscp to register NFT_REG32_00
        expr = create_read_expr(NFT_PAYLOAD_NETWORK_HEADER, 1, 1, NFT_REG32_00);
        if (!expr) return -1;
        nftnl_rule_add_expr(rule, expr);

        expr = nftnl_expr_alloc("bitwise");
        if (!expr) return -1;
        nftnl_expr_set_u32(expr, NFTNL_EXPR_BITWISE_SREG, NFT_REG32_00);
        nftnl_expr_set_u32(expr, NFTNL_EXPR_BITWISE_DREG, NFT_REG32_00);
        uint8_t mask = 0xfc; // 0b11111100，only keep DSCP bits
        nftnl_expr_set_data(expr, NFTNL_EXPR_BITWISE_MASK, &mask, sizeof(mask));
        nftnl_rule_add_expr(rule, expr);

        expr = create_cmp_expr(NFT_REG32_00, NFT_CMP_EQ, &nft->dscp_value, sizeof(nft->dscp_value));
        if (!expr) return -1;
        nftnl_rule_add_expr(rule, expr);
    }

    if (encode_nfset_into_rule(rule, nft) < 0) return -1;

    return 0;
}

static int nftnl_rule_add_actions(struct nftnl_rule *rule, struct zebra_pbr_iptable *nft)
{
    if (!nft || !rule) return -1;
    struct nftnl_expr *expr;

    // 1. remark DSCP
    if (nft->action == ZEBRA_IPTABLES_MARKING) {
        // Only support marking DSCP in mangle table for now
        // 1.1 load the TOS byte to NFT_REG32_01
        expr = create_read_expr(NFT_PAYLOAD_NETWORK_HEADER, 1, 1, NFT_REG32_01);
        if (!expr) return -1;
        nftnl_rule_add_expr(rule, expr);
    
        // 1.2 1.2 Modify DSCP bits while preserving ECN bits
        expr = nftnl_expr_alloc("bitwise");
        if (!expr) return -1;
        nftnl_expr_set_u32(expr, NFTNL_EXPR_BITWISE_SREG, NFT_REG32_01);
        nftnl_expr_set_u32(expr, NFTNL_EXPR_BITWISE_DREG, NFT_REG32_01);
        uint8_t mask_clear = 0x03; // 0b00000011 - preserve ECN bits (0-1)
        nftnl_expr_set_data(expr, NFTNL_EXPR_BITWISE_MASK, &mask_clear, sizeof(mask_clear));
        uint8_t new_dscp =  (nft->marking_dscp << 2) & 0xFC; // DSCP in bits 2-7
        nftnl_expr_set_data(expr, NFTNL_EXPR_BITWISE_XOR, &new_dscp, sizeof(new_dscp));
        nftnl_rule_add_expr(rule, expr);

        // 1.3 Write the modified TOS byte from register NFT_REG32_01 back to the packet
        expr = create_write_expr(NFT_PAYLOAD_NETWORK_HEADER, 1, 1, NFT_REG32_01);
        if (!expr) return -1;
        nftnl_rule_add_expr(rule, expr);
    }

    // 2. rate limiting action
    if (nft->action == ZEBRA_IPTABLES_TRAFFICRATE && nft->rate > 0) {
        expr = nftnl_expr_alloc("limit");
        if (!expr) return -1;
        uint64_t rate_bytes_per_sec = (uint64_t)(nft->rate); // in bytes per second
        uint64_t burst = rate_bytes_per_sec;

        nftnl_expr_set_u64(expr, NFTNL_EXPR_LIMIT_RATE, rate_bytes_per_sec);
        nftnl_expr_set_u64(expr, NFTNL_EXPR_LIMIT_UNIT, 1000000000); // nanosec
        nftnl_expr_set_u32(expr, NFTNL_EXPR_LIMIT_BURST, burst);
        nftnl_expr_set_u32(expr, NFTNL_EXPR_LIMIT_TYPE, NFT_LIMIT_PKT_BYTES);
        nftnl_expr_set_u32(expr, NFTNL_EXPR_LIMIT_FLAGS, NFT_LIMIT_F_INV);
        
        nftnl_rule_add_expr(rule, expr);
        
        expr = create_imm_verdict_expr(NF_DROP);
        if (!expr) return -1;
        nftnl_rule_add_expr(rule, expr);
    } 

    // 3. Later we may support multiple actions in a single rule
    switch (nft->action) {
    case ZEBRA_IPTABLES_DROP:
        expr = create_imm_verdict_expr(NF_DROP);
        if (!expr) return -1;
        nftnl_rule_add_expr(rule, expr);
        break;

    case ZEBRA_IPTABLES_FORWARD:
        expr = create_imm_verdict_expr(NF_ACCEPT);
        if (!expr) return -1;
        nftnl_rule_add_expr(rule, expr);
        break;

    case ZEBRA_IPTABLES_TRAFFICRATE:
    case ZEBRA_IPTABLES_MARKING:
        break;
    default:
        // NOT SUPPORTED YET
        return -1;
        break;
    }
    return 0;
}

ssize_t netlink_nft_rule_msg_encode(bool add, struct zebra_pbr_iptable *nft, void *data)
{
    // 1. Basic input validation.
    assert(nft != NULL);

    // 2. Allocate the rule object and check for success.
    struct nftnl_rule *rule = nftnl_rule_alloc();
    if (!rule) return -1;

    // 3. Set basic rule attributes.
    nftnl_rule_set_u32(rule, NFTNL_RULE_FAMILY, nft->family == AF_INET ? NFPROTO_IPV4 : NFPROTO_IPV6);
    nftnl_rule_set_str(rule, NFTNL_RULE_TABLE, nft->action == ZEBRA_IPTABLES_MARKING ? "mangle" : "filter");
    nftnl_rule_set_str(rule, NFTNL_RULE_CHAIN, "FORWARD");

    // 4. Add filters and actions, checking for errors.
    if (nftnl_rule_add_filters(rule, nft) < 0 || nftnl_rule_add_actions(rule, nft) < 0) {
        goto error;
    }

    int cmd = add ? NFT_MSG_NEWRULE : NFT_MSG_DELRULE;
    int flags = NLM_F_REQUEST | NLM_F_ACK;
    if (add) {
        flags |= (NLM_F_CREATE | NLM_F_APPEND);
    }
    struct nlmsghdr *nlh = nftnl_rule_nlmsg_build_hdr(data, cmd, nft->family == AF_INET ? NFPROTO_IPV4 : NFPROTO_IPV6,
                                    flags,
                                    nft->unique);
    if (!nlh) {
        goto error;
    }

    nftnl_rule_nlmsg_build_payload(nlh, rule);

    // 6. Success: clean up the rule object and return length.
    nftnl_rule_free(rule);

    return nlh->nlmsg_len;
error:
    // 8. Error path: clean up the rule object and return -1.
    if (rule) {
        nftnl_rule_free(rule);
    }
    return -1;
}

static void calculate_ipv4_range(const struct prefix *p,
                          struct in_addr *start,
                          struct in_addr *end)
{
    const struct in_addr *ipv4 = &p->u.prefix4;

    // if prefix_len is 32, start and end are the same
    if (p->prefixlen == 32) {
        *start = *ipv4;
        *end = *ipv4;
    } else {
        // calculate subnet mask, the 4 bytes should be in network byte order
        uint32_t mask = htonl(~((1UL << (32 - p->prefixlen)) - 1));

        // calculate start address (IP & mask)
        start->s_addr = ipv4->s_addr & mask;

        // calculate end address (IP | ~mask)
        end->s_addr = ipv4->s_addr | (~mask);
    }
}

static void calculate_ipv6_range(const struct prefix *p,
                          struct in6_addr *start,
                          struct in6_addr *end)
{
    const struct in6_addr *ipv6 = &p->u.prefix6;

    // if prefix_len is 128, start and end are the same
    if (p->prefixlen == 128) {
        *start = *ipv6;
        *end = *ipv6;
    } else if (p->prefixlen == 0) {
        // /0 represents the whole IPv6 range
        memset(start, 0, sizeof(struct in6_addr));
        memset(end, 0xFF, sizeof(struct in6_addr));
    }
    else 
    {
        // create mask
        struct in6_addr mask;
        memset(&mask, 0, sizeof(struct in6_addr));
        for (int i = 0; i < p->prefixlen / 8; i++) {
            mask.s6_addr[i] = 0xFF;
        }
        if (p->prefixlen % 8 != 0) {
            mask.s6_addr[p->prefixlen / 8] = (0xFF << (8 - p->prefixlen % 8));
        }

        for (int i = 0; i < 16; i++) {
            start->s6_addr[i] = ipv6->s6_addr[i] & mask.s6_addr[i];
            end->s6_addr[i] = ipv6->s6_addr[i] | (~mask.s6_addr[i]);
        }
    }
}

static void concat_port_to_key(struct zebra_pbr_ipset_entry *nfse, uint8_t *key_start, uint8_t *key_end, int offset, int ip_len)
{
    if (nfse->filter_bm & MATCH_ICMP_SET)
    {
        uint16_t icmp = htons((nfse->src_port_min << 8) | nfse->dst_port_min);
        memcpy(key_start + offset, &icmp, PORT_INDEX_LEN);
        memcpy(key_end + offset, &icmp, PORT_INDEX_LEN);
    }
    else if (nfse->filter_bm & MATCH_PORT_SRC_SET)
    {
        uint16_t port_min = htons(nfse->src_port_min);
        uint16_t port_max = port_min;

        if (nfse->filter_bm & MATCH_PORT_SRC_RANGE_SET)
            port_max = htons(nfse->src_port_max);
        memcpy(key_start + offset, &port_min, PORT_INDEX_LEN);
        memcpy(key_end + offset, &port_max, PORT_INDEX_LEN);
    }
    else if (nfse->filter_bm & MATCH_PORT_DST_SET) {
        uint16_t port_min = htons(nfse->dst_port_min);
        uint16_t port_max = port_min;
        if (nfse->filter_bm & MATCH_PORT_DST_RANGE_SET)
            port_max = htons(nfse->dst_port_max);
        memcpy(key_start + offset, &port_min, PORT_INDEX_LEN);
        memcpy(key_end + offset, &port_max, PORT_INDEX_LEN);
    }
}

static void build_net_net_key(int nf_family, struct prefix *src, struct prefix *dst, uint8_t *key_start, uint8_t *key_end)
{
    if (nf_family == NFPROTO_IPV4) {
        struct in_addr src_start_v4, src_end_v4;
        struct in_addr dst_start_v4, dst_end_v4;
        calculate_ipv4_range(src, &src_start_v4, &src_end_v4);
        calculate_ipv4_range(dst, &dst_start_v4, &dst_end_v4);
        memcpy(key_start, &src_start_v4, sizeof(struct in_addr));
        memcpy(key_start + sizeof(struct in_addr), &dst_start_v4, sizeof(struct in_addr));
        memcpy(key_end, &src_end_v4, sizeof(struct in_addr));
        memcpy(key_end + sizeof(struct in_addr), &dst_end_v4, sizeof(struct in_addr));
    } else if (nf_family == NFPROTO_IPV6) {
        struct in6_addr src_start_v6, src_end_v6;
        struct in6_addr dst_start_v6, dst_end_v6;
        calculate_ipv6_range(src, &src_start_v6, &src_end_v6);
        calculate_ipv6_range(dst, &dst_start_v6, &dst_end_v6);
        memcpy(key_start, &src_start_v6, sizeof(struct in6_addr));
        memcpy(key_start + sizeof(struct in6_addr), &dst_start_v6, sizeof(struct in6_addr));
        memcpy(key_end, &src_end_v6, sizeof(struct in6_addr));
        memcpy(key_end + sizeof(struct in6_addr), &dst_end_v6, sizeof(struct in6_addr));
    }
}

static struct nftnl_set * encode_nftnl_setelem(struct zebra_pbr_ipset_entry *nfse, struct zebra_pbr_ipset *info)
{
    struct nftnl_set_elem *elem = nftnl_set_elem_alloc();
    if (!elem) return NULL;

    struct nftnl_set * set = nftnl_set_alloc();
    if (!set) {
        nftnl_set_elem_free(elem);
        return NULL;
    }

    int nf_family = info->family == AF_INET ? NFPROTO_IPV4 : NFPROTO_IPV6;
    nftnl_set_set_str(set, NFTNL_SET_NAME, info->ipset_name);
    nftnl_set_set_str(set, NFTNL_SET_TABLE, info->table == FILTER_TABLE ? "filter" : "mangle");
    nftnl_set_set_u32(set, NFTNL_SET_FAMILY, nf_family);

    int ip_len = info->family == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr);

    switch (info->type) {
        case IPSET_NET:
        {
            struct prefix *p = (nfse->filter_bm & MATCH_IP_SRC_SET) ? &nfse->src : &nfse->dst;
            if (nf_family == NFPROTO_IPV4) {
                struct in_addr start_v4, end_v4;
                calculate_ipv4_range(p, &start_v4, &end_v4);
                nftnl_set_elem_set(elem, NFTNL_SET_ELEM_KEY, &start_v4, sizeof(struct in_addr));
                nftnl_set_elem_set(elem, NFTNL_SET_ELEM_KEY_END, &end_v4, sizeof(struct in_addr));
            } else {
                struct in6_addr start_v6, end_v6;
                calculate_ipv6_range(p, &start_v6, &end_v6);
                nftnl_set_elem_set(elem, NFTNL_SET_ELEM_KEY, &start_v6, sizeof(struct in6_addr));
                nftnl_set_elem_set(elem, NFTNL_SET_ELEM_KEY_END, &end_v6, sizeof(struct in6_addr));
            }
        }
        break;

        case IPSET_NET_PORT:
        {
            struct prefix *p = (nfse->filter_bm & MATCH_IP_SRC_SET) ? &nfse->src : &nfse->dst;
            uint32_t total_key_len = ip_len + PORT_INDEX_LEN;
            uint8_t key_start[total_key_len];
            uint8_t key_end[total_key_len];

            if (nf_family == NFPROTO_IPV4) {
                struct in_addr start_v4, end_v4;
                calculate_ipv4_range(p, &start_v4, &end_v4);
                memcpy(key_start, &start_v4, sizeof(struct in_addr));
                memcpy(key_end, &end_v4, sizeof(struct in_addr));
            } else if (nf_family == NFPROTO_IPV6) {
                struct in6_addr start_v6, end_v6;
                calculate_ipv6_range(p, &start_v6, &end_v6);
                memcpy(key_start, &start_v6, sizeof(struct in6_addr));
                memcpy(key_end, &end_v6, sizeof(struct in6_addr));
            }

            concat_port_to_key(nfse, key_start, key_end, ip_len, ip_len);

            nftnl_set_elem_set(elem, NFTNL_SET_ELEM_KEY, key_start, total_key_len);
            if (memcmp(key_start, key_end, total_key_len) != 0) {
                // only set the end key if it's different from the start key
                nftnl_set_elem_set(elem, NFTNL_SET_ELEM_KEY_END, key_end, total_key_len);
            }
        }
        break;

        case IPSET_NET_NET:
        {
            uint32_t total_key_len = ip_len * 2;
            uint8_t key_start[total_key_len];
            uint8_t key_end[total_key_len];

            build_net_net_key(nf_family, &nfse->src, &nfse->dst, key_start, key_end);

            nftnl_set_elem_set(elem, NFTNL_SET_ELEM_KEY, key_start, total_key_len);

            if (memcmp(key_start, key_end, total_key_len) != 0)
                nftnl_set_elem_set(elem, NFTNL_SET_ELEM_KEY_END, key_end, total_key_len);
        }
        break;

        case IPSET_NET_PORT_NET:
        {
            uint32_t total_key_len = ip_len * 2 + PORT_INDEX_LEN;
            uint8_t key_start[total_key_len];
            uint8_t key_end[total_key_len];

            build_net_net_key(nf_family, &nfse->src, &nfse->dst, key_start, key_end);

            concat_port_to_key(nfse, key_start, key_end, ip_len * 2, ip_len);

            nftnl_set_elem_set(elem, NFTNL_SET_ELEM_KEY, key_start, total_key_len);
            if (memcmp(key_start, key_end, total_key_len) != 0)
                nftnl_set_elem_set(elem, NFTNL_SET_ELEM_KEY_END, key_end, total_key_len);
        }
        break;

        default:
            break;
    }

    // Add the element to the set and return.
    nftnl_set_elem_add(set, elem);

    return set;
}

ssize_t netlink_nft_setelem_msg_encode(bool add, struct zebra_pbr_ipset_entry *nfse, struct zebra_pbr_ipset * nfs, void *data)
{
    assert(nfse && nfs);

    struct nftnl_set * set = encode_nftnl_setelem(nfse, nfs);
    if (!set) {
        return -1;
    }

    int cmd = add ? NFT_MSG_NEWSETELEM : NFT_MSG_DELSETELEM;
    int flags = NLM_F_REQUEST | NLM_F_ACK;
    if (add) {
        flags |= NLM_F_CREATE;
    }

    struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(data,
                                                cmd,
                                                nfs->family == AF_INET ? NFPROTO_IPV4 : NFPROTO_IPV6,
                                                flags,
                                                nfse->unique);
    if (!nlh) {
        nftnl_set_free(set);
        return -1;
    }

    nftnl_set_elems_nlmsg_build_payload(nlh, set);

    nftnl_set_free(set);

    return nlh->nlmsg_len;
}

static struct nftnl_set * encode_nftnl_set(struct zebra_pbr_ipset *nfs)
{
    // check the input pointer
    assert(nfs);

    struct nftnl_set *nft_set = nftnl_set_alloc();
    if (!nft_set) {
        return NULL;
    }

    int nf_family = nfs->family == AF_INET ? NFPROTO_IPV4 : NFPROTO_IPV6;
    uint32_t ip_addr_len = nfs->family == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr);

    nftnl_set_set_str(nft_set, NFTNL_SET_TABLE, nfs->table == FILTER_TABLE ? "filter" : "mangle");
    nftnl_set_set_u32(nft_set, NFTNL_SET_FAMILY, nf_family);
    nftnl_set_set_str(nft_set, NFTNL_SET_NAME, nfs->ipset_name);
    nftnl_set_set_u32(nft_set, NFTNL_SET_KEY_TYPE, NFT_DATA_VALUE);
    nftnl_set_set_u32(nft_set, NFTNL_SET_FLAGS, NFT_SET_INTERVAL);

    switch (nfs->type) {
        case IPSET_NET:
            // hash:net -> single ip addr, with interval flag
            nftnl_set_set_u32(nft_set, NFTNL_SET_KEY_LEN, ip_addr_len);
            break;

        case IPSET_NET_PORT:
        {
            // hash:net,port ->  ip addr and inet_service
            uint8_t field_lens[] = {ip_addr_len, PORT_INDEX_LEN};
            nftnl_set_set_u32(nft_set, NFTNL_SET_KEY_LEN, ip_addr_len + PORT_INDEX_LEN);
            nftnl_set_set_data(nft_set, NFTNL_SET_DESC_CONCAT, field_lens, sizeof(field_lens));
            break;
        }

        case IPSET_NET_NET:
        {
            // hash:net,net
            uint8_t field_lens[] = {ip_addr_len, ip_addr_len};
            nftnl_set_set_u32(nft_set, NFTNL_SET_KEY_LEN, ip_addr_len * 2);
            nftnl_set_set_data(nft_set, NFTNL_SET_DESC_CONCAT, field_lens, sizeof(field_lens));
            break;
        }

        case IPSET_NET_PORT_NET:
        {
            // hash:net,port,net -> ip addr . ip addr .inet_service
            uint8_t field_lens[] = {ip_addr_len, ip_addr_len, PORT_INDEX_LEN};
            nftnl_set_set_u32(nft_set, NFTNL_SET_KEY_LEN, ip_addr_len * 2 + PORT_INDEX_LEN);
            nftnl_set_set_data(nft_set, NFTNL_SET_DESC_CONCAT, field_lens, sizeof(field_lens));
            break;
        }
        default:
            break; // Unsupported IPset type
    }

    return nft_set;
}

ssize_t netlink_nft_set_msg_encode(bool add, struct zebra_pbr_ipset *nfs, void *data)
{
    assert(nfs);

    struct nftnl_set *nft_set = encode_nftnl_set(nfs);
    if (!nft_set) {
        return -1;
    }

    int nf_family = nfs->family == AF_INET ? NFPROTO_IPV4 : NFPROTO_IPV6;
    int cmd = add ? NFT_MSG_NEWSET : NFT_MSG_DELSET;
    int flags = add ? (NLM_F_CREATE | NLM_F_ACK) : NLM_F_ACK;
    struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(data, cmd, nf_family, flags, nfs->unique);

    if (!nlh) {
        nftnl_set_free(nft_set);
        return -1;
    }

    nftnl_set_nlmsg_build_payload(nlh, nft_set);
    nftnl_set_free(nft_set);
    return nlh->nlmsg_len;
}

#endif /* HAVE_NETLINK */