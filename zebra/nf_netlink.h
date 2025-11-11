#ifndef _ZEBRA_NF_NETLINK_H
#define _ZEBRA_NF_NETLINK_H

#include "config.h"
#include <stdint.h>
#include <sys/types.h>
#include <stdbool.h>
#include <netinet/in.h>
#include "zebra_pbr.h"

#ifdef HAVE_NETLINK

#ifdef __cplusplus
extern "C" {
#endif


// Netfilter families (from linux/netfilter.h)
#define NFPROTO_IPV4 2
#define NFPROTO_IPV6 10

#define NF_DROP 0
#define NF_ACCEPT 1

/**
 * @brief Fill the netlink buffer with nft information.
 *
 * @param[in]  add	   	 Whether cmd is NFT_MSG_NEWRULE or NFT_MSG_DELRULE
 * @param[in]  nft     	 Pointer to a struct that contains the nftable information.
 * @param[out] data      Pointer to the buffer to be filled.
 * @return     ssize_t   Size of the filled buffer, -1 on failure.
 */
extern ssize_t netlink_nft_rule_msg_encode(bool add, struct zebra_pbr_iptable *nft, void *data);

/**
 * @brief Fill the netlink buffer with nf set information.
 *
 * @param[in]  add	   	 Whether cmd is NFT_MSG_NEWSET or NFT_MSG_DELSET
 * @param[in]  nfs     	 Pointer to a struct that contains the nf set information.
 * @param[out] data      Pointer to the buffer to be filled.
 * @return     ssize_t   Size of the filled buffer, -1 on failure.
 */
extern ssize_t netlink_nft_set_msg_encode(bool add, struct zebra_pbr_ipset *nfs, void *data);

/**
 * @brief Fill the netlink buffer with nf set element information.
 *
 * @param[in]  add	   	 Whether cmd is NFT_MSG_NEWSETELEM or NFT_MSG_DELSETELEM
 * @param[in]  nfse    	 Pointer to a struct that contains the nf set element information.
 * @param[in]  nfs     	 Pointer to a struct that contains the nf set information.
 * @param[out] data      Pointer to the buffer to be filled.
 * @return     ssize_t   Size of the filled buffer, -1 on failure.
 */
extern ssize_t netlink_nft_setelem_msg_encode(bool add, struct zebra_pbr_ipset_entry *nfse, struct zebra_pbr_ipset *nfs, void *data);


#ifdef __cplusplus
}
#endif

#endif /* HAVE_NETLINK */

#endif /* _ZEBRA_NF_NETLINK_H */
