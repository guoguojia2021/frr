/**
 * zebra_db.h: for db
 */

#ifndef _Z_DB_H
#define _Z_DB_H

//#include "/usr/local/include/sw/redis++/redis_db.h"
#include "/usr/local/include/sw/redis++/redis_db.h"

#include "srv6.h"
#include "prefix.h"

#define ZEBRA_DB_MAX_KEY_LEN      256
#define ZEBRA_DB_MAX_VALUE_LEN    256
#define ZEBRA_DB_MAX_SID_LEN      128
#define ZEBRA_DB_IF_MAX_VALUE_LEN 50 * 50

extern void zebra_db_init(void);
extern int zebra_Db_GetVrfAlias(const char *vrfname, char *aliasName, int aliasNameLen);

extern void zebra_Db_Set_SRV6_LOCAL_SID(const struct in6_addr *result_sid, const char *vrf_name,
                    enum seg6local_action_t act, const struct seg6local_context *ctx, const char *ifname, const struct ipaddr *nexthop,
                    const bool sidmarking);
extern void zebra_Db_Set_SRV6_LOCAL_ENDX_SID(const struct in6_addr *result_sid, const char *vrf_name,
                    enum seg6local_action_t act, const struct seg6local_context *ctx, const struct list *sid_endx_params);
extern void zebra_Db_Del_SRV6_LOCAL_SID(const struct in6_addr *result_sid, const struct seg6local_context *ctx);


#endif /* _ZEBRA_BFD_H */


