/**
 * zebra_db.h: for db
 */
#include "pathd/pathd.h"

#ifndef _PATH_DB_H
#define _PATH_DB_H

#include "/usr/local/include/sw/redis++/redis_db.h"

#define PATH_DB_MAX_KEY_LEN      128
#define PATH_DB_MAX_VALUE_LEN    1024

extern void path_db_init(void);

extern void sidlist_Db_SetEntry(struct srte_segment_list *segl);

extern void sidlist_Db_DelEntry(const char *name);

extern void sr_policy_Db_SetEntry(const struct srte_policy *policy, const struct srte_candidate_group *candidate_group);

extern void sr_policy_Db_DelEntry(const char *name);

#endif /* _PATH_DB_H */


