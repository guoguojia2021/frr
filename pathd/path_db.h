/**
 * zebra_db.h: for db
 */
#include "pathd/pathd.h"

#ifndef _PATH_DB_H
#define _PATH_DB_H

#include "/usr/local/include/sw/redis++/redis_db.h"

#define PATH_DB_MAX_KEY_LEN      256
#define PATH_DB_MAX_VALUE_LEN    1024

extern void path_db_init(void);

extern void redis_Db_Sid_List_SetEntry(struct srte_segment_list *segl);

extern void redis_Db_Sid_List_DelEntry(struct srte_segment_list *segl);

extern void redis_Db_Policy_SetEntry(struct srte_policy *policy);

extern void redis_Db_Policy_DelEntry(struct srte_policy *policy);

extern void redis_Db_Cpath_SetEntry(struct srte_candidate *candidate);

extern void redis_Db_Cpath_DelEntry(struct srte_candidate *candidate);
#endif /* _PATH_DB_H */


