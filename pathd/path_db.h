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

extern void sidlist_Db_DelEntry(struct srte_segment_list *segl);

#endif /* _PATH_DB_H */


