/**
 * zebra_db.h: for db
 */
#include "bfd.h"

#ifndef _Z_DB_H
#define _Z_DB_H

#include "/usr/local/include/sw/redis++/redis_db.h"

#define BFD_DB_MAX_KEY_LEN      320
#define BFD_DB_MAX_VALUE_LEN    50

extern void bfd_db_init(void);
extern void bfd_Db_GetSessStatus(struct bfd_session *bs);


#endif /* _ZEBRA_BFD_H */


