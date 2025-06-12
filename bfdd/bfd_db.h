/**
 * bfd_db.h: for bfd db operations
 */
#include "bfd.h"

#ifndef _BFD_DB_H_
#define _BFD_DB_H_

#include "/usr/local/include/sw/redis++/redis_db.h"

#define BFD_DB_MAX_KEY_LEN      320
#define BFD_DB_MAX_VALUE_LEN    50

extern void bfd_db_init(void);
extern void bfd_Db_SetSessStatus(struct bfd_session *bs);
extern void bfd_Db_ClearSessStatus(struct bfd_session *bs);
extern void bfd_db_deinit(void);

#endif /* _BFD_DB_H_ */


