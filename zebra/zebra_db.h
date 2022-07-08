/**
 * zebra_db.h: for db
 */

#ifndef _Z_DB_H
#define _Z_DB_H

//#include "/usr/local/include/sw/redis++/redis_db.h"
#include "/usr/local/include/sw/redis++/redis_db.h"


#define ZEBRA_DB_MAX_KEY_LEN      256
#define ZEBRA_DB_MAX_VALUE_LEN    50

extern void zebra_db_init(void);
extern int zebra_Db_GetVrfAlias(char *vrfname, char *aliasName, int aliasNameLen);


#endif /* _ZEBRA_BFD_H */


