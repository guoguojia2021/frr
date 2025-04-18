/* clang-format off */
#include <pthread.h>        // for pthread_mutex_lock, pthread_mutex_unlock
#include <libgen.h>
#include <dlfcn.h>

#include "frr_pthread.h"        // for frr_pthread
#include "hash.h"       // for hash, hash_clean, hash_create_size...
#include "log.h"        // for zlog_debug
#include "memory.h"     // for MTYPE_TMP, XFREE, XCALLOC, XMALLOC
#include "monotime.h"       // for monotime, monotime_since

#include "bfd_db.h"

/* clang-format on */

/* redis config*/
REDIS_INFO_S g_stBfdCounterRedisDbInfo = {0};
void *g_bfddhandleRedis = NULL; /* libredis++.so */
struct redis_user_ext g_bfdcounter_redis = {0};/* libredis++.so */
bool g_bBFDRedisInUse = false;

void bfd_db_init(void)
{
    int ret;
    char dbErrMsg[100] = {0};
    
    /* Open and load the .so */
    g_bfddhandleRedis = dlopen("/usr/lib/frr/libredis++.so", RTLD_NOW | RTLD_GLOBAL);
    if (g_bfddhandleRedis == NULL)
    {
        zlog_err("Bfd redis init could not load user extension redis.so, %s", dlerror());
        return;
    }

    /* Get the entry points */
    g_bfdcounter_redis.redis_Connect =
        (int (*)(REDIS_INFO_S *pstRediDbInfo, char *dbErrMsg, int msglen, DB_TYPE_E enDbType))
        dlsym(g_bfddhandleRedis, "Redis_Connect");
    g_bfdcounter_redis.redis_Set_Timeout =
        (void (*)(int timeout))
        dlsym(g_bfddhandleRedis, "Redis_Set_Timeout");
    g_bfdcounter_redis.redis_DisConnect =
        (void (*)(char *dbErrMsg, int msglen))
        dlsym(g_bfddhandleRedis, "Redis_DisConnect");

    g_bfdcounter_redis.redis_Db_DispConnectInfo =
        (int (*)(char *dbErrMsg, int msglen))
        dlsym(g_bfddhandleRedis, "Redis_Db_DispConnectInfo");

    g_bfdcounter_redis.redis_Db_HGetKeyAndValueNoCursor =
        (void (*)(char *key_prefix, char *field, char* result, int resultlen, char *dbErrMsg, int msglen, int *errNo, DB_TYPE_E enDbType))
        dlsym(g_bfddhandleRedis, "Redis_Db_HGetKeyAndValueNoCursor");

    g_bfdcounter_redis.redis_Db_HGetAllKeyAndValueNoCursor =
        (DB_KeyFieldValue_List* (*)(char *key_prefix, char *dbErrMsg, int msglen, DB_TYPE_E enDbType))
        dlsym(g_bfddhandleRedis, "Redis_Db_HGetAllKeyAndValueNoCursor");

    g_bfdcounter_redis.redis_Set_Timeout(1);
    snprintf(g_stBfdCounterRedisDbInfo.sentinelInfo.ip_addr, 128, "127.0.0.1");
    g_stBfdCounterRedisDbInfo.sentinelInfo.port = 6382;
    g_stBfdCounterRedisDbInfo.db = 2;

    ret = g_bfdcounter_redis.redis_Connect(&g_stBfdCounterRedisDbInfo, dbErrMsg, sizeof(dbErrMsg), REDIS_COUNTER_DB);
    if (ret == 0)
    {
        g_bBFDRedisInUse = true;
        zlog_info("Bfd redis connect success");
    }
    else
    {
        zlog_err("Bfd redis connect fail:%s", dbErrMsg);
    }
    zlog_info("Bfd redis init end");
    
    return;
}

void bfd_Db_GetSessStatus(struct bfd_session *bs)
{
    char keyType[BFD_DB_MAX_KEY_LEN] = {0};
    char field[BFD_DB_MAX_KEY_LEN] = {0};
    char result[BFD_DB_MAX_VALUE_LEN] = {0};
    char dbErrMsg[100] = {0};
    char tmpbuf[INET6_ADDRSTRLEN] = {0};
    DB_KeyFieldValue_List *dbNode = NULL;
    int ret = 0;

    if (!g_bBFDRedisInUse)
        return;

    if (!bs->counterOid)
    {
        snprintf(keyType, BFD_DB_MAX_KEY_LEN, "COUNTERS_BFD_SESSION_NAME_MAP");
        snprintf(field, BFD_DB_MAX_KEY_LEN, "%s|%u|%s", inet_ntop(bs->key.family, &bs->key.peer, tmpbuf,
              sizeof(tmpbuf)), bs->discrs.my_discr, bs->key.bfdname[0] ? bs->key.bfdname : "none");
        g_bfdcounter_redis.redis_Db_HGetKeyAndValueNoCursor(keyType, field, result, BFD_DB_MAX_VALUE_LEN, dbErrMsg, sizeof(dbErrMsg), &ret, REDIS_COUNTER_DB);
        /* oid:0x45000000001185 */
        sscanf(result, "oid:%llx", &bs->counterOid);
        keyType[0] = 0;
        field[0] = 0;
        dbErrMsg[0] = 0;
        result[0] = 0;
    }

    /* COUNTERS:oid:0x45000000001185 */
    snprintf(keyType, BFD_DB_MAX_KEY_LEN, "COUNTERS:oid:0x%llx", bs->counterOid);
    dbNode = g_bfdcounter_redis.redis_Db_HGetAllKeyAndValueNoCursor(keyType, dbErrMsg, sizeof(dbErrMsg), REDIS_COUNTER_DB);
    if (dbNode)
    {
        for(int i = 0; i < dbNode->fieldcnt; i++)
        {
            if(!strncmp(dbNode->field[i], "SAI_BFD_SESSION_STAT_OUT_PACKETS", strlen("SAI_BFD_SESSION_STAT_OUT_PACKETS")))
                bs->stats.hw_tx_ctrl_pkt = strtoull(dbNode->value[i], NULL, 10);
            else if(!strncmp(dbNode->field[i], "SAI_BFD_SESSION_STAT_IN_PACKETS", strlen("SAI_BFD_SESSION_STAT_IN_PACKETS")))
                bs->stats.hw_rx_ctrl_pkt = strtoull(dbNode->value[i], NULL, 10);
            free(dbNode->field[i]);
            free(dbNode->value[i]);
        }
        free(dbNode->field);
        free(dbNode->value);
        free(dbNode);
    }
    
    return;
}

