/* clang-format off */
#include <pthread.h>        // for pthread_mutex_lock, pthread_mutex_unlock
#include <libgen.h>
#include <dlfcn.h>

#include "frr_pthread.h"        // for frr_pthread
#include "hash.h"       // for hash, hash_clean, hash_create_size...
#include "log.h"        // for zlog_debug
#include "memory.h"     // for MTYPE_TMP, XFREE, XCALLOC, XMALLOC
#include "monotime.h"       // for monotime, monotime_since

#include "zebra_db.h"

/* clang-format on */

#define LINE_MAX_BUF_LEN 1024

/* redisÊý¾Ý¿âÅäÖÃ*/
REDIS_INFO_S g_stZebraRedisDbInfo = {0};
void *g_zebrahandleRedis = NULL; /* libredis++.so */
struct redis_user_ext g_zebra_redis = {0};/* libredis++.so */
bool g_bZebraRedisInUse = false;

void zebra_db_init(void)
{
    int ret;
    char dbErrMsg[100] = {0};
    
    /* Open and load the .so */
    g_zebrahandleRedis = dlopen("/usr/lib/frr/libredis++.so", RTLD_NOW | RTLD_GLOBAL);
    if (g_zebrahandleRedis == NULL)
    {
        zlog_err("Zebra redis init could not load user extension redis.so, %s", dlerror());
        return;
    }

    /* Get the entry points */
    g_zebra_redis.redis_Connect =
        (int (*)(REDIS_INFO_S *pstRediDbInfo, char *dbErrMsg, int msglen))
        dlsym(g_zebrahandleRedis, "Redis_Connect");
    g_zebra_redis.redis_Set_Timeout =
        (void (*)(int timeout))
        dlsym(g_zebrahandleRedis, "Redis_Set_Timeout");
    g_zebra_redis.redis_DisConnect =
        (void (*)(char *dbErrMsg, int msglen))
        dlsym(g_zebrahandleRedis, "Redis_DisConnect");

    g_zebra_redis.redis_Db_DispConnectInfo =
        (int (*)(char *dbErrMsg, int msglen))
        dlsym(g_zebrahandleRedis, "Redis_Db_DispConnectInfo");

    g_zebra_redis.redis_Db_HGetKeyAndValueNoCursor =
        (void (*)(char *key_prefix, char *field, char* result, int resultlen, char *dbErrMsg, int msglen, int *errNo, DB_TYPE_E enDbType))
        dlsym(g_zebrahandleRedis, "Redis_Db_HGetKeyAndValueNoCursor");

    g_zebra_redis.redis_Db_HGetAllKeyAndValueNoCursor =
        (DB_KeyFieldValue_List* (*)(char *key_prefix, char *field, char* result, int resultlen, char *dbErrMsg, int msglen, DB_TYPE_E enDbType))
        dlsym(g_zebrahandleRedis, "Redis_Db_HGetAllKeyAndValueNoCursor");
    g_zebra_redis.redis_Db_GetKey =
        (DB_Key_List* (*)(char *key_prefix, char *dbErrMsg, int msglen, DB_TYPE_E enDbType))
        dlsym(g_zebrahandleRedis, "Redis_Db_GetKey");

    g_zebra_redis.redis_Set_Timeout(1);
    snprintf(g_stZebraRedisDbInfo.sentinelInfo.ip_addr, 128, "127.0.0.1");
    g_stZebraRedisDbInfo.sentinelInfo.port = 6379;
    g_stZebraRedisDbInfo.db = 6;

    ret = g_zebra_redis.redis_Connect(&g_stZebraRedisDbInfo, dbErrMsg, sizeof(dbErrMsg), REDIS_STATE_DB);
    if (ret != 0)
    {
        zlog_err("Zebra redis connect fail:%s", dbErrMsg);
        return;
    }
    snprintf(g_stZebraRedisDbInfo.sentinelInfo.ip_addr, 128, "127.0.0.1");
    g_stZebraRedisDbInfo.sentinelInfo.port = 6379;
    g_stZebraRedisDbInfo.db = 4;

    ret = g_zebra_redis.redis_Connect(&g_stZebraRedisDbInfo, dbErrMsg, sizeof(dbErrMsg), REDIS_CONFIG_DB);
    if (ret != 0)
    {
        zlog_err("Zebra redis connect fail:%s", dbErrMsg);
        return;
    }
    g_bZebraRedisInUse = true;
    zlog_info("Zebra redis connect success");
    zlog_info("Zebra redis init end");
    
    return;
}

int zebra_Db_GetVrfAlias(char *vrfname, char *aliasName, int aliasNameLen)
{
    char keyType[ZEBRA_DB_MAX_KEY_LEN] = {0};
    char aliasKey[10] = {0};
    char result[ZEBRA_DB_MAX_KEY_LEN] = {0};
    char dbErrMsg[100] = {0};
    int errNo = 0;
    DB_Key_List *pKeyList = NULL;
    DB_Key_List *pKeyNode = NULL;
    char aliasId[10] = {0};

    if (!g_bZebraRedisInUse)
    {
        zlog_err("redis err,fail to get vrfname :%s", vrfname);
        return 1;
    }

    /*1.try to check mgmt vrf*/
    snprintf(keyType, ZEBRA_DB_MAX_KEY_LEN, "MGMT_VRF_CONFIG|vrf_global");
    g_zebra_redis.redis_Db_HGetKeyAndValueNoCursor(keyType, "vrf_name", result, 
                                    ZEBRA_DB_MAX_VALUE_LEN, dbErrMsg, sizeof(dbErrMsg), &errNo, REDIS_CONFIG_DB);
    if (strlen(result) && (strlen(result) == strlen(vrfname)) && !strncmp(vrfname, result, strlen(result)))
    {
        g_zebra_redis.redis_Db_HGetKeyAndValueNoCursor(keyType, "alias_name", result, 
                                    ZEBRA_DB_MAX_VALUE_LEN, dbErrMsg, sizeof(dbErrMsg), &errNo, REDIS_CONFIG_DB);
        if (strlen(result))
        {
            snprintf(aliasName, aliasNameLen, "%s", result);
            return 0;
        }
    }

    sscanf(vrfname, "Vrf%s", aliasId);

    snprintf(keyType, ZEBRA_DB_MAX_KEY_LEN, "VRF_ALIAS|*");
    pKeyList = g_zebra_redis.redis_Db_GetKey(keyType, dbErrMsg, sizeof(dbErrMsg), REDIS_STATE_DB);

    while(pKeyList)
    {
        g_zebra_redis.redis_Db_HGetKeyAndValueNoCursor(pKeyList->key, "vrf_nameid", result, ZEBRA_DB_MAX_VALUE_LEN, 
                                                                            dbErrMsg, sizeof(dbErrMsg), &errNo, REDIS_STATE_DB);
        if (strlen(result) && (strlen(result) == strlen(aliasId)) &&!strncmp(aliasId, result, strlen(result)))
        {
            sscanf(pKeyList->key, "VRF_ALIAS|%s", aliasKey);
            snprintf(aliasName, aliasNameLen, "%s", aliasKey);
            while(pKeyList)
            {
                pKeyNode = pKeyList;
                pKeyList = pKeyList->next;
                free(pKeyNode->key);
                free(pKeyNode);
            }
            return 0;
        }
        pKeyNode = pKeyList;
        pKeyList = pKeyList->next;
        free(pKeyNode->key);
        free(pKeyNode);
    }
    
    return 1;
}

