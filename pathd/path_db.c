/* clang-format off */
#include <pthread.h>        // for pthread_mutex_lock, pthread_mutex_unlock
#include <libgen.h>
#include <dlfcn.h>

#include "frr_pthread.h"        // for frr_pthread
#include "hash.h"       // for hash, hash_clean, hash_create_size...
#include "zlog.h"        // for zlog_debug
#include "memory.h"     // for MTYPE_TMP, XFREE, XCALLOC, XMALLOC
#include "monotime.h"       // for monotime, monotime_since

#include "path_db.h"
#include "path_debug.h"

#define SRV6_SID_LIST_TABLE "SRV6_SID_LIST_TABLE"
#define TAG   "0"

/* clang-format on */

/* redis config*/
REDIS_INFO_S g_stSrv6SidListRedisDbInfo = {0};
void *g_sidlistHandleRedis = NULL; /* libredis++.so */
struct redis_user_ext g_sidlist_appdb_redis = {0};/* libredis++.so */
bool g_bPathRedisInUse = false;

void path_db_init(void)
{
    int ret;
    char dbErrMsg[100] = {0};

    /* Open and load the .so */
    g_sidlistHandleRedis = dlopen("/usr/lib/frr/libredis++.so", RTLD_NOW | RTLD_GLOBAL);
    if (g_sidlistHandleRedis == NULL)
    {
        zlog_err("Path redis init could not load user extension redis.so, %s", dlerror());
        return;
    }

    /* Get the entry points */
    g_sidlist_appdb_redis.redis_Connect =
        (int (*)(REDIS_INFO_S *pstRediDbInfo, char *dbErrMsg, int msglen, DB_TYPE_E enDbType))
        dlsym(g_sidlistHandleRedis, "Redis_Connect");
    g_sidlist_appdb_redis.redis_Set_Timeout =
        (void (*)(int timeout))
        dlsym(g_sidlistHandleRedis, "Redis_Set_Timeout");
    g_sidlist_appdb_redis.redis_DisConnect =
        (void (*)(char *dbErrMsg, int msglen))
        dlsym(g_sidlistHandleRedis, "Redis_DisConnect");

    g_sidlist_appdb_redis.redis_Db_DispConnectInfo =
        (int (*)(char *dbErrMsg, int msglen))
        dlsym(g_sidlistHandleRedis, "Redis_Db_DispConnectInfo");

    g_sidlist_appdb_redis.redis_Db_HGetKeyAndValueNoCursor =
        (void (*)(char *key_prefix, char *field, char* result, int resultlen, char *dbErrMsg, int msglen, int *errNo, DB_TYPE_E enDbType))
        dlsym(g_sidlistHandleRedis, "Redis_Db_HGetKeyAndValueNoCursor");

    g_sidlist_appdb_redis.redis_Db_GetKey =
        (DB_Key_List* (*)(char *key_prefix, char *dbErrMsg, int msglen, DB_TYPE_E enDbType))
        dlsym(g_sidlistHandleRedis, "Redis_Db_GetKey");

    g_sidlist_appdb_redis.redis_Db_SetKeyAndFValue =
        (int (*)(char *key, DB_FieldValue_List *pstDataLst, char *dbErrMsg, int msglen, DB_TYPE_E enDbType))
        dlsym(g_sidlistHandleRedis, "Redis_Db_SetKeyAndFValue");

    g_sidlist_appdb_redis.redis_Db_DelKeyLst =
        (int (*)(DB_Key_List *pstKeylist, char *dbErrMsg, int msglen, DB_TYPE_E enDbType))
        dlsym(g_sidlistHandleRedis, "Redis_Db_DelKeyLst");

    g_sidlist_appdb_redis.redis_PublishMsg =
        (int (*)(char *key, char *msg, DB_TYPE_E enDbType))
        dlsym(g_sidlistHandleRedis, "Redis_PublishMsgForce");

    g_sidlist_appdb_redis.redis_Db_SetSadd =
        (int (*)(char *key, char *member, char *dbErrMsg, int msglen, DB_TYPE_E enDbType))
        dlsym(g_sidlistHandleRedis, "Redis_Db_SetSadd");

    /* alias redis-appdb='redis-cli  -n 0 -p 6380' */
    g_sidlist_appdb_redis.redis_Set_Timeout(1);
    snprintf(g_stSrv6SidListRedisDbInfo.sentinelInfo.ip_addr, 128, "127.0.0.1");
    g_stSrv6SidListRedisDbInfo.sentinelInfo.port = 6380;
    g_stSrv6SidListRedisDbInfo.db = 0;

    ret = g_sidlist_appdb_redis.redis_Connect(&g_stSrv6SidListRedisDbInfo, dbErrMsg, sizeof(dbErrMsg), REDIS_APP_DB);
    if (ret == 0)
    {
        g_bPathRedisInUse = true;
        if (IS_PATHD_DEBUG_DB)
            zlog_debug("Path redis connect success");
    }
    else
    {
        zlog_err("Path redis connect fail:%s", dbErrMsg);
    }
    if (IS_PATHD_DEBUG_DB)
        zlog_debug("Path redis init end");

    return;
}

static DB_FieldValue_List *new_Sidlist_DB_Data(char *key, char *field, char *value)
{
    DB_FieldValue_List *pstDataLst = NULL;
    pstDataLst = (DB_FieldValue_List *)malloc(sizeof(DB_FieldValue_List));
    if (!pstDataLst)
    {
        zlog_err("pstDataLst malloc failed");
        goto err_proc;
    }
    memset(pstDataLst, 0, sizeof(DB_FieldValue_List));

    /*set table:key*/
    pstDataLst->key = strdup(key);
    if (!pstDataLst->key)
    {
        zlog_err("pstDataLst->key malloc failed");
        goto err_proc;
    }
    pstDataLst->key_length = strlen(key);

    /*set field*/
    pstDataLst->field = strdup(field);
    if (!pstDataLst->field)
    {
        zlog_err("pstDataLst->field malloc failed");
        goto err_proc;
    }
    pstDataLst->field_length = strlen(field);

    /* set value*/
    pstDataLst->value = strdup(value);
    if (!pstDataLst->value)
    {
        zlog_err("pstDataLst->value malloc failed");
        goto err_proc;
    }
    pstDataLst->value_length = strlen(value);
    return pstDataLst;

err_proc:
    if (pstDataLst->value)
        free(pstDataLst->value);
    if (pstDataLst->field)
        free(pstDataLst->field);
    if (pstDataLst->key)
        free(pstDataLst->key);
    if (pstDataLst)
        free(pstDataLst);
    return NULL;
}

static void release_Sidlist_DB_Data(DB_FieldValue_List *pstDataLst)
{
    DB_FieldValue_List *dataTmp, *plistTmp;
    dataTmp = pstDataLst;
    while (dataTmp) {
        plistTmp = dataTmp->next;

        if (dataTmp->value)
            free(dataTmp->value);
        if (dataTmp->field)
            free(dataTmp->field);
        if (dataTmp->key)
            free(dataTmp->key);
        if (dataTmp)
            free(dataTmp);

        dataTmp = plistTmp;
    }
}

void sidlist_Db_SetEntry(struct srte_segment_list *segl)
{
    int ret;
    char key[PATH_DB_MAX_KEY_LEN] = {0};
    char field[PATH_DB_MAX_KEY_LEN] = {0};
    char value[PATH_DB_MAX_VALUE_LEN] = {0};
    char seg_value[PATH_DB_MAX_VALUE_LEN] = {0};
    char set_key[PATH_DB_MAX_KEY_LEN] = {0};
    char set_value[PATH_DB_MAX_VALUE_LEN] = {0};
    char channel[PATH_DB_MAX_KEY_LEN] = {0};
    char dbErrMsg[100] = {0};
    char tmpbuf[INET6_ADDRSTRLEN] = {0};
    char G[] = "G";
    bool first = true;
    struct srte_segment_entry *s_entry;
    DB_FieldValue_List *pstDataLst = NULL;

    if (!g_bPathRedisInUse)
        return;

    /* set segment key and field*/
    snprintf(key, PATH_DB_MAX_KEY_LEN, "_%s:%s",SRV6_SID_LIST_TABLE, segl->name);
    snprintf(field, PATH_DB_MAX_KEY_LEN, "path");

    /* set segment value*/
	RB_FOREACH (s_entry, srte_segment_entry_head, &segl->segments)
    {
        if (first)
        {
            snprintf(value, PATH_DB_MAX_VALUE_LEN, "%s",
                inet_ntop(s_entry->srv6_sid_value.ipa_type, &s_entry->srv6_sid_value.ipaddr_v6,
                tmpbuf, sizeof(tmpbuf)));
            first = false;
        }
        else
        {
            strncpy(seg_value, value, PATH_DB_MAX_VALUE_LEN);
            snprintf(value, PATH_DB_MAX_VALUE_LEN, "%s,%s", seg_value,
                inet_ntop(s_entry->srv6_sid_value.ipa_type, &s_entry->srv6_sid_value.ipaddr_v6,
                tmpbuf, sizeof(tmpbuf)));
        }
    }

    pstDataLst = new_Sidlist_DB_Data(key, field, value);
    if (pstDataLst == NULL)
    {
        zlog_err("create field segment failed.");
        return;
    }
    pstDataLst->next = NULL;

    ret = g_sidlist_appdb_redis.redis_Db_SetKeyAndFValue(key, pstDataLst, dbErrMsg, sizeof(dbErrMsg), REDIS_APP_DB);
    if (ret)
    {
        zlog_err("redis_Db_SetKeyAndFValue error code : %d", ret);
        release_Sidlist_DB_Data(pstDataLst);
        return;
    }

    /*sadd KEY_SET*/
    snprintf(set_key, PATH_DB_MAX_KEY_LEN, "%s_KEY_SET",SRV6_SID_LIST_TABLE);
    snprintf(set_value, PATH_DB_MAX_VALUE_LEN, "%s", segl->name);
    ret = g_sidlist_appdb_redis.redis_Db_SetSadd(set_key, set_value, dbErrMsg, sizeof(dbErrMsg), REDIS_APP_DB);
    if (ret)
    {
        zlog_err("redis_Db_SetSadd error code : %d", ret);
        return;
    }

    snprintf(channel, PATH_DB_MAX_KEY_LEN, "%s_CHANNEL@%s",SRV6_SID_LIST_TABLE, TAG);
    if (IS_PATHD_DEBUG_DB)
        zlog_debug("redis publishMsg channel : %s", channel);
    ret = g_sidlist_appdb_redis.redis_PublishMsg(channel, G, REDIS_APP_DB);
    if (ret)
    {
        zlog_err("redis_PublishMsg error code : %d", ret);
    }

    segl->installed = true;
    release_Sidlist_DB_Data(pstDataLst);
    return;
}

void sidlist_Db_DelEntry(struct srte_segment_list *segl)
{
    int ret;
    char key[PATH_DB_MAX_KEY_LEN] = {0};
    char set_key[PATH_DB_MAX_KEY_LEN] = {0};
    char set_value[PATH_DB_MAX_VALUE_LEN] = {0};
    char channel[PATH_DB_MAX_KEY_LEN] = {0};
    char dbErrMsg[100] = {0};
    char G[] = "G";
    DB_Key_List item = {0};
    const char *name = segl->name;

    if (!g_bPathRedisInUse)
        return;

    /* del key*/
    snprintf(key, PATH_DB_MAX_KEY_LEN, "SRV6_SID_LIST_TABLE:%s", name);
    item.next = NULL;
    item.key = key;

    ret = g_sidlist_appdb_redis.redis_Db_DelKeyLst(&item, dbErrMsg, sizeof(dbErrMsg), REDIS_APP_DB);
    if (ret)
    {
        zlog_err("redis_Db_DelKeyLst error code : %d", ret);
        return;
    }

    /*sadd DEL_SET*/
    snprintf(set_key, PATH_DB_MAX_KEY_LEN, "%s_DEL_SET",SRV6_SID_LIST_TABLE);
    snprintf(set_value, PATH_DB_MAX_VALUE_LEN, "%s", name);
    ret = g_sidlist_appdb_redis.redis_Db_SetSadd(set_key, set_value, dbErrMsg, sizeof(dbErrMsg), REDIS_APP_DB);
    if (ret)
    {
        zlog_err("redis_Db_SetSadd DEL_SET error code : %d", ret);
        return;
    }

    /*sadd KEY_SET*/
    snprintf(set_key, PATH_DB_MAX_KEY_LEN, "%s_KEY_SET",SRV6_SID_LIST_TABLE);
    ret = g_sidlist_appdb_redis.redis_Db_SetSadd(set_key, set_value, dbErrMsg, sizeof(dbErrMsg), REDIS_APP_DB);
    if (ret)
    {
        zlog_err("redis_Db_SetSadd KEY_SET error code : %d", ret);
        return;
    }

    /*publish*/
    snprintf(channel, PATH_DB_MAX_KEY_LEN, "%s_CHANNEL@%s",SRV6_SID_LIST_TABLE, TAG);
    if (IS_PATHD_DEBUG_DB)
        zlog_debug("redis publishMsg channel : %s", channel);
    ret = g_sidlist_appdb_redis.redis_PublishMsg(channel, G, REDIS_APP_DB);
    if (ret)
    {
        zlog_err("redis_PublishMsg error code : %d", ret);
    }

    segl->installed = false;

    return;
}
