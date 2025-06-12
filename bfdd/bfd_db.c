/* clang-format off */
#include <pthread.h>        // for pthread_mutex_lock, pthread_mutex_unlock
#include <libgen.h>
#include <dlfcn.h>

#include "frr_pthread.h"        // for frr_pthread
#include "hash.h"       // for hash, hash_clean, hash_create_size...
#include "log.h"        // for zlog_debug
//#include "zlog.h"        // for zlog_debug
#include "bfd_db.h"

/* redis config*/
struct redis_user_ext g_bfdstatus_redis = {0};/* libredis++.so */
REDIS_INFO_S g_stBfdStateRedisDbInfo = {0};
void *g_bfddhandleRedis = NULL;
bool g_bBFDRedisInUse = false;

#define BFD_SESSION_ATTR_TIMESTAMP                  "update_time"
#define BFD_SESSION_ATTR_STATUS                     "status"
#define BFD_SESSION_STATE_TABLE_NAME                "BFD_STATE"

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
    g_bfdstatus_redis.redis_Connect =
        (int (*)(REDIS_INFO_S *pstRediDbInfo, char *dbErrMsg, int msglen, DB_TYPE_E enDbType))
        dlsym(g_bfddhandleRedis, "Redis_Connect");
    g_bfdstatus_redis.redis_Set_Timeout =
        (void (*)(int timeout))
        dlsym(g_bfddhandleRedis, "Redis_Set_Timeout");
    g_bfdstatus_redis.redis_DisConnect =
        (void (*)(char *dbErrMsg, int msglen))
        dlsym(g_bfddhandleRedis, "Redis_DisConnect");

    g_bfdstatus_redis.redis_Db_SetKeyAndFValue =
        (int (*)(char *key, DB_FieldValue_List *pstDataLst, char *dbErrMsg, int msglen, DB_TYPE_E enDbType))
        dlsym(g_bfddhandleRedis, "Redis_Db_SetKeyAndFValue");

    g_bfdstatus_redis.redis_Db_DelKeyLst =
        (int (*)(DB_Key_List *pstKeylist, char *dbErrMsg, int msglen, DB_TYPE_E enDbType))
        dlsym(g_bfddhandleRedis, "Redis_Db_DelKeyLst");

    g_bfdstatus_redis.redis_Set_Timeout(1);
    snprintf(g_stBfdStateRedisDbInfo.sentinelInfo.ip_addr, 128, "127.0.0.1");
    g_stBfdStateRedisDbInfo.sentinelInfo.port = 6379;
    g_stBfdStateRedisDbInfo.db = 6;

    ret = g_bfdstatus_redis.redis_Connect(&g_stBfdStateRedisDbInfo, dbErrMsg, sizeof(dbErrMsg), REDIS_STATE_DB);
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

void bfd_Db_SetSessStatus(struct bfd_session *bs)
{
    char keyType[BFD_DB_MAX_KEY_LEN] = {0};
    char dbErrMsg[100] = {0};
    char peer[INET6_ADDRSTRLEN] = {0};
	char timebuf[MONOTIME_STRLEN] = {0};
    struct tm tm;
	struct timeval _time, time_real;

    DB_FieldValue_List fv_status = {0};
    DB_FieldValue_List fv_timestamp = {0};

    int ret = 0;

    if (!g_bBFDRedisInUse)
        return;

    /* KEY: BFD_STATE|2000::56|4277021251|bfd1 */
    inet_ntop(bs->key.family, &bs->key.peer, peer, sizeof(peer));
    snprintf(keyType, BFD_DB_MAX_KEY_LEN, "%s|%s|%u|%s", BFD_SESSION_STATE_TABLE_NAME, peer, bs->discrs.my_discr, bs->bfd_name[0]?bs->bfd_name: "none");

    fv_status.key = keyType;
    fv_status.key_length = strlen(keyType);
    fv_status.field = (char *)BFD_SESSION_ATTR_STATUS;
    fv_status.field_length = strlen(BFD_SESSION_ATTR_STATUS);

	switch (bs->ses_state) {
	case PTM_BFD_ADM_DOWN:
        fv_status.value = (char *)"shutdown";
		break;
	case PTM_BFD_DOWN:
		fv_status.value = (char *)"down";
		break;
	case PTM_BFD_INIT:
        fv_status.value = (char *)"init";
		break;
	case PTM_BFD_UP:
        fv_status.value = (char *)"up";
		break;

	default:
        fv_status.value = (char *)"unknown";
		break;
	}
    fv_status.value_length = strlen(fv_status.value);
    fv_status.next = &fv_timestamp;

    //get current rfc-3339 time
    _time.tv_sec = monotime(NULL);
	_time.tv_usec = 0;
	monotime_to_realtime(&_time, &time_real);
	gmtime_r(&time_real.tv_sec, &tm);
	strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%S", &tm);

    fv_timestamp.key = keyType;
    fv_timestamp.key_length = strlen(keyType);
    fv_timestamp.field = (char *)BFD_SESSION_ATTR_TIMESTAMP;
    fv_timestamp.field_length = strlen(BFD_SESSION_ATTR_TIMESTAMP);
    fv_timestamp.value = timebuf;
    fv_timestamp.value_length = strlen(timebuf);

    ret = g_bfdstatus_redis.redis_Db_SetKeyAndFValue(keyType, &fv_status, dbErrMsg, sizeof(dbErrMsg), REDIS_STATE_DB);
    if (ret)
    {
        zlog_err("bfd_Db_SetSessStatus error:%d, key:%s, msg:%s", ret, keyType, dbErrMsg);
    }

    return;
}

void bfd_Db_ClearSessStatus(struct bfd_session *bs)
{
    char keyType[BFD_DB_MAX_KEY_LEN] = {0};
    char dbErrMsg[100] = {0};
    char peer[INET6_ADDRSTRLEN] = {0};

    DB_Key_List item = {0};
    int ret = 0;

    if (!g_bBFDRedisInUse)
        return;

    inet_ntop(bs->key.family, &bs->key.peer, peer, sizeof(peer));
    snprintf(keyType, BFD_DB_MAX_KEY_LEN, "%s|%s|%u|%s", BFD_SESSION_STATE_TABLE_NAME, peer, bs->discrs.my_discr, bs->bfd_name[0]?bs->bfd_name: "none");

    item.key = keyType;
    ret = g_bfdstatus_redis.redis_Db_DelKeyLst(&item, dbErrMsg, sizeof(dbErrMsg), REDIS_STATE_DB);
    if (ret)
    {
        zlog_err("bfd_Db_ClearSessStatus error:%d, key:%s, msg:%s", ret, keyType, dbErrMsg);
    }

    return;
}

void bfd_db_deinit(void)
{
    char dbErrMsg[100] = {0};

    if (!g_bBFDRedisInUse)
        return;

    g_bfdstatus_redis.redis_DisConnect(dbErrMsg, sizeof(dbErrMsg));
    g_bBFDRedisInUse = false;

    return;
}