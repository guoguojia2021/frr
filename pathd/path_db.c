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
#define SRV6_POLICY_TABLE "SRV6_POLICY_STATE"
#define TAG   "0"

/* clang-format on */

/* redis config*/
REDIS_INFO_S g_stAppRedisDbInfo = {0};
REDIS_INFO_S g_stStateRedisDbInfo = {0};
void *g_HandleRedis = NULL; /* libredis++.so */
struct redis_user_ext g_redis_appdb = {0};/* libredis++.so */
struct redis_user_ext g_redis_statedb = {0};/* libredis++.so */
bool g_bPathAppRedisInUse = false;
bool g_bPathStateRedisInUse = false;

static void path_monotime_to_realtime(time_t time, char *realtime)
{
	struct tm tm;
	struct timeval _time, time_real;

	_time.tv_sec = time;
	_time.tv_usec = 0;
	monotime_to_realtime(&_time, &time_real);

	gmtime_r(&time_real.tv_sec, &tm);

	/* rfc-3339 format */
	strftime(realtime, MONOTIME_STRLEN, "%Y-%m-%dT%H:%M:%S", &tm);
    return;
}


void path_db_init(void)
{
    int ret;
    char dbErrMsg[100] = {0};

    /* Open and load the .so */
    g_HandleRedis = dlopen("/usr/lib/frr/libredis++.so", RTLD_NOW | RTLD_GLOBAL);
    if (g_HandleRedis == NULL)
    {
        zlog_err("Path redis init could not load user extension redis.so, %s", dlerror());
        return;
    }

    /* Get the entry points */
    g_redis_appdb.redis_Connect =
        (int (*)(REDIS_INFO_S *pstRediDbInfo, char *dbErrMsg, int msglen, DB_TYPE_E enDbType))
        dlsym(g_HandleRedis, "Redis_Connect");
    g_redis_appdb.redis_Set_Timeout =
        (void (*)(int timeout))
        dlsym(g_HandleRedis, "Redis_Set_Timeout");
    g_redis_appdb.redis_DisConnect =
        (void (*)(char *dbErrMsg, int msglen))
        dlsym(g_HandleRedis, "Redis_DisConnect");

    g_redis_appdb.redis_Db_DispConnectInfo =
        (int (*)(char *dbErrMsg, int msglen))
        dlsym(g_HandleRedis, "Redis_Db_DispConnectInfo");

    g_redis_appdb.redis_Db_HGetKeyAndValueNoCursor =
        (void (*)(char *key_prefix, char *field, char* result, int resultlen, char *dbErrMsg, int msglen, int *errNo, DB_TYPE_E enDbType))
        dlsym(g_HandleRedis, "Redis_Db_HGetKeyAndValueNoCursor");

    g_redis_appdb.redis_Db_GetKey =
        (DB_Key_List* (*)(char *key_prefix, char *dbErrMsg, int msglen, DB_TYPE_E enDbType))
        dlsym(g_HandleRedis, "Redis_Db_GetKey");

    g_redis_appdb.redis_Db_SetKeyAndFValue =
        (int (*)(char *key, DB_FieldValue_List *pstDataLst, char *dbErrMsg, int msglen, DB_TYPE_E enDbType))
        dlsym(g_HandleRedis, "Redis_Db_SetKeyAndFValue");

    g_redis_appdb.redis_Db_DelKeyLst =
        (int (*)(DB_Key_List *pstKeylist, char *dbErrMsg, int msglen, DB_TYPE_E enDbType))
        dlsym(g_HandleRedis, "Redis_Db_DelKeyLst");

    g_redis_appdb.redis_PublishMsg =
        (int (*)(char *key, char *msg, DB_TYPE_E enDbType))
        dlsym(g_HandleRedis, "Redis_PublishMsgForce");

    g_redis_appdb.redis_Db_SetSadd =
        (int (*)(char *key, char *member, char *dbErrMsg, int msglen, DB_TYPE_E enDbType))
        dlsym(g_HandleRedis, "Redis_Db_SetSadd");

    /* alias redis-appdb='redis-cli  -n 0 -p 6380' */
    g_redis_appdb.redis_Set_Timeout(1);
    snprintf(g_stAppRedisDbInfo.sentinelInfo.ip_addr, 128, "127.0.0.1");
    g_stAppRedisDbInfo.sentinelInfo.port = 6380;
    g_stAppRedisDbInfo.db = 0;

    ret = g_redis_appdb.redis_Connect(&g_stAppRedisDbInfo, dbErrMsg, sizeof(dbErrMsg), REDIS_APP_DB);
    if (ret == 0)
    {
        g_bPathAppRedisInUse = true;
        if (IS_PATHD_DEBUG_DB)
            zlog_debug("Path redis appdb connect success");
    }
    else
    {
        zlog_err("Path redis appdb connect fail:%s", dbErrMsg);
    }

    /* Get the entry points */
    g_redis_statedb.redis_Connect =
        (int (*)(REDIS_INFO_S *pstRediDbInfo, char *dbErrMsg, int msglen, DB_TYPE_E enDbType))
        dlsym(g_HandleRedis, "Redis_Connect");
    g_redis_statedb.redis_Set_Timeout =
        (void (*)(int timeout))
        dlsym(g_HandleRedis, "Redis_Set_Timeout");
    g_redis_statedb.redis_DisConnect =
        (void (*)(char *dbErrMsg, int msglen))
        dlsym(g_HandleRedis, "Redis_DisConnect");

    g_redis_statedb.redis_Db_DispConnectInfo =
        (int (*)(char *dbErrMsg, int msglen))
        dlsym(g_HandleRedis, "Redis_Db_DispConnectInfo");

    g_redis_statedb.redis_Db_HGetKeyAndValueNoCursor =
        (void (*)(char *key_prefix, char *field, char* result, int resultlen, char *dbErrMsg, int msglen, int *errNo, DB_TYPE_E enDbType))
        dlsym(g_HandleRedis, "Redis_Db_HGetKeyAndValueNoCursor");

    g_redis_statedb.redis_Db_GetKey =
        (DB_Key_List* (*)(char *key_prefix, char *dbErrMsg, int msglen, DB_TYPE_E enDbType))
        dlsym(g_HandleRedis, "Redis_Db_GetKey");

    g_redis_statedb.redis_Db_SetKeyAndFValue =
        (int (*)(char *key, DB_FieldValue_List *pstDataLst, char *dbErrMsg, int msglen, DB_TYPE_E enDbType))
        dlsym(g_HandleRedis, "Redis_Db_SetKeyAndFValue");

    g_redis_statedb.redis_Db_DelKeyLst =
        (int (*)(DB_Key_List *pstKeylist, char *dbErrMsg, int msglen, DB_TYPE_E enDbType))
        dlsym(g_HandleRedis, "Redis_Db_DelKeyLst");

    /* alias redis-appdb='redis-cli  -n 6 -p 6379' */
    g_redis_statedb.redis_Set_Timeout(1);
    snprintf(g_stStateRedisDbInfo.sentinelInfo.ip_addr, 128, "127.0.0.1");
    g_stStateRedisDbInfo.sentinelInfo.port = 6379;
    g_stStateRedisDbInfo.db = 6;

    ret = g_redis_statedb.redis_Connect(&g_stStateRedisDbInfo, dbErrMsg, sizeof(dbErrMsg), REDIS_STATE_DB);
    if (ret == 0)
    {
        g_bPathStateRedisInUse = true;
        if (IS_PATHD_DEBUG_DB)
            zlog_debug("Path redis statedb connect success");
    }
    else
    {
        zlog_err("Path redis statedb connect fail:%s", dbErrMsg);
    }
    if (IS_PATHD_DEBUG_DB)
        zlog_debug("Path redis init end");

    return;
}

static DB_FieldValue_List *new_redis_DB_Data(char *key, char *field, char *value)
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

static void release_redis_DB_Data(DB_FieldValue_List *pstDataLst)
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

void redis_Db_Sid_List_SetEntry(struct srte_segment_list *segl)
{
    int ret;
    char key[PATH_DB_MAX_KEY_LEN] = {0};
    char field[PATH_DB_MAX_KEY_LEN] = {0};
    char value[PATH_DB_MAX_VALUE_LEN] = {0};
    char set_key[PATH_DB_MAX_KEY_LEN] = {0};
    char set_value[PATH_DB_MAX_VALUE_LEN] = {0};
    char channel[PATH_DB_MAX_KEY_LEN] = {0};
    char dbErrMsg[100] = {0};
    char tmpbuf[INET6_ADDRSTRLEN] = {0};
    char G[] = "G";
    bool first = true;
    struct srte_segment_entry *s_entry;
    DB_FieldValue_List *pstDataLst = NULL;

    if (!g_bPathAppRedisInUse)
        return;

    /* set segment key and field*/
    snprintf(key, PATH_DB_MAX_KEY_LEN, "_%s:%s",SRV6_SID_LIST_TABLE, segl->name);
    snprintf(field, PATH_DB_MAX_KEY_LEN, "path");

    /* set segment value*/
    RB_FOREACH (s_entry, srte_segment_entry_head, &segl->segments)
    {
        const char *seg_value = inet_ntop(s_entry->srv6_sid_value.ipa_type,
                                        &s_entry->srv6_sid_value.ipaddr_v6,
                                        tmpbuf, sizeof(tmpbuf));
        if (first)
        {
            strncat(value, seg_value, PATH_DB_MAX_VALUE_LEN - strlen(value) - 1);
            first = false;
        }
        else
        {
            strncat(value, ",", PATH_DB_MAX_VALUE_LEN - strlen(value) - 1);
            strncat(value, seg_value, PATH_DB_MAX_VALUE_LEN - strlen(value) - 1);
        }
    }

    pstDataLst = new_redis_DB_Data(key, field, value);
    if (pstDataLst == NULL)
    {
        zlog_err("create field segment failed.");
        return;
    }
    pstDataLst->next = NULL;

    ret = g_redis_appdb.redis_Db_SetKeyAndFValue(key, pstDataLst, dbErrMsg, sizeof(dbErrMsg), REDIS_APP_DB);
    if (ret)
    {
        zlog_err("redis_Db_SetKeyAndFValue error code : %d", ret);
        release_redis_DB_Data(pstDataLst);
        return;
    }

    /*sadd KEY_SET*/
    snprintf(set_key, PATH_DB_MAX_KEY_LEN, "%s_KEY_SET",SRV6_SID_LIST_TABLE);
    snprintf(set_value, PATH_DB_MAX_VALUE_LEN, "%s", segl->name);
    ret = g_redis_appdb.redis_Db_SetSadd(set_key, set_value, dbErrMsg, sizeof(dbErrMsg), REDIS_APP_DB);
    if (ret)
    {
        zlog_err("redis_Db_SetSadd error code : %d", ret);
        return;
    }

    snprintf(channel, PATH_DB_MAX_KEY_LEN, "%s_CHANNEL@%s",SRV6_SID_LIST_TABLE, TAG);
    if (IS_PATHD_DEBUG_DB)
        zlog_debug("redis publishMsg channel : %s", channel);
    ret = g_redis_appdb.redis_PublishMsg(channel, G, REDIS_APP_DB);
    if (ret)
    {
        zlog_err("redis_PublishMsg error code : %d", ret);
    }

    segl->installed = true;
    release_redis_DB_Data(pstDataLst);
    return;
}

void redis_Db_Sid_List_DelEntry(struct srte_segment_list *segl)
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

    if (!g_bPathAppRedisInUse)
        return;

    /* del key*/
    snprintf(key, PATH_DB_MAX_KEY_LEN, "SRV6_SID_LIST_TABLE:%s", name);
    item.next = NULL;
    item.key = key;

    ret = g_redis_appdb.redis_Db_DelKeyLst(&item, dbErrMsg, sizeof(dbErrMsg), REDIS_APP_DB);
    if (ret)
    {
        zlog_err("redis_Db_DelKeyLst error code : %d", ret);
        return;
    }

    /*sadd DEL_SET*/
    snprintf(set_key, PATH_DB_MAX_KEY_LEN, "%s_DEL_SET",SRV6_SID_LIST_TABLE);
    snprintf(set_value, PATH_DB_MAX_VALUE_LEN, "%s", name);
    ret = g_redis_appdb.redis_Db_SetSadd(set_key, set_value, dbErrMsg, sizeof(dbErrMsg), REDIS_APP_DB);
    if (ret)
    {
        zlog_err("redis_Db_SetSadd DEL_SET error code : %d", ret);
        return;
    }

    /*sadd KEY_SET*/
    snprintf(set_key, PATH_DB_MAX_KEY_LEN, "%s_KEY_SET",SRV6_SID_LIST_TABLE);
    ret = g_redis_appdb.redis_Db_SetSadd(set_key, set_value, dbErrMsg, sizeof(dbErrMsg), REDIS_APP_DB);
    if (ret)
    {
        zlog_err("redis_Db_SetSadd KEY_SET error code : %d", ret);
        return;
    }

    /*publish*/
    snprintf(channel, PATH_DB_MAX_KEY_LEN, "%s_CHANNEL@%s",SRV6_SID_LIST_TABLE, TAG);
    if (IS_PATHD_DEBUG_DB)
        zlog_debug("redis publishMsg channel : %s", channel);
    ret = g_redis_appdb.redis_PublishMsg(channel, G, REDIS_APP_DB);
    if (ret)
    {
        zlog_err("redis_PublishMsg error code : %d", ret);
    }

    segl->installed = false;

    return;
}

void redis_Db_Policy_SetEntry(struct srte_policy *policy)
{
    int ret;
    char key[PATH_DB_MAX_KEY_LEN] = {0};
    char field[PATH_DB_MAX_KEY_LEN] = {0};
    char value[PATH_DB_MAX_VALUE_LEN] = {0};
    char dbErrMsg[100] = {0};
    char endpoint[INET6_ADDRSTRLEN] = {0};
    char realtime[MONOTIME_STRLEN] = {0};

    DB_FieldValue_List *pstDataLst_head = NULL;
    DB_FieldValue_List *pstDataLst_name = NULL;
    DB_FieldValue_List *pstDataLst_state = NULL;
    DB_FieldValue_List *pstDataLst_update_time = NULL;

    if (!g_bPathStateRedisInUse)
        return;

    inet_ntop(policy->endpoint.family, &policy->endpoint.u.prefix,
            endpoint, sizeof(endpoint));
    snprintf(key, PATH_DB_MAX_KEY_LEN, "%s|%u|%s",SRV6_POLICY_TABLE, policy->color, endpoint);
    snprintf(field, PATH_DB_MAX_KEY_LEN, "name");
    snprintf(value, PATH_DB_MAX_VALUE_LEN, "%s", policy->name);

    pstDataLst_name = new_redis_DB_Data(key, field, value);
    if (pstDataLst_name == NULL)
    {
        zlog_err("create policy(%u|%s) name(%s) failed.", policy->color, endpoint, policy->name);
        return;
    }
    pstDataLst_head = pstDataLst_name;

    snprintf(field, PATH_DB_MAX_KEY_LEN, "status");
    snprintf(value, PATH_DB_MAX_VALUE_LEN, "%s", policy->status == SRTE_POLICY_STATUS_UP ? "up" : "down");

    pstDataLst_state = new_redis_DB_Data(key, field, value);
    if (pstDataLst_state == NULL)
    {
        release_redis_DB_Data(pstDataLst_head);
        zlog_err("create policy(%u|%s) status(%u) failed.", policy->color, endpoint, policy->status);
        return;
    }
    pstDataLst_head->next = pstDataLst_state;

    path_monotime_to_realtime(policy->updatetime, realtime);
    snprintf(field, PATH_DB_MAX_KEY_LEN, "update_time");
    snprintf(value, PATH_DB_MAX_VALUE_LEN, "%s", realtime);

    pstDataLst_update_time = new_redis_DB_Data(key, field, value);
    if (pstDataLst_update_time == NULL)
    {
        release_redis_DB_Data(pstDataLst_head);
        zlog_err("create policy(%u|%s) upadte time(%s) failed.", policy->color, endpoint, realtime);
        return;
    }
    pstDataLst_state->next = pstDataLst_update_time;
    ret = g_redis_statedb.redis_Db_SetKeyAndFValue(key, pstDataLst_head, dbErrMsg, sizeof(dbErrMsg), REDIS_STATE_DB);
    if (ret)
    {
        zlog_err("%s: redis_Db_SetKeyAndFValue error code(%d) %s", __func__, ret, dbErrMsg);
    }

    release_redis_DB_Data(pstDataLst_head);
    return;
}

void redis_Db_Policy_DelEntry(struct srte_policy *policy)
{
    int ret;
    char key[PATH_DB_MAX_KEY_LEN] = {0};
    char dbErrMsg[100] = {0};
    DB_Key_List item = {0};
    char endpoint[INET6_ADDRSTRLEN] = {0};

    if (!g_bPathStateRedisInUse)
        return;

    inet_ntop(policy->endpoint.family, &policy->endpoint.u.prefix,
            endpoint, sizeof(endpoint));
    /* del key*/
    snprintf(key, PATH_DB_MAX_KEY_LEN, "%s|%u|%s", SRV6_POLICY_TABLE, policy->color, endpoint);
    item.next = NULL;
    item.key = key;

    ret = g_redis_statedb.redis_Db_DelKeyLst(&item, dbErrMsg, sizeof(dbErrMsg), REDIS_STATE_DB);
    if (ret)
    {
        zlog_err("%s: redis_Db_DelKeyLst error code(%d) %s", __func__, ret, dbErrMsg);
    }

    return;
}

void redis_Db_Cpath_SetEntry(struct srte_candidate *candidate)
{
    int ret;
    char key[PATH_DB_MAX_KEY_LEN] = {0};
    char field[PATH_DB_MAX_KEY_LEN] = {0};
    char value[PATH_DB_MAX_VALUE_LEN] = {0};
    char dbErrMsg[100] = {0};
    struct srte_policy *policy = NULL;
    char endpoint[INET6_ADDRSTRLEN] = {0};
    char binding_bfd[BFD_NAME_SIZE + 1] = {0};
    bool has_bfd = false;
    char realtime[MONOTIME_STRLEN] = {0};

    DB_FieldValue_List *pstDataLst_head = NULL;
    DB_FieldValue_List *pstDataLst_sidlist = NULL;
    DB_FieldValue_List *pstDataLst_bfd = NULL;
    DB_FieldValue_List *pstDataLst_state = NULL;
    DB_FieldValue_List *pstDataLst_update_time = NULL;

    if (!g_bPathStateRedisInUse)
        return;

    if (CHECK_FLAG(candidate->flags, F_CANDIDATE_HIDDEN)) {
        return;
    }
    policy = candidate->policy;

    inet_ntop(policy->endpoint.family, &policy->endpoint.u.prefix,
            endpoint, sizeof(endpoint));
    snprintf(key, PATH_DB_MAX_KEY_LEN, "%s|%u|%s|%u|%s",SRV6_POLICY_TABLE, policy->color,
        endpoint, candidate->preference, candidate->name);
    snprintf(field, PATH_DB_MAX_KEY_LEN, "segment_list");
    snprintf(value, PATH_DB_MAX_VALUE_LEN, "%s", candidate->segment_list ? candidate->segment_list->name : "");

    pstDataLst_sidlist = new_redis_DB_Data(key, field, value);
    if (pstDataLst_sidlist == NULL)
    {
        zlog_err("create policy(%u|%s|%u|%s) segment list name(%s) failed.",
            policy->color, endpoint, candidate->preference, candidate->name,
            candidate->segment_list ? candidate->segment_list->name : "");
        return;
    }
    pstDataLst_head = pstDataLst_sidlist;

    if(candidate->bfd_name[0]){
        has_bfd = true;
        snprintf(binding_bfd, sizeof(binding_bfd), "%s", candidate->bfd_name);
    }
    snprintf(field, PATH_DB_MAX_KEY_LEN, "bfd_name");
    snprintf(value, PATH_DB_MAX_VALUE_LEN, "%s", binding_bfd);

    pstDataLst_bfd = new_redis_DB_Data(key, field, value);
    if (pstDataLst_bfd == NULL)
    {
        release_redis_DB_Data(pstDataLst_head);
        zlog_err("create policy(%u|%s|%u|%s) bfd name(%s) failed.", policy->color, endpoint,
            candidate->preference, candidate->name, binding_bfd);
        return;
    }
    pstDataLst_sidlist->next = pstDataLst_bfd;

    snprintf(field, PATH_DB_MAX_KEY_LEN, "status");
    snprintf(value, PATH_DB_MAX_VALUE_LEN, "%s", 
        has_bfd ? (candidate->status == SRTE_DETECT_UP ? "up" : (candidate->status == SRTE_DETECT_NONE ?"up": "down")) : "up");

    pstDataLst_state = new_redis_DB_Data(key, field, value);
    if (pstDataLst_state == NULL)
    {
        release_redis_DB_Data(pstDataLst_head);
        zlog_err("create policy(%u|%s|%u|%s) state(%u) failed.", policy->color, endpoint,
        candidate->preference, candidate->name, candidate->status);
        return;
    }
    pstDataLst_bfd->next = pstDataLst_state;

    path_monotime_to_realtime(candidate->status_change_time, realtime);
    snprintf(field, PATH_DB_MAX_KEY_LEN, "update_time");
    snprintf(value, PATH_DB_MAX_VALUE_LEN, "%s", realtime);

    pstDataLst_update_time = new_redis_DB_Data(key, field, value);
    if (pstDataLst_update_time == NULL)
    {
        release_redis_DB_Data(pstDataLst_head);
        zlog_err("create policy(%u|%s) upadte time(%s) failed.", policy->color, endpoint, realtime);
        return;
    }
    pstDataLst_state->next = pstDataLst_update_time;
    ret = g_redis_statedb.redis_Db_SetKeyAndFValue(key, pstDataLst_head, dbErrMsg, sizeof(dbErrMsg), REDIS_STATE_DB);
    if (ret)
    {
        zlog_err("%s: redis_Db_SetKeyAndFValue error code(%d) %s", __func__, ret, dbErrMsg);
    }

    release_redis_DB_Data(pstDataLst_head);
    return;
}

void redis_Db_Cpath_DelEntry(struct srte_candidate *candidate)
{
    int ret;
    char key[PATH_DB_MAX_KEY_LEN] = {0};
    char dbErrMsg[100] = {0};
    struct srte_policy *policy;
    char endpoint[INET6_ADDRSTRLEN] = {0};
    DB_Key_List item = {0};

    if (!g_bPathStateRedisInUse)
        return;
    if (CHECK_FLAG(candidate->flags, F_CANDIDATE_HIDDEN))
        return;

    policy = candidate->policy;
    inet_ntop(policy->endpoint.family, &policy->endpoint.u.prefix,
            endpoint, sizeof(endpoint));
    /* del key*/
    snprintf(key, PATH_DB_MAX_KEY_LEN, "%s|%u|%s|%u|%s", SRV6_POLICY_TABLE, policy->color, endpoint,
        candidate->preference, candidate->name);
    item.next = NULL;
    item.key = key;

    ret = g_redis_statedb.redis_Db_DelKeyLst(&item, dbErrMsg, sizeof(dbErrMsg), REDIS_STATE_DB);
    if (ret)
    {
        zlog_err("%s: redis_Db_DelKeyLst error code(%d) %s", __func__, ret, dbErrMsg);
    }

    return;
}