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

REDIS_INFO_S g_stZebraRedisDbInfo = {0};
void *g_zebrahandleRedis = NULL; /* libredis++.so */
struct redis_user_ext g_zebra_redis = {0};/* libredis++.so */
bool g_bZebraRedisInUse = false;

REDIS_INFO_S g_stZebraRedisDbInfo_appdb = {0};
struct redis_user_ext g_zebra_redis_appdb = {0};
bool g_bZebraRedisInUse_appdb = false;


#define SRV6_MY_SID_TABLE "SRV6_MY_SID_TABLE"
#define TAG "0"

static DB_FieldValue_List *create_DB_Data(char *key, char *field, char *value)
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

static void destroy_DB_Data(DB_FieldValue_List *pstDataLst)
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
        (int (*)(REDIS_INFO_S *pstRediDbInfo, char *dbErrMsg, int msglen, DB_TYPE_E enDbType))
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


    /* Get the entry points for APP_DB start */
    g_zebra_redis_appdb.redis_Connect =
        (int (*)(REDIS_INFO_S *pstRediDbInfo, char *dbErrMsg, int msglen, DB_TYPE_E enDbType))
        dlsym(g_zebrahandleRedis, "Redis_Connect");
    g_zebra_redis_appdb.redis_Set_Timeout =
        (void (*)(int timeout))
        dlsym(g_zebrahandleRedis, "Redis_Set_Timeout");
    g_zebra_redis_appdb.redis_DisConnect =
        (void (*)(char *dbErrMsg, int msglen))
        dlsym(g_zebrahandleRedis, "Redis_DisConnect");

    g_zebra_redis_appdb.redis_Db_DispConnectInfo =
        (int (*)(char *dbErrMsg, int msglen))
        dlsym(g_zebrahandleRedis, "Redis_Db_DispConnectInfo");

    g_zebra_redis_appdb.redis_Db_HGetKeyAndValueNoCursor =
        (void (*)(char *key_prefix, char *field, char* result, int resultlen, char *dbErrMsg, int msglen, int *errNo, DB_TYPE_E enDbType))
        dlsym(g_zebrahandleRedis, "Redis_Db_HGetKeyAndValueNoCursor");

    g_zebra_redis_appdb.redis_Db_GetKey =
        (DB_Key_List* (*)(char *key_prefix, char *dbErrMsg, int msglen, DB_TYPE_E enDbType))
        dlsym(g_zebrahandleRedis, "Redis_Db_GetKey");

    g_zebra_redis_appdb.redis_Db_SetKeyAndFValue =
        (int (*)(char *key, DB_FieldValue_List *pstDataLst, char *dbErrMsg, int msglen, DB_TYPE_E enDbType))
        dlsym(g_zebrahandleRedis, "Redis_Db_SetKeyAndFValue");

    g_zebra_redis_appdb.redis_Db_DelKeyLst =
        (int (*)(DB_Key_List *pstKeylist, char *dbErrMsg, int msglen, DB_TYPE_E enDbType))
        dlsym(g_zebrahandleRedis, "Redis_Db_DelKeyLst");

    g_zebra_redis_appdb.redis_PublishMsg =
        (int (*)(char *key, char *msg, DB_TYPE_E enDbType))
        dlsym(g_zebrahandleRedis, "Redis_PublishMsgForce");

    g_zebra_redis_appdb.redis_Db_SetSadd =
        (int (*)(char *key, char *member, char *dbErrMsg, int msglen, DB_TYPE_E enDbType))
        dlsym(g_zebrahandleRedis, "Redis_Db_SetSadd");

    g_zebra_redis_appdb.redis_Set_Timeout(1);
    snprintf(g_stZebraRedisDbInfo_appdb.sentinelInfo.ip_addr, 128, "127.0.0.1");
    g_stZebraRedisDbInfo_appdb.sentinelInfo.port = 6380;
    g_stZebraRedisDbInfo_appdb.db = 0;

    ret = g_zebra_redis_appdb.redis_Connect(&g_stZebraRedisDbInfo_appdb, dbErrMsg, sizeof(dbErrMsg), REDIS_APP_DB);
    if (ret != 0)
    {
        zlog_err("Zebra redis app db connect fail:%s", dbErrMsg);
        return;
    }

    g_bZebraRedisInUse_appdb = true;
    zlog_info("Zebra redis app db connect success");
    zlog_info("Zebra redis app db init end");


    /* Get the entry points for APP_DB end */

    return;
}

int zebra_Db_GetVrfAlias(const char *vrfname, char *aliasName, int aliasNameLen)
{
    char keyType[ZEBRA_DB_MAX_KEY_LEN] = {0};
    char aliasKey[10] = {0};
    char result[ZEBRA_DB_MAX_KEY_LEN] = {0};
    char dbErrMsg[100] = {0};
    int errNo = 0;
    DB_Key_List *pKeyList = NULL;
    DB_Key_List *pKeyNode = NULL;
    char aliasId[10] = {0};
    char VRF_NAME[] = "vrf_name";
    char ALIAS_NAME[] = "alias_name";
    char VRF_NAMEID[] = "vrf_nameid";

    if (!g_bZebraRedisInUse)
    {
        zlog_err("redis err,fail to get vrfname :%s", vrfname);
        return 1;
    }

    /*1.try to check mgmt vrf*/
    snprintf(keyType, ZEBRA_DB_MAX_KEY_LEN, "MGMT_VRF_CONFIG|vrf_global");
    g_zebra_redis.redis_Db_HGetKeyAndValueNoCursor(keyType, VRF_NAME, result,
                                    ZEBRA_DB_MAX_VALUE_LEN, dbErrMsg, sizeof(dbErrMsg), &errNo, REDIS_CONFIG_DB);
    if (strlen(result) && (strlen(result) == strlen(vrfname)) && !strncmp(vrfname, result, strlen(result)))
    {
        g_zebra_redis.redis_Db_HGetKeyAndValueNoCursor(keyType, ALIAS_NAME, result,
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
        g_zebra_redis.redis_Db_HGetKeyAndValueNoCursor(pKeyList->key, VRF_NAMEID, result, ZEBRA_DB_MAX_VALUE_LEN,
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

static const char *local_action2str(enum seg6local_action_t action)
{
    switch (action)
    {
        case ZEBRA_SEG6_LOCAL_ACTION_UNSPEC:
            return "unspec";
        case ZEBRA_SEG6_LOCAL_ACTION_END:
            return "end";
        case ZEBRA_SEG6_LOCAL_ACTION_END_X:
            return "end.x";
        case ZEBRA_SEG6_LOCAL_ACTION_END_T:
            return "end.t";
        case ZEBRA_SEG6_LOCAL_ACTION_END_DX6:
            return "end.dx6";
        case ZEBRA_SEG6_LOCAL_ACTION_END_DX4:
            return "end.dx4";
        case ZEBRA_SEG6_LOCAL_ACTION_END_DT6:
            return "end.dt6";
        case ZEBRA_SEG6_LOCAL_ACTION_END_DT4:
            return "end.dt4";
        case ZEBRA_SEG6_LOCAL_ACTION_END_B6_ENCAP:
            return "end.b6.encaps";
        case ZEBRA_SEG6_LOCAL_ACTION_END_DT46:
            return "end.dt46";
        case ZEBRA_SEG6_LOCAL_ACTION_END_UDX6:
            return "udx6";
        case ZEBRA_SEG6_LOCAL_ACTION_END_UDX4:
            return "udx4";
        case ZEBRA_SEG6_LOCAL_ACTION_END_UDT6:
            return "udt6";
        case ZEBRA_SEG6_LOCAL_ACTION_END_UDT4:
            return "udt4";
        case ZEBRA_SEG6_LOCAL_ACTION_END_UDT46:
            return "udt46";
        case ZEBRA_SEG6_LOCAL_ACTION_END_UN:
            return "un";
        case ZEBRA_SEG6_LOCAL_ACTION_END_UA:
            return "ua";
        default:
            return "unspec";
    }
}

void zebra_Db_Set_SRV6_LOCAL_ENDX_SID(const struct in6_addr *result_sid, const char *vrf_name,
    enum seg6local_action_t act, const struct seg6local_context *ctx, const struct list *sid_endx_params)
{
    int ret;
    char key[ZEBRA_DB_MAX_KEY_LEN + 24] = {0};
    char field[ZEBRA_DB_MAX_KEY_LEN] = {0};
    char value[ZEBRA_DB_MAX_VALUE_LEN] = {0};
    char intf_val[ZEBRA_DB_IF_MAX_VALUE_LEN] = {0};
    char nhp_val[ZEBRA_DB_IF_MAX_VALUE_LEN] = {0};
    char set_key[ZEBRA_DB_MAX_KEY_LEN] = {0};
    char set_value[ZEBRA_DB_MAX_VALUE_LEN] = {0};
    char channel[ZEBRA_DB_MAX_KEY_LEN] = {0};
    char dbErrMsg[100] = {0};
    char G[] = "G";

    struct seg6_sid_endx_params *sid_ua_params_node = NULL;
    struct listnode *node = NULL;

    DB_FieldValue_List *pstDataLst_head = NULL;
    DB_FieldValue_List *pstDataLst_block_len = NULL;
    DB_FieldValue_List *pstDataLst_node_len = NULL;
    DB_FieldValue_List *pstDataLst_func_len = NULL;
    DB_FieldValue_List *pstDataLst_argu_len = NULL;
    DB_FieldValue_List *pstDataLst_action = NULL;
    DB_FieldValue_List *pstDataLst_vrf = NULL;
    DB_FieldValue_List *pstDataLst_ifname = NULL;
    DB_FieldValue_List *pstDataLst_nhp = NULL;

    char my_local_sid[ZEBRA_DB_MAX_KEY_LEN] = {0};
    struct prefix p = {};

    p.family = AF_INET6;
    p.prefixlen = ctx->block_bits_length + ctx->node_bits_length + ctx->function_bits_length;
    p.u.prefix6 = *result_sid;
    prefix2str(&p, my_local_sid, ZEBRA_DB_MAX_KEY_LEN);

    if (!g_bZebraRedisInUse_appdb) {
        zlog_err("redis err, redis app db handle init failed");
        return;
    }

    /* block len */
    snprintf(key, ZEBRA_DB_MAX_KEY_LEN + 24, "_%s:%s", SRV6_MY_SID_TABLE, my_local_sid);
    snprintf(field, ZEBRA_DB_MAX_KEY_LEN, "block_len");
    snprintf(value, ZEBRA_DB_MAX_VALUE_LEN, "%u", ctx->block_bits_length);
    pstDataLst_block_len = create_DB_Data(key, field, value);
    if (pstDataLst_block_len == NULL)
    {
        zlog_err("create block len field segment failed.");
        return;
    }
    pstDataLst_head = pstDataLst_block_len;

    /* node len */
    snprintf(key, ZEBRA_DB_MAX_KEY_LEN + 24, "_%s:%s", SRV6_MY_SID_TABLE, my_local_sid);
    snprintf(field, ZEBRA_DB_MAX_KEY_LEN, "node_len");
    snprintf(value, ZEBRA_DB_MAX_VALUE_LEN, "%u", ctx->node_bits_length);
    pstDataLst_node_len = create_DB_Data(key, field, value);
    if (pstDataLst_node_len == NULL)
    {
        destroy_DB_Data(pstDataLst_head);
        zlog_err("create node len field segment failed.");
        return;
    }
    pstDataLst_block_len->next = pstDataLst_node_len;

    /* func_len */
    snprintf(key, ZEBRA_DB_MAX_KEY_LEN + 24, "_%s:%s", SRV6_MY_SID_TABLE, my_local_sid);
    snprintf(field, ZEBRA_DB_MAX_KEY_LEN, "func_len");
    snprintf(value, ZEBRA_DB_MAX_VALUE_LEN, "%u", ctx->function_bits_length);
    pstDataLst_func_len = create_DB_Data(key, field, value);
    if (pstDataLst_func_len == NULL)
    {
        destroy_DB_Data(pstDataLst_head);
        zlog_err("create func len field segment failed.");
        return;
    }
    pstDataLst_node_len->next = pstDataLst_func_len;

    /* argu len */
    snprintf(key, ZEBRA_DB_MAX_KEY_LEN + 24, "_%s:%s", SRV6_MY_SID_TABLE, my_local_sid);
    snprintf(field, ZEBRA_DB_MAX_KEY_LEN, "argu_len");
    snprintf(value, ZEBRA_DB_MAX_VALUE_LEN, "%u", ctx->argument_bits_length);
    pstDataLst_argu_len = create_DB_Data(key, field, value);
    if (pstDataLst_argu_len == NULL)
    {
        destroy_DB_Data(pstDataLst_head);
        zlog_err("create argu len field segment failed.");
        return;
    }
    pstDataLst_func_len->next = pstDataLst_argu_len;

    /* action */
    snprintf(key, ZEBRA_DB_MAX_KEY_LEN + 24, "_%s:%s", SRV6_MY_SID_TABLE, my_local_sid);
    snprintf(field, ZEBRA_DB_MAX_KEY_LEN, "action");
    snprintf(value, ZEBRA_DB_MAX_VALUE_LEN, "%s", local_action2str(act));
    pstDataLst_action = create_DB_Data(key, field, value);
    if (pstDataLst_action == NULL)
    {
        destroy_DB_Data(pstDataLst_head);
        zlog_err("create action field segment failed.");
        return;
    }
    pstDataLst_argu_len->next = pstDataLst_action;

    /* vrf */
    snprintf(key, ZEBRA_DB_MAX_KEY_LEN + 24, "_%s:%s", SRV6_MY_SID_TABLE, my_local_sid);
    snprintf(field, ZEBRA_DB_MAX_KEY_LEN, "vrf");
    snprintf(value, ZEBRA_DB_MAX_VALUE_LEN, "%s", vrf_name);
    pstDataLst_vrf = create_DB_Data(key, field, value);
    if (pstDataLst_vrf == NULL)
    {
        destroy_DB_Data(pstDataLst_head);
        zlog_err("create vrf field segment failed.");
        return;
    }
    pstDataLst_action->next = pstDataLst_vrf;

    for (ALL_LIST_ELEMENTS_RO(sid_endx_params, node, sid_ua_params_node)) {
        if (strlen(intf_val) + strlen(sid_ua_params_node->ifname) + 1 >= ZEBRA_DB_IF_MAX_VALUE_LEN) {
            zlog_err("create ifname field segment failed.");
            return;
        }
        if (intf_val[0] != '\0') {
            // Add comma separator if not the first element
            strncat(intf_val, ",", ZEBRA_DB_IF_MAX_VALUE_LEN - strlen(intf_val) - 1); 
        }
        strncat(intf_val, sid_ua_params_node->ifname, ZEBRA_DB_IF_MAX_VALUE_LEN - strlen(intf_val) - 1);

        char nhp_buf[INET6_ADDRSTRLEN] = {0};
        if (sid_ua_params_node->nexthop.ipa_type == IPADDR_V4)
            inet_ntop(AF_INET, &sid_ua_params_node->nexthop.ipaddr_v4, nhp_buf, sizeof(nhp_buf));
        else if (sid_ua_params_node->nexthop.ipa_type == IPADDR_V6)
            inet_ntop(AF_INET6, &sid_ua_params_node->nexthop.ipaddr_v6, nhp_buf, sizeof(nhp_buf));

        if (strlen(nhp_val) + strlen(nhp_buf) + 1 >= ZEBRA_DB_IF_MAX_VALUE_LEN) {
            zlog_err("create nexthop field segment failed.");
            return;
        }

        if (nhp_val[0] != '\0') {
            // Add comma separator if not the first element
            strncat(nhp_val, ",", ZEBRA_DB_IF_MAX_VALUE_LEN - strlen(nhp_val) - 1); 
        }
        strncat(nhp_val, nhp_buf, ZEBRA_DB_IF_MAX_VALUE_LEN - strlen(nhp_val) - 1);
    }

    /* ifname */
    snprintf(key, ZEBRA_DB_MAX_KEY_LEN + 24, "_%s:%s", SRV6_MY_SID_TABLE, my_local_sid);
    snprintf(field, ZEBRA_DB_MAX_KEY_LEN, "ifname");
    pstDataLst_ifname = create_DB_Data(key, field, intf_val);
    if (pstDataLst_ifname == NULL)
    {
        destroy_DB_Data(pstDataLst_head);
        zlog_err("create vrf field segment failed.");
        return;
    }
    pstDataLst_vrf->next = pstDataLst_ifname;

    /* nexthop */
    snprintf(key, ZEBRA_DB_MAX_KEY_LEN + 24, "_%s:%s", SRV6_MY_SID_TABLE, my_local_sid);
    snprintf(field, ZEBRA_DB_MAX_KEY_LEN, "nexthop");
    pstDataLst_nhp = create_DB_Data(key, field, nhp_val);
    if (pstDataLst_nhp == NULL)
    {
        destroy_DB_Data(pstDataLst_head);
        zlog_err("create nexthop field segment failed.");
        return;
    }
    pstDataLst_ifname->next = pstDataLst_nhp;


    ret = g_zebra_redis_appdb.redis_Db_SetKeyAndFValue(key, pstDataLst_head, dbErrMsg, sizeof(dbErrMsg), REDIS_APP_DB);
    if (ret)
    {
        zlog_err("redis_Db_SetKeyAndFValue error code : %d", ret);
        destroy_DB_Data(pstDataLst_head);
        return;
    }

    /*sadd KEY_SET*/
    snprintf(set_key, ZEBRA_DB_MAX_KEY_LEN, "%s_KEY_SET", SRV6_MY_SID_TABLE);
    snprintf(set_value, ZEBRA_DB_MAX_VALUE_LEN, "%s", my_local_sid);
    ret = g_zebra_redis_appdb.redis_Db_SetSadd(set_key, set_value, dbErrMsg, sizeof(dbErrMsg), REDIS_APP_DB);
    if (ret)
    {
        zlog_err("redis_Db_SetSadd error code : %d", ret);
        return;
    }

    snprintf(channel, ZEBRA_DB_MAX_KEY_LEN, "%s_CHANNEL@%s", SRV6_MY_SID_TABLE, TAG);
    zlog_debug("redis publishMsg channel : %s", channel);
    ret = g_zebra_redis_appdb.redis_PublishMsg(channel, G, REDIS_APP_DB);
    if (ret)
    {
        destroy_DB_Data(pstDataLst_head);
        zlog_err("redis_PublishMsg error code : %d", ret);
        return;
    }

    destroy_DB_Data(pstDataLst_head);
    return;
}


void zebra_Db_Set_SRV6_LOCAL_SID(const struct in6_addr *result_sid, const char *vrf_name,
    enum seg6local_action_t act, const struct seg6local_context *ctx, const char *ifname, const struct ipaddr *nexthop, const bool sidmarking)
{
    int ret;
    char key[ZEBRA_DB_MAX_KEY_LEN + 24] = {0};
    char field[ZEBRA_DB_MAX_KEY_LEN] = {0};
    char value[ZEBRA_DB_MAX_VALUE_LEN] = {0};
    char set_key[ZEBRA_DB_MAX_KEY_LEN] = {0};
    char set_value[ZEBRA_DB_MAX_VALUE_LEN] = {0};
    char channel[ZEBRA_DB_MAX_KEY_LEN] = {0};
    char dbErrMsg[100] = {0};
    char G[] = "G";

    DB_FieldValue_List *pstDataLst_head = NULL;
    DB_FieldValue_List *pstDataLst_block_len = NULL;
    DB_FieldValue_List *pstDataLst_node_len = NULL;
    DB_FieldValue_List *pstDataLst_func_len = NULL;
    DB_FieldValue_List *pstDataLst_argu_len = NULL;
    DB_FieldValue_List *pstDataLst_action = NULL;
    DB_FieldValue_List *pstDataLst_vrf = NULL;
    DB_FieldValue_List *pstDataLst_sidmarking = NULL;
    DB_FieldValue_List *pstDataLst_ifname = NULL;
    DB_FieldValue_List *pstDataLst_nhp = NULL;

    char my_local_sid[ZEBRA_DB_MAX_KEY_LEN] = {0};
    struct prefix p = {};

    p.family = AF_INET6;
    p.prefixlen = ctx->block_bits_length + ctx->node_bits_length + ctx->function_bits_length;
    p.u.prefix6 = *result_sid;
    prefix2str(&p, my_local_sid, ZEBRA_DB_MAX_KEY_LEN);

    if (!g_bZebraRedisInUse_appdb) {
        zlog_err("redis err, redis app db handle init failed");
        return;
    }

    /* block len */
    snprintf(key, ZEBRA_DB_MAX_KEY_LEN + 24, "_%s:%s", SRV6_MY_SID_TABLE, my_local_sid);
    snprintf(field, ZEBRA_DB_MAX_KEY_LEN, "block_len");
    snprintf(value, ZEBRA_DB_MAX_VALUE_LEN, "%u", ctx->block_bits_length);
    pstDataLst_block_len = create_DB_Data(key, field, value);
    if (pstDataLst_block_len == NULL)
    {
        zlog_err("create block len field segment failed.");
        return;
    }
    pstDataLst_head = pstDataLst_block_len;

    /* node len */
    snprintf(key, ZEBRA_DB_MAX_KEY_LEN + 24, "_%s:%s", SRV6_MY_SID_TABLE, my_local_sid);
    snprintf(field, ZEBRA_DB_MAX_KEY_LEN, "node_len");
    snprintf(value, ZEBRA_DB_MAX_VALUE_LEN, "%u", ctx->node_bits_length);
    pstDataLst_node_len = create_DB_Data(key, field, value);
    if (pstDataLst_node_len == NULL)
    {
        destroy_DB_Data(pstDataLst_head);
        zlog_err("create node len field segment failed.");
        return;
    }
    pstDataLst_block_len->next = pstDataLst_node_len;

    /* func_len */
    snprintf(key, ZEBRA_DB_MAX_KEY_LEN + 24, "_%s:%s", SRV6_MY_SID_TABLE, my_local_sid);
    snprintf(field, ZEBRA_DB_MAX_KEY_LEN, "func_len");
    snprintf(value, ZEBRA_DB_MAX_VALUE_LEN, "%u", ctx->function_bits_length);
    pstDataLst_func_len = create_DB_Data(key, field, value);
    if (pstDataLst_func_len == NULL)
    {
        destroy_DB_Data(pstDataLst_head);
        zlog_err("create func len field segment failed.");
        return;
    }
    pstDataLst_node_len->next = pstDataLst_func_len;

    /* argu len */
    snprintf(key, ZEBRA_DB_MAX_KEY_LEN + 24, "_%s:%s", SRV6_MY_SID_TABLE, my_local_sid);
    snprintf(field, ZEBRA_DB_MAX_KEY_LEN, "argu_len");
    snprintf(value, ZEBRA_DB_MAX_VALUE_LEN, "%u", ctx->argument_bits_length);
    pstDataLst_argu_len = create_DB_Data(key, field, value);
    if (pstDataLst_argu_len == NULL)
    {
        destroy_DB_Data(pstDataLst_head);
        zlog_err("create argu len field segment failed.");
        return;
    }
    pstDataLst_func_len->next = pstDataLst_argu_len;

    /* action */
    snprintf(key, ZEBRA_DB_MAX_KEY_LEN + 24, "_%s:%s", SRV6_MY_SID_TABLE, my_local_sid);
    snprintf(field, ZEBRA_DB_MAX_KEY_LEN, "action");
    snprintf(value, ZEBRA_DB_MAX_VALUE_LEN, "%s", local_action2str(act));
    pstDataLst_action = create_DB_Data(key, field, value);
    if (pstDataLst_action == NULL)
    {
        destroy_DB_Data(pstDataLst_head);
        zlog_err("create action field segment failed.");
        return;
    }
    pstDataLst_argu_len->next = pstDataLst_action;

    /* vrf */
    snprintf(key, ZEBRA_DB_MAX_KEY_LEN + 24, "_%s:%s", SRV6_MY_SID_TABLE, my_local_sid);
    snprintf(field, ZEBRA_DB_MAX_KEY_LEN, "vrf");
    snprintf(value, ZEBRA_DB_MAX_VALUE_LEN, "%s", vrf_name);
    pstDataLst_vrf = create_DB_Data(key, field, value);
    if (pstDataLst_vrf == NULL)
    {
        destroy_DB_Data(pstDataLst_head);
        zlog_err("create vrf field segment failed.");
        return;
    }
    pstDataLst_action->next = pstDataLst_vrf;

    /* sidmarking */
    snprintf(key, ZEBRA_DB_MAX_KEY_LEN + 24, "_%s:%s", SRV6_MY_SID_TABLE, my_local_sid);
    snprintf(field, ZEBRA_DB_MAX_KEY_LEN, "sidmarking");
    snprintf(value, ZEBRA_DB_MAX_VALUE_LEN, "%d", sidmarking);
    pstDataLst_sidmarking = create_DB_Data(key, field, value);
    if (pstDataLst_sidmarking == NULL)
    {
        destroy_DB_Data(pstDataLst_head);
        zlog_err("create sidmarking field segment failed.");
        return;
    }
    pstDataLst_vrf->next = pstDataLst_sidmarking;

    /* ifname */
    snprintf(key, ZEBRA_DB_MAX_KEY_LEN + 24, "_%s:%s", SRV6_MY_SID_TABLE, my_local_sid);
    snprintf(field, ZEBRA_DB_MAX_KEY_LEN, "ifname");
    snprintf(value, ZEBRA_DB_MAX_VALUE_LEN, "%s", ifname ? ifname : "NULL");
    pstDataLst_ifname = create_DB_Data(key, field, value);
    if (pstDataLst_ifname == NULL)
    {
        destroy_DB_Data(pstDataLst_head);
        zlog_err("create vrf field segment failed.");
        return;
    }
    pstDataLst_sidmarking->next = pstDataLst_ifname;

    /* nexthop */
    if (nexthop)
    {
        char nhp_buf[INET6_ADDRSTRLEN] = {0};
        if (nexthop->ipa_type == IPADDR_V4)
            inet_ntop(AF_INET, &nexthop->ipaddr_v4, nhp_buf, sizeof(nhp_buf));
        else if (nexthop->ipa_type == IPADDR_V6)
            inet_ntop(AF_INET6, &nexthop->ipaddr_v6, nhp_buf, sizeof(nhp_buf));

        snprintf(key, ZEBRA_DB_MAX_KEY_LEN + 24, "_%s:%s", SRV6_MY_SID_TABLE, my_local_sid);
        snprintf(field, ZEBRA_DB_MAX_KEY_LEN, "nexthop");
        snprintf(value, ZEBRA_DB_MAX_VALUE_LEN, "%s", nhp_buf);
        pstDataLst_nhp = create_DB_Data(key, field, value);
        if (pstDataLst_nhp == NULL)
        {
            destroy_DB_Data(pstDataLst_head);
            zlog_err("create nexthop field segment failed.");
            return;
        }
        pstDataLst_ifname->next = pstDataLst_nhp;
    }

    ret = g_zebra_redis_appdb.redis_Db_SetKeyAndFValue(key, pstDataLst_head, dbErrMsg, sizeof(dbErrMsg), REDIS_APP_DB);
    if (ret)
    {
        zlog_err("redis_Db_SetKeyAndFValue error code : %d", ret);
        destroy_DB_Data(pstDataLst_head);
        return;
    }

    /*sadd KEY_SET*/
    snprintf(set_key, ZEBRA_DB_MAX_KEY_LEN, "%s_KEY_SET", SRV6_MY_SID_TABLE);
    snprintf(set_value, ZEBRA_DB_MAX_VALUE_LEN, "%s", my_local_sid);
    ret = g_zebra_redis_appdb.redis_Db_SetSadd(set_key, set_value, dbErrMsg, sizeof(dbErrMsg), REDIS_APP_DB);
    if (ret)
    {
        zlog_err("redis_Db_SetSadd error code : %d", ret);
        return;
    }

    snprintf(channel, ZEBRA_DB_MAX_KEY_LEN, "%s_CHANNEL@%s", SRV6_MY_SID_TABLE, TAG);
    zlog_debug("redis publishMsg channel : %s", channel);
    ret = g_zebra_redis_appdb.redis_PublishMsg(channel, G, REDIS_APP_DB);
    if (ret)
    {
        destroy_DB_Data(pstDataLst_head);
        zlog_err("redis_PublishMsg error code : %d", ret);
        return;
    }

    destroy_DB_Data(pstDataLst_head);
    return;
}

void zebra_Db_Del_SRV6_LOCAL_SID(const struct in6_addr *result_sid, const struct seg6local_context *ctx)
{
    int ret;
    char key[ZEBRA_DB_MAX_KEY_LEN] = {0};
    char set_key[ZEBRA_DB_MAX_KEY_LEN] = {0};
    char set_value[ZEBRA_DB_MAX_VALUE_LEN] = {0};
    char channel[ZEBRA_DB_MAX_KEY_LEN] = {0};
    char dbErrMsg[100] = {0};
    DB_Key_List item = {0};
    char G[] = "G";

    if (!g_bZebraRedisInUse_appdb) {
        zlog_err("redis err, redis app db handle init failed");
        return;
    }

    char my_local_sid[ZEBRA_DB_MAX_SID_LEN] = {0};
    struct prefix p = {};

    p.family = AF_INET6;
    p.prefixlen = ctx->block_bits_length + ctx->node_bits_length + ctx->function_bits_length;
    p.u.prefix6 = *result_sid;
    prefix2str(&p, my_local_sid, ZEBRA_DB_MAX_SID_LEN);

    /* del key*/
    snprintf(key, ZEBRA_DB_MAX_KEY_LEN, "%s:%s", SRV6_MY_SID_TABLE, my_local_sid);
    item.next = NULL;
    item.key = key;

    ret = g_zebra_redis_appdb.redis_Db_DelKeyLst(&item, dbErrMsg, sizeof(dbErrMsg), REDIS_APP_DB);
    if (ret)
    {
        zlog_err("redis_Db_DelKeyLst error code : %d", ret);
        return;
    }

    /*sadd DEL_SET*/
    snprintf(set_key, ZEBRA_DB_MAX_KEY_LEN, "%s_DEL_SET", SRV6_MY_SID_TABLE);
    snprintf(set_value, ZEBRA_DB_MAX_VALUE_LEN, "%s", my_local_sid);
    ret = g_zebra_redis_appdb.redis_Db_SetSadd(set_key, set_value, dbErrMsg, sizeof(dbErrMsg), REDIS_APP_DB);
    if (ret)
    {
        zlog_err("redis_Db_SetSadd DEL_SET error code : %d", ret);
        return;
    }

    /*sadd KEY_SET*/
    snprintf(set_key, ZEBRA_DB_MAX_KEY_LEN, "%s_KEY_SET", SRV6_MY_SID_TABLE);
    ret = g_zebra_redis_appdb.redis_Db_SetSadd(set_key, set_value, dbErrMsg, sizeof(dbErrMsg), REDIS_APP_DB);
    if (ret)
    {
        zlog_err("redis_Db_SetSadd KEY_SET error code : %d", ret);
        return;
    }

    /*publish*/
    snprintf(channel, ZEBRA_DB_MAX_KEY_LEN, "%s_CHANNEL@%s", SRV6_MY_SID_TABLE, TAG);
    zlog_debug("redis publishMsg channel : %s", channel);
    ret = g_zebra_redis_appdb.redis_PublishMsg(channel, G, REDIS_APP_DB);
    if (ret)
    {
        zlog_err("redis_PublishMsg error code : %d", ret);
    }

    return;

}



