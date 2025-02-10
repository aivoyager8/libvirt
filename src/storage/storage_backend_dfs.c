/*
 * storage_backend_dfs.c: storage backend for DFS handling
 *
 * Copyright (C) 2025 ChenHonggang
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <inttypes.h>
#include "datatypes.h"
#include "virerror.h"
#include "storage_conf.h"
#include "viralloc.h"
#include "viridentity.h"
#include "virlog.h"
#include "viruuid.h"
#include "virrandom.h"
#include "virsecret.h"
#include "storage_util.h"
#include "virsecureerase.h"

#include "storage_backend_dfs.h"
#include "daos.h"
#include "daos_fs.h"
#include <fcntl.h>
#include <sys/stat.h>

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage.storage_backend_dfs");

struct _virStorageBackendDFSState
{
    daos_handle_t poh;      /* Pool handle */
    daos_handle_t coh;      /* Container handle */
    dfs_t *dfs;             /* DFS mount handle */
    daos_pool_info_t pinfo; /* Pool information */
    time_t starttime;       /* Connection start time */
    char *pool;             /* Pool UUID or label */
    char *cont;             /* Container UUID or label */
    char *file;             /* File name */
};

typedef struct _virStorageBackendDFSState virStorageBackendDFSState;

typedef struct _virStoragePoolDFSConfigOptionsDef
{
    char *pool_name;   /* DFS pool name */
    char *host;        /* DFS server host */
    int port;          /* DFS server port */
    char *username;    /* Auth username */
    char *secret_uuid; /* Auth secret UUID */
    size_t noptions;   /* Number of additional options */
    char **names;      /* Option names array */
    char **values;     /* Option values array */
} virStoragePoolDFSConfigOptionsDef;

// 添加前向声明
static void virStoragePoolDefDFSNamespaceFree(void *nsdata);

/* Function declarations */
static int
virStorageBackendDFSParseVolName(virStorageVolDef *vol,
                                 char **container,
                                 char **filename);

/**
 * Opens a connection to the DFS storage backend.
 *
 * @param ptr Pointer to DFS backend state structure
 * @param def Storage pool definition
 *
 * @return 0 on success, -1 on failure
 */
static int virStorageBackendDFSOpenConn(virStorageBackendDFSState *ptr,
                                        virStoragePoolDef *def)
{
    virStoragePoolDFSConfigOptionsDef *opts = def->namespaceData;
    int ret = -1;
    g_autofree char *sys = NULL;

    if (!ptr || !def)
    {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing required DFS connection parameters"));
        return -1;
    }

    // 使用 daos_init 进行初始化
    ret = daos_init();
    if (ret < 0)
    {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to init DAOS: %d"), ret);
        return -1;
    }

    // 如果有认证信息,设置认证
    if (opts->username)
    {
        // TODO: 处理认证
    }

    // 连接存储池
    ret = daos_pool_connect(opts->pool_name, NULL, DAOS_PC_RW,
                            &ptr->poh, &ptr->pinfo, NULL);

    if (ret < 0)
    {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to connect to DFS pool '%s': %d"),
                       opts->pool_name, ret);
        goto cleanup;
    }

    ptr->starttime = time(NULL);
    VIR_DEBUG("Connected to DFS pool '%s'", ptr->pool);
    return 0;

cleanup:
    if (ptr->poh.cookie)
    {
        daos_pool_disconnect(ptr->poh, NULL);
    }
    g_clear_pointer(&ptr->pool, g_free);
    g_clear_pointer(&ptr->cont, g_free);
    g_clear_pointer(&ptr->file, g_free);
    return -1;
}

/**
 * Closes the DFS connection and cleans up associated resources
 *
 * @param ptr Pointer to the DFS storage backend state structure to be cleaned up
 *
 * This function handles cleanup of DFS connection state, ensuring proper
 * disconnection from the DFS storage backend and release of any associated
 * resources.
 */
static void virStorageBackendDFSCloseConn(virStorageBackendDFSState *ptr)
{
    if (!ptr)
    {
        return;
    }

    if (ptr->poh.cookie)
    {
        daos_pool_disconnect(ptr->poh, NULL);
        ptr->poh.cookie = 0;
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to disconnect from DFS pool"));
    }

    g_clear_pointer(&ptr->pool, g_free);
    g_clear_pointer(&ptr->cont, g_free);
    g_clear_pointer(&ptr->file, g_free);
}

/**
 * Frees the DFS storage backend state structure
 *
 * @param ptr Pointer to the DFS storage backend state structure to be freed
 *
 * This function handles cleanup of the DFS storage backend state structure,
 * ensuring proper release of any associated resources.
 */
static int virStorageBackendDFSCreateVol(virStoragePoolObj *pool,
                                         virStorageVolDef *vol)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    dfs_obj_t *obj = NULL;
    virStorageBackendDFSState *ptr = NULL;
    int ret = -1;
    g_autofree char *container = NULL;
    g_autofree char *filename = NULL;

    if (!def || !vol)
    {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing pool or volume definition"));
        return -1;
    }

    VIR_DEBUG("Creating DFS volume...");

    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("DFS volume creation is not supported"));

    // Check volume format early
    if (vol->target.format != VIR_STORAGE_FILE_RAW)
    {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("only RAW volumes are supported by this storage pool"));
        return -1;
    }

    if (!(ptr = g_new0(virStorageBackendDFSState, 1)))
        return -1;

    if (virStorageBackendDFSOpenConn(ptr, def) < 0)
        goto cleanup;

    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("DFS volume creating"));

    // 修改调用, 删除pool参数
    if (virStorageBackendDFSParseVolName(vol, &container, &filename) < 0)
        return -1;

    // Set volume attributes
    vol->type = VIR_STORAGE_VOL_NETWORK;
    vol->target.format = VIR_STORAGE_FILE_RAW;

    // Update volume paths using pool/container/filename format
    g_clear_pointer(&vol->target.path, g_free);
    g_clear_pointer(&vol->key, g_free);

    vol->target.path = g_strdup_printf("dfs:%s/%s",
                                       def->source.name,
                                       vol->name);
    vol->key = g_strdup_printf("dfs:%s/%s",
                               def->source.name,
                               vol->name);

    if (!vol->target.path || !vol->key)
    {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to allocate volume paths"));
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (obj)
        dfs_release(obj);
    virStorageBackendDFSCloseConn(ptr);
    VIR_FREE(ptr);
    return ret;
}

static int
virStorageBackendDFSDeleteVol(virStoragePoolObj *pool,
                              virStorageVolDef *vol,
                              unsigned int flags G_GNUC_UNUSED)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    virStorageBackendDFSState *ptr = NULL;
    dfs_obj_t *parent = NULL;
    g_autofree char *container = NULL;
    g_autofree char *filename = NULL;
    int ret = -1;

    if (!(ptr = g_new0(virStorageBackendDFSState, 1)))
        return -1;

    if (virStorageBackendDFSOpenConn(ptr, def) < 0)
        goto cleanup;

    if (virStorageBackendDFSParseVolName(vol, &container, &filename) < 0)
        goto cleanup;

    ret = dfs_lookup(ptr->dfs, container, O_RDONLY, &parent, NULL, NULL);
    if (ret < 0)
    {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to lookup container '%s'"), container);
        goto cleanup;
    }

    ret = dfs_remove(ptr->dfs, parent, filename, true, NULL);
    if (ret < 0 && ret != -ENOENT)
    {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to remove DFS file '%s/%s'"), container, filename);
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (parent)
        dfs_release(parent);
    virStorageBackendDFSCloseConn(ptr);
    VIR_FREE(ptr);
    return ret;
}

static int
virStorageBackendDFSResizeVol(virStoragePoolObj *pool,
                              virStorageVolDef *vol,
                              unsigned long long capacity,
                              unsigned int flags)
{
    VIR_DEBUG("Resizing DFS volume pool=%p vol=%s capacity=%llu flags=0x%x",
              pool, vol->name, capacity, flags);

    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("DFS volume resizing is not supported"));
    return -1;
}

static int
virStorageBackendDFSRefreshPool(virStoragePoolObj *pool)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    virStorageBackendDFSState *ptr = NULL;
    struct daos_pool_space *space;
    int ret = -1;

    if (!(ptr = g_new0(virStorageBackendDFSState, 1)))
        return -1;

    if (virStorageBackendDFSOpenConn(ptr, def) < 0)
        goto cleanup;

    // 查询存储池信息
    if (daos_pool_query(ptr->poh, NULL, &ptr->pinfo, NULL, NULL) < 0)
    {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to query DFS pool '%s'"), def->source.name);
        goto cleanup;
    }

    // 获取存储池空间信息
    space = &ptr->pinfo.pi_space;

    // 每个target的平均可用空间(bytes) * target数量 = 总可用空间
    def->available = space->ps_free_mean[DAOS_MEDIA_SCM] * space->ps_ntargets;

    // 每个target的容量 * target数量 = 总容量
    def->capacity = space->ps_space.s_total[DAOS_MEDIA_SCM] * space->ps_ntargets;

    // 已分配空间 = 总容量 - 可用空间
    def->allocation = def->capacity - def->available;

    VIR_DEBUG("Refreshed DFS pool '%s': capacity=%llu allocation=%llu available=%llu ntargets=%u",
              def->source.name, def->capacity, def->allocation,
              def->available, space->ps_ntargets);
    ret = 0;

cleanup:
    virStorageBackendDFSCloseConn(ptr);
    VIR_FREE(ptr);
    return ret;
}

static int
virStorageBackendDFSBuildVol(virStoragePoolObj *pool,
                             virStorageVolDef *vol,
                             unsigned int flags G_GNUC_UNUSED)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    virStorageBackendDFSState *ptr = NULL;
    dfs_obj_t *obj = NULL;
    int ret = -1;

    // 检查容量参数
    if (!vol->target.capacity)
    {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("volume capacity required for DFS pool"));
        goto cleanup;
    }

    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("DFS volume creation is not supported"));

    if (!(ptr = g_new0(virStorageBackendDFSState, 1)))
        goto cleanup;

    if (virStorageBackendDFSOpenConn(ptr, def) < 0)
        goto cleanup;

    // 创建 DFS 文件
    ret = dfs_open(ptr->dfs, NULL, vol->name, S_IFREG | 0644,
                   O_CREAT | O_RDWR, 0, 0, NULL, &obj);
    if (ret < 0)
    {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to create DFS file '%s'"), vol->name);
        goto cleanup;
    }

    // 设置文件大小
    ret = dfs_punch(ptr->dfs, obj, 0, vol->target.capacity);
    if (ret < 0)
    {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to set size for '%s'"), vol->name);
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (obj)
        dfs_release(obj);
    virStorageBackendDFSCloseConn(ptr);
    VIR_FREE(ptr);
    return ret;
}

static int
virStorageBackendDFSBuildVolFrom(virStoragePoolObj *pool,
                                 virStorageVolDef *vol,
                                 virStorageVolDef *inputvol,
                                 unsigned int flags)
{
    int ret = -1;
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    virStorageBackendDFSState *ptr = NULL;

    VIR_DEBUG("Building DFS volume from pool=%p vol=%s inputvol=%s flags=0x%x def=%p ptr=%p",
              pool, vol->name, inputvol->name, flags, def, ptr);

    ret = 0;

    if (ptr)
    {
        virStorageBackendDFSCloseConn(ptr);
        VIR_FREE(ptr);
    }
    return ret;
}

static int
virStorageBackendDFSRefreshVol(virStoragePoolObj *pool,
                               virStorageVolDef *vol)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    virStorageBackendDFSState *ptr = NULL;
    dfs_obj_t *obj = NULL;
    struct stat stbuf;
    int ret = -1;

    if (!(ptr = g_new0(virStorageBackendDFSState, 1)))
        return -1;

    if (virStorageBackendDFSOpenConn(ptr, def) < 0)
        goto cleanup;

    // 获取文件信息
    ret = dfs_lookup(ptr->dfs, vol->name, DFS_RDONLY, &obj,
                     NULL, &stbuf);
    if (ret < 0)
    {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to lookup '%s'"), vol->name);
        goto cleanup;
    }

    // 更新卷信息
    vol->target.capacity = stbuf.st_size;
    vol->target.allocation = stbuf.st_blocks * 512;
    vol->type = VIR_STORAGE_VOL_NETWORK;
    vol->target.format = VIR_STORAGE_FILE_RAW;

    // 更新路径 - 使用正确的存储池名称和路径格式
    g_clear_pointer(&vol->target.path, g_free);
    g_clear_pointer(&vol->key, g_free);

    vol->target.path = g_strdup_printf("dfs:%s/%s",
                                       def->source.name,
                                       vol->name);
    vol->key = g_strdup_printf("dfs:%s/%s",
                               def->source.name,
                               vol->name);

    ret = 0;

cleanup:
    if (obj)
        dfs_release(obj);
    virStorageBackendDFSCloseConn(ptr);
    VIR_FREE(ptr);
    return ret;
}

static int
virStorageBackendDFSVolWipe(virStoragePoolObj *pool G_GNUC_UNUSED,
                            virStorageVolDef *vol G_GNUC_UNUSED,
                            unsigned int algorithm,
                            unsigned int flags)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    virStorageBackendDFSState *ptr = NULL;
    dfs_obj_t *obj = NULL;
    int ret = -1;
    d_sg_list_t sgl = {0}; // 修复不兼容的类型

    virCheckFlags(0, -1);

    if (!(ptr = g_new0(virStorageBackendDFSState, 1)))
        return -1;

    if (virStorageBackendDFSOpenConn(ptr, def) < 0)
        goto cleanup;

    switch ((virStorageVolWipeAlgorithm)algorithm)
    {
    case VIR_STORAGE_VOL_WIPE_ALG_ZERO:
        sgl.sg_iovs = g_malloc0(1024 * 1024); // 1MB buffer of zeros
        sgl.sg_nr = 1;
        sgl.sg_nr_out = 0;
        break;
    case VIR_STORAGE_VOL_WIPE_ALG_NNSA:
    case VIR_STORAGE_VOL_WIPE_ALG_DOD:
    case VIR_STORAGE_VOL_WIPE_ALG_BSI:
    case VIR_STORAGE_VOL_WIPE_ALG_GUTMANN:
    case VIR_STORAGE_VOL_WIPE_ALG_SCHNEIER:
    case VIR_STORAGE_VOL_WIPE_ALG_PFITZNER7:
    case VIR_STORAGE_VOL_WIPE_ALG_PFITZNER33:
    case VIR_STORAGE_VOL_WIPE_ALG_RANDOM:
    case VIR_STORAGE_VOL_WIPE_ALG_TRIM:
    case VIR_STORAGE_VOL_WIPE_ALG_LAST:
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unsupported wiping algorithm %d"),
                       algorithm);
        goto cleanup;
    }

    if (ret < 0)
    {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to wipe data in DFS volume"));
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (sgl.sg_iovs)
        g_free(sgl.sg_iovs);
    if (obj)
        dfs_release(obj);
    virStorageBackendDFSCloseConn(ptr);
    VIR_FREE(ptr);
    return ret;
}

// DFS namespace free接口示例
static void
virStoragePoolDefDFSNamespaceFree(void *nsdata)
{
    virStoragePoolDFSConfigOptionsDef *opts = nsdata;
    size_t i;

    if (!opts)
        return;

    g_free(opts->pool_name);
    g_free(opts->host);
    g_free(opts->username);
    g_free(opts->secret_uuid);

    for (i = 0; i < opts->noptions; i++)
    {
        g_free(opts->names[i]);
        g_free(opts->values[i]);
    }
    g_free(opts->names);
    g_free(opts->values);
    g_free(opts);
}

static int
virStoragePoolDefDFSNamespaceParse(xmlXPathContextPtr ctxt,
                                   void **nsdata)
{
    virStoragePoolDFSConfigOptionsDef *opts = NULL;
    g_autofree xmlNodePtr *nodes = NULL;
    g_autofree char *source_name = NULL;
    g_autofree xmlNodePtr *hosts = NULL;
    g_autofree char *auth_username = NULL;
    g_autofree char *auth_uuid = NULL;
    int nhosts;
    int port = 10999; // 默认端口移到这里

    // Parse pool name
    source_name = virXPathString("string(./source/name)", ctxt);
    if (!source_name)
    {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("DFS pool must specify name in source"));
        return -1;
    }

    // Parse host info
    nhosts = virXPathNodeSet("./source/host", ctxt, &hosts);
    if (nhosts <= 0)
    {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("DFS pool must specify host in source"));
        return -1;
    }

    // Parse auth info if present
    auth_username = virXPathString("string(./source/auth/@username)", ctxt);
    auth_uuid = virXPathString("string(./source/auth/secret/@uuid)", ctxt);

    opts = g_new0(virStoragePoolDFSConfigOptionsDef, 1);
    opts->pool_name = g_strdup(source_name);
    opts->host = g_strdup(virXMLPropString(hosts[0], "name"));

    // 正确调用 virXMLPropInt:
    // virXMLPropInt(xmlNodePtr node, const char *name, int base,
    //               virXMLPropFlags flags, int *result, int default_val)
    if (virXMLPropInt(hosts[0], "port", 10, 0, &port, 10999) < 0)
        goto cleanup;
    opts->port = port;

    if (auth_username)
        opts->username = g_strdup(auth_username);
    if (auth_uuid)
        opts->secret_uuid = g_strdup(auth_uuid);

    *nsdata = g_steal_pointer(&opts);
    return 0;

cleanup:
    virStoragePoolDefDFSNamespaceFree(opts);
    return -1;
}

// 修改 virStoragePoolDefDFSNamespaceFormatXML 函数
static int
virStoragePoolDefDFSNamespaceFormatXML(virBuffer *buf,
                                       void *nsdata)
{
    virStoragePoolDFSConfigOptionsDef *def = nsdata;

    if (!def)
        return 0;

    // 这里不需要生成额外的source标签,因为主XML已经有source标签
    // 只需要在主XML的source标签中添加我们的特定属性
    virBufferAddLit(buf, "enable_pool_ops='yes'>\n");

    return 0;
}

virStorageBackend virStorageBackendDFS = {
    .type = VIR_STORAGE_POOL_DFS,

    // Pool operations
    .refreshPool = virStorageBackendDFSRefreshPool, // 获取存储池容量信息

    // Volume operations
    .createVol = virStorageBackendDFSCreateVol,       // 创建卷定义
    .buildVol = virStorageBackendDFSBuildVol,         // 实际创建卷文件
    .buildVolFrom = virStorageBackendDFSBuildVolFrom, // 从现有卷创建新卷
    .refreshVol = virStorageBackendDFSRefreshVol,     // 刷新卷信息
    .deleteVol = virStorageBackendDFSDeleteVol,       // 删除卷
    .resizeVol = virStorageBackendDFSResizeVol,       // 调整卷大小
    .wipeVol = virStorageBackendDFSVolWipe,           // 擦除卷内容
};

static virXMLNamespace virStoragePoolDFSXMLNamespace = {
    .parse = virStoragePoolDefDFSNamespaceParse,
    .free = virStoragePoolDefDFSNamespaceFree,
    .format = virStoragePoolDefDFSNamespaceFormatXML,
    .prefix = "dfs",
    .uri = "http://libvirt.org/schemas/storagepool/dfs/1.0",
};

int virStorageBackendDFSRegister(void)
{
    if (virStorageBackendRegister(&virStorageBackendDFS) < 0)
        return -1;

    return virStorageBackendNamespaceInit(VIR_STORAGE_POOL_DFS,
                                          &virStoragePoolDFSXMLNamespace);
}

static int
virStorageBackendDFSParseVolName(virStorageVolDef *vol,
                                 char **container,
                                 char **filename)
{
    char *slash;

    // 检查卷名是否包含 '/'
    if (!(slash = strchr(vol->name, '/')))
    {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("volume name '%s' must be in format 'container/filename'"),
                       vol->name);
        return -1;
    }

    // 分割容器名和文件名
    *container = g_strndup(vol->name, slash - vol->name);
    *filename = g_strdup(slash + 1);

    if (!**container || !**filename)
    {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("invalid volume name '%s', must be 'container/filename'"),
                       vol->name);
        return -1;
    }

    return 0;
}
