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

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage.storage_backend_dfs");

struct _virStorageBackendDFSState {
    daos_handle_t poh;         /* Pool handle */
    daos_handle_t coh;         /* Container handle */ 
    dfs_t *dfs;               /* DFS mount handle */
    time_t starttime;         /* Connection start time */
    char *pool;              /* Pool UUID or label */
    char *cont;              /* Container UUID or label */
};

typedef struct _virStorageBackendDFSState virStorageBackendDFSState;

typedef struct _virStoragePoolDFSConfigOptionsDef {
    size_t noptions;
    char **names;
    char **values;
} virStoragePoolDFSConfigOptionsDef;

static int
virStorageBackendDFSOpenConn(virStorageBackendDFSState *ptr,
                             virStoragePoolDef *def)
{
    int ret = -1;
    daos_pool_info_t pinfo;
    daos_cont_info_t cinfo;

    VIR_DEBUG("Connecting to DAOS pool '%s' container '%s'",
              def->source.name, def->source.path);

    /* Initialize DAOS */
    if (daos_init() != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to initialize DAOS"));
        return -1;
    }

    /* Connect to pool */
    if (daos_pool_connect(def->source.name, NULL, DAOS_PC_RW,
                         &ptr->poh, &pinfo, NULL) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to connect to DAOS pool '%s'"),
                       def->source.name);
        goto cleanup_init;
    }

    /* Open container */
    if (daos_cont_open(ptr->poh, def->source.path, DAOS_COO_RW,
                       &ptr->coh, &cinfo, NULL) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to open DAOS container '%s'"),
                       def->source.path);
        goto cleanup_pool;
    }

    /* Mount DFS */
    if (dfs_mount(def->source.name, def->source.path, O_RDWR, &ptr->dfs) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to mount DFS"));
        goto cleanup_cont;  
    }

    ptr->pool = g_strdup(def->source.name);
    ptr->cont = g_strdup(def->source.path);
    ptr->starttime = time(0);

    VIR_DEBUG("Successfully connected to DAOS pool '%s' container '%s'",
              ptr->pool, ptr->cont);

    return 0;

cleanup_cont:
    daos_cont_close(ptr->coh, NULL);
cleanup_pool:  
    daos_pool_disconnect(ptr->poh, NULL);
cleanup_init:
    daos_fini();
    return ret;
}

static void
virStorageBackendDFSCloseConn(virStorageBackendDFSState *ptr)
{
    if (!ptr)
        return;

    if (ptr->dfs) {
        dfs_umount(ptr->dfs);
        ptr->dfs = NULL;
    }

    if (!daos_handle_is_inval(ptr->coh)) {
        daos_cont_close(ptr->coh, NULL);
        ptr->coh = DAOS_HDL_INVAL;
    }

    if (!daos_handle_is_inval(ptr->poh)) {
        daos_pool_disconnect(ptr->poh, NULL);
        ptr->poh = DAOS_HDL_INVAL;
    }

    daos_fini();

    VIR_FREE(ptr->pool);
    VIR_FREE(ptr->cont);

    VIR_DEBUG("DFS connection existed for %ld seconds", time(0) - ptr->starttime);
}

static int
virStorageBackendDFSCreateVol(virStoragePoolObj *pool,
                              virStorageVolDef *vol)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool); 
    dfs_obj_t *obj = NULL;
    mode_t mode = S_IFREG | 0644;
    int ret = -1;
    virStorageBackendDFSState *ptr = NULL;

    if (!(ptr = g_new0(virStorageBackendDFSState, 1)))
        return -1;

    if (virStorageBackendDFSOpenConn(ptr, def) < 0)
        goto cleanup;

    VIR_DEBUG("Creating DFS volume '%s'", vol->name);

    if (dfs_open(ptr->dfs, NULL, vol->name, mode,
                 O_CREAT | O_RDWR, 0, 0, NULL, &obj) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to create DFS volume '%s'"), vol->name);
        goto cleanup;
    }

    vol->type = VIR_STORAGE_VOL_NETWORK;
    vol->target.format = VIR_STORAGE_FILE_RAW;

    VIR_FREE(vol->target.path);
    vol->target.path = g_strdup_printf("%s/%s", def->source.path, vol->name);

    VIR_FREE(vol->key);
    vol->key = g_strdup_printf("%s/%s", def->source.name, vol->name);

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
                              unsigned int flags)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    dfs_t *dfs;

    if (dfs_mount(def->source.name, def->source.path, O_RDWR, &dfs) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("failed to mount DFS"));
        return -1;
    }

    if (dfs_remove(dfs, NULL, vol->name, 0, NULL) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("failed to delete DFS volume"));
        dfs_umount(dfs);
        return -1;
    }

    dfs_umount(dfs);
    return 0;
}

static int
virStorageBackendDFSResizeVol(virStoragePoolObj *pool,
                              virStorageVolDef *vol,
                              unsigned long long capacity,
                              unsigned int flags)
{
    virReportError(VIR_ERR_NO_SUPPORT, "%s", _("DFS volume resizing is not supported"));
    return -1;
}

static int
virStorageBackendDFSRefreshPool(virStoragePoolObj *pool)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    virStorageBackendDFSState *ptr = NULL;
    dfs_obj_t *obj = NULL;
    dfs_attr_t attr;
    int ret = -1;

    if (!(ptr = g_new0(virStorageBackendDFSState, 1)))
        return -1;

    if (virStorageBackendDFSOpenConn(ptr, def) < 0)
        goto cleanup;

    if (dfs_query(ptr->dfs, &attr) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to query DFS pool '%s'"), def->source.name);
        goto cleanup;
    }

    def->capacity = attr.da_chunk_size;
    def->allocation = attr.da_chunk_size; // For now use same as capacity
    def->available = def->capacity - def->allocation;

    VIR_DEBUG("Refreshed DFS pool '%s': capacity=%llu allocation=%llu available=%llu",
              def->source.name, def->capacity, def->allocation, def->available);

    ret = 0;

cleanup:
    if (obj)
        dfs_release(obj);
    virStorageBackendDFSCloseConn(ptr);
    VIR_FREE(ptr);
    return ret; 
}

static int
virStorageBackendDFSBuildVol(virStoragePoolObj *pool,
                            virStorageVolDef *vol,
                            unsigned int flags)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    virStorageBackendDFSState *ptr = NULL;
    int ret = -1;
    dfs_obj_t *obj = NULL;
    mode_t mode = S_IFREG | 0644;

    VIR_DEBUG("Creating DFS volume '%s'", vol->name);

    if (!(ptr = g_new0(virStorageBackendDFSState, 1)))
        return -1;

    if (virStorageBackendDFSOpenConn(ptr, def) < 0)
        goto cleanup;

    if (dfs_open(ptr->dfs, NULL, vol->name, mode,
                 O_CREAT | O_RDWR, 0, 0, NULL, &obj) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to create DFS volume '%s'"), vol->name);
        goto cleanup;
    }

    vol->type = VIR_STORAGE_VOL_NETWORK;
    vol->target.format = VIR_STORAGE_FILE_RAW;

    VIR_FREE(vol->target.path);
    vol->target.path = g_strdup_printf("%s/%s", def->source.path, vol->name);

    VIR_FREE(vol->key);
    vol->key = g_strdup_printf("%s/%s", def->source.name, vol->name);

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
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    virStorageBackendDFSState *ptr = NULL;
    int ret = -1;
    dfs_obj_t *src_obj = NULL;
    dfs_obj_t *dst_obj = NULL;
    mode_t mode = S_IFREG | 0644;
    char *buf = NULL;
    ssize_t read_size, write_size;

    VIR_DEBUG("Creating DFS volume '%s' from '%s'", vol->name, inputvol->name);

    if (!(ptr = g_new0(virStorageBackendDFSState, 1)))
        return -1;

    if (virStorageBackendDFSOpenConn(ptr, def) < 0)
        goto cleanup;

    if (dfs_open(ptr->dfs, NULL, inputvol->name, mode, O_RDONLY, 0, 0, NULL, &src_obj) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to open source DFS volume '%s'"), inputvol->name);
        goto cleanup;
    }

    if (dfs_open(ptr->dfs, NULL, vol->name, mode, O_CREAT | O_RDWR, 0, 0, NULL, &dst_obj) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to create destination DFS volume '%s'"), vol->name);
        goto cleanup;
    }

    buf = g_malloc0(1024 * 1024); // 1MB buffer

    while ((read_size = dfs_read(ptr->dfs, src_obj, buf, 1024 * 1024)) > 0) {
        write_size = dfs_write(ptr->dfs, dst_obj, buf, read_size);
        if (write_size != read_size) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("failed to write data to DFS volume"));
            goto cleanup;
        }
    }

    if (read_size < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("failed to read data from DFS volume"));
        goto cleanup;
    }

    vol->type = VIR_STORAGE_VOL_NETWORK;
    vol->target.format = VIR_STORAGE_FILE_RAW;

    VIR_FREE(vol->target.path);
    vol->target.path = g_strdup_printf("%s/%s", def->source.path, vol->name);

    VIR_FREE(vol->key);
    vol->key = g_strdup_printf("%s/%s", def->source.name, vol->name);

    ret = 0;

cleanup:
    if (buf)
        g_free(buf);
    if (src_obj)
        dfs_release(src_obj);
    if (dst_obj)
        dfs_release(dst_obj);
    virStorageBackendDFSCloseConn(ptr);
    VIR_FREE(ptr);
    return ret;
}

static int
virStorageBackendDFSRefreshVol(virStoragePoolObj *pool,
                              virStorageVolDef *vol)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    virStorageBackendDFSState *ptr = NULL;
    dfs_obj_t *obj = NULL;
    dfs_attr_t attr;
    int ret = -1;

    if (!(ptr = g_new0(virStorageBackendDFSState, 1)))
        return -1;

    if (virStorageBackendDFSOpenConn(ptr, def) < 0)
        goto cleanup;

    if (dfs_open(ptr->dfs, NULL, vol->name, S_IFREG | 0644, O_RDONLY, 0, 0, NULL, &obj) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to open DFS volume '%s'"), vol->name);
        goto cleanup;
    }

    if (dfs_get_attr(ptr->dfs, obj, &attr) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to get attributes of DFS volume '%s'"), vol->name);
        goto cleanup;
    }

    vol->capacity = attr.da_chunk_size;
    vol->allocation = attr.da_chunk_size; // For now use same as capacity

    ret = 0;

cleanup:
    if (obj)
        dfs_release(obj);
    virStorageBackendDFSCloseConn(ptr);
    VIR_FREE(ptr);
    return ret;
}

static int
virStorageBackendDFSVolWipe(virStoragePoolObj *pool,
                           virStorageVolDef *vol,
                           unsigned int flags)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    virStorageBackendDFSState *ptr = NULL;
    dfs_obj_t *obj = NULL;
    int ret = -1;
    char *buf = NULL;
    ssize_t write_size;

    if (!(ptr = g_new0(virStorageBackendDFSState, 1)))
        return -1;

    if (virStorageBackendDFSOpenConn(ptr, def) < 0)
        goto cleanup;

    if (dfs_open(ptr->dfs, NULL, vol->name, S_IFREG | 0644, O_RDWR, 0, 0, NULL, &obj) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to open DFS volume '%s'"), vol->name);
        goto cleanup;
    }

    buf = g_malloc0(1024 * 1024); // 1MB buffer

    while ((write_size = dfs_write(ptr->dfs, obj, buf, 1024 * 1024)) > 0) {
        if (write_size != 1024 * 1024) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("failed to wipe data in DFS volume"));
            goto cleanup;
        }
    }

    if (write_size < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("failed to wipe data in DFS volume"));
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (buf)
        g_free(buf);
    if (obj)
        dfs_release(obj);
    virStorageBackendDFSCloseConn(ptr);
    VIR_FREE(ptr);
    return ret;
}

static int
virStoragePoolDefDFSNamespaceParse(xmlXPathContextPtr ctxt,
                                   void **nsdata)
{
    // 仅做示例解析, 可根据实际需要扩展更多逻辑
    // ...existing code (如需要)...

    virStoragePoolDFSConfigOptionsDef *opts = NULL;
    g_autofree xmlNodePtr *nodes = NULL;
    int nnodes, i;
    int ret = -1;

    nnodes = virXPathNodeSet("./dfs:config_opts/dfs:option", ctxt, &nodes);
    if (nnodes <= 0)
        return 0; // 没有dfs:option节点则直接返回

    opts = g_new0(virStoragePoolDFSConfigOptionsDef, 1);
    opts->noptions = nnodes;
    opts->names = g_new0(char *, nnodes);
    opts->values = g_new0(char *, nnodes);

    for (i = 0; i < nnodes; i++) {
        // ...existing code...
        // 从XML节点读option name, value并存储
        // opts->names[i] = ...
        // opts->values[i] = ...
    }

    *nsdata = opts;
    ret = 0;
    // ...existing code...
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

    for (i = 0; i < opts->noptions; i++) {
        g_free(opts->names[i]);
        g_free(opts->values[i]);
    }
    g_free(opts->names);
    g_free(opts->values);
    g_free(opts);
}

// DFS namespace format接口示例
static int
virStoragePoolDefDFSNamespaceFormatXML(virBuffer *buf,
                                       void *nsdata)
{
    virStoragePoolDFSConfigOptionsDef *opts = nsdata;
    size_t i;

    if (!opts)
        return 0;

    virBufferAddLit(buf, "<dfs:config_opts>\n");
    virBufferAdjustIndent(buf, 2);

    for (i = 0; i < opts->noptions; i++) {
        virBufferAsprintf(buf,
                          "<dfs:option name=\"%s\" value=\"%s\"/>\n",
                          opts->names[i] ? opts->names[i] : "",
                          opts->values[i] ? opts->values[i] : "");
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</dfs:config_opts>\n");
    return 0;
}


virStorageBackend virStorageBackendDFS = {
    .type = VIR_STORAGE_POOL_DFS,

    .refreshPool = virStorageBackendDFSRefreshPool,
    .createVol = virStorageBackendDFSCreateVol,
    .buildVol = virStorageBackendDFSBuildVol,
    .buildVolFrom = virStorageBackendDFSBuildVolFrom,
    .refreshVol = virStorageBackendDFSRefreshVol,
    .deleteVol = virStorageBackendDFSDeleteVol,
    .resizeVol = virStorageBackendDFSResizeVol,
    .wipeVol = virStorageBackendDFSVolWipe
};


static virXMLNamespace virStoragePoolDFSXMLNamespace = {
    .parse = virStoragePoolDefDFSNamespaceParse,
    .free = virStoragePoolDefDFSNamespaceFree,
    .format = virStoragePoolDefDFSNamespaceFormatXML,
    .prefix = "dfs",
    .uri = "http://libvirt.org/schemas/storagepool/dfs/1.0",
};

int
virStorageBackendDFSRegister(void)
{
    if (virStorageBackendRegister(&virStorageBackendDFS) < 0)
        return -1;

    return virStorageBackendNamespaceInit(VIR_STORAGE_POOL_DFS,
                                          &virStoragePoolDFSXMLNamespace);
}
