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
    char *file;              /* File name */
};

typedef struct _virStorageBackendDFSState virStorageBackendDFSState;

typedef struct _virStoragePoolDFSConfigOptionsDef {
    size_t noptions;
    char **names;
    char **values;
} virStoragePoolDFSConfigOptionsDef;

// 添加前向声明
static void virStoragePoolDefDFSNamespaceFree(void *nsdata);

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
    g_autofree char *pool_cont = NULL;
    int ret = -1;
    char *slash;

    if (!ptr || !def || !def->source.name || !def->source.dir) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                      _("missing required DFS connection parameters"));
        return -1;
    }

    // Make a copy and parse pool/container
    pool_cont = g_strdup(def->source.dir);
    if ((slash = strchr(pool_cont, '/')) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                      _("invalid DFS dir format - expected pool/container"));
        return -1;
    }
    *slash = '\0';

    // Store pool and container names
    ptr->pool = g_strdup(pool_cont);
    ptr->cont = g_strdup(slash + 1);
    ptr->file = g_strdup(def->source.name);

    if (!ptr->pool || !ptr->cont || !ptr->file) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                      _("failed to allocate DFS connection strings"));
        goto cleanup;
    }

    // Connect to DAOS pool
    ret = daos_pool_connect(ptr->pool, NULL, DAOS_PC_RW, 
                           &ptr->poh, NULL, NULL);
    if (ret < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                      _("failed to connect to DFS pool '%s': %d"),
                      ptr->pool, ret);
        goto cleanup;
    }

    ptr->starttime = time(NULL);
    VIR_DEBUG("Connected to DFS pool '%s'", ptr->pool);
    return 0;

cleanup:
    if (ptr->poh.cookie)
        daos_pool_disconnect(ptr->poh, NULL);
    g_clear_pointer(&ptr->pool, g_free);
    g_clear_pointer(&ptr->cont, g_free); 
    g_clear_pointer(&ptr->file, g_free);
    return -1;
}

static void
virStorageBackendDFSCloseConn(virStorageBackendDFSState *ptr)
{
    if (!ptr)
        return;
}

static int
virStorageBackendDFSCreateVol(virStoragePoolObj *pool,
                              virStorageVolDef *vol)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool); 
    dfs_obj_t *obj = NULL;
    int ret = -1;
    virStorageBackendDFSState *ptr = NULL;

    if (!(ptr = g_new0(virStorageBackendDFSState, 1)))
        return -1;

    if (virStorageBackendDFSOpenConn(ptr, def) < 0)
        goto cleanup;

    VIR_DEBUG("Creating DFS volume '%s' ", vol->name);
    goto cleanup;


    vol->type = VIR_STORAGE_VOL_NETWORK;
    vol->target.format = VIR_STORAGE_FILE_RAW;

    VIR_FREE(vol->target.path);
    vol->target.path = g_strdup_printf("%s/%s", def->source.dir, vol->name);

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

    VIR_DEBUG("Deleting DFS volume pool=%p vol=%s flags=0x%x def=%p",
              pool, vol->name, flags, def);

    return 0;
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
    int ret = -1;
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    virStorageBackendDFSState *ptr = NULL;

    VIR_DEBUG("Building DFS volume pool=%p vol=%s flags=0x%x def=%p ptr=%p",
              pool, vol->name, flags, def, ptr);

    ret = 0;
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
    
    if (ptr) {
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
    int ret = -1;

    if (!(ptr = g_new0(virStorageBackendDFSState, 1)))
        return -1;

    if (virStorageBackendDFSOpenConn(ptr, def) < 0)
        goto cleanup;

    VIR_DEBUG("Refreshing DFS volume '%s'", vol->name);

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

    switch ((virStorageVolWipeAlgorithm) algorithm) {
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

    if (ret < 0) {
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

    for (i = 0; i < opts->noptions; i++) {
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
    int nnodes;
    int ret = -1;

    nnodes = virXPathNodeSet("./dfs:config_opts/dfs:option", ctxt, &nodes);
    if (nnodes < 0)
        return -1;

    if (nnodes == 0)
        return 0;

    opts = g_new0(virStoragePoolDFSConfigOptionsDef, 1);

    opts->names = g_new0(char *, nnodes);
    opts->values = g_new0(char *, nnodes); 

    for (int i = 0; i < nnodes; i++) {
        if (!(opts->names[opts->noptions] = 
              virXMLPropString(nodes[i], "name"))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("no dfs option name specified"));
            goto cleanup;
        }

        if (!(opts->values[opts->noptions] =
              virXMLPropString(nodes[i], "value"))) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("no value specified for option '%s'"),
                           opts->names[opts->noptions]);
            goto cleanup;
        }

        opts->noptions++;
    }

    *nsdata = g_steal_pointer(&opts);
    ret = 0;

cleanup:
    virStoragePoolDefDFSNamespaceFree(opts);
    return ret;
}

// DFS namespace format接口示例
static int
virStoragePoolDefDFSNamespaceFormatXML(virBuffer *buf,
                                       void *nsdata)
{
    virStoragePoolDFSConfigOptionsDef *def = nsdata;

    if (!def || !def->noptions)
        return 0;

    virBufferAddLit(buf, "<dfs:config_opts>\n");
    virBufferAdjustIndent(buf, 2);

    for (size_t i = 0; i < def->noptions; i++) {
        if (def->names[i] && def->values[i])
            virBufferAsprintf(buf, "<dfs:option name='%s' value='%s'/>\n",
                             def->names[i], def->values[i]);
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
