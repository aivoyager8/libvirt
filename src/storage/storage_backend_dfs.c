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
    daos_handle_t poh;
    daos_handle_t coh;
    time_t starttime;
};

typedef struct _virStorageBackendDFSState virStorageBackendDFSState;

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

static int
virStorageBackendDFSOpenConn(virStorageBackendDFSState *ptr,
                             virStoragePoolDef *def)
{
    int ret = -1;
    daos_pool_info_t pinfo;
    daos_cont_info_t cinfo;
    daos_handle_t poh, coh;

    if (daos_pool_connect(def->source.name, NULL, DAOS_PC_RW, &poh, &pinfo, NULL) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("failed to connect to the DAOS pool"));
        return ret;
    }

    if (daos_cont_open(poh, def->source.path, DAOS_COO_RW, &coh, &cinfo, NULL) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("failed to open the DAOS container"));
        daos_pool_disconnect(poh, NULL);
        return ret;
    }

    ptr->poh = poh;
    ptr->coh = coh;
    ptr->starttime = time(0);

    return 0;
}

static void
virStorageBackendDFSCloseConn(virStorageBackendDFSState *ptr)
{
    if (!daos_handle_is_inval(ptr->coh)) {
        daos_cont_close(ptr->coh, NULL);
    }

    if (!daos_handle_is_inval(ptr->poh)) {
        daos_pool_disconnect(ptr->poh, NULL);
    }

    VIR_DEBUG("DFS connection existed for %ld seconds", time(0) - ptr->starttime);
}

static int
virStorageBackendDFSCreateVol(virStoragePoolObj *pool,
                              virStorageVolDef *vol)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    dfs_t *dfs;
    dfs_obj_t *obj;
    mode_t mode = S_IFREG | 0644;

    if (dfs_mount(def->source.name, def->source.path, O_RDWR, &dfs) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("failed to mount DFS"));
        return -1;
    }

    if (dfs_open(dfs, NULL, vol->name, mode, O_CREAT | O_RDWR, 0, 0, NULL, &obj) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("failed to create DFS volume"));
        dfs_umount(dfs);
        return -1;
    }

    dfs_release(obj);
    dfs_umount(dfs);

    vol->type = VIR_STORAGE_VOL_NETWORK;
    vol->target.format = VIR_STORAGE_FILE_RAW;

    return 0;
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
    dfs_t *dfs;
    dfs_obj_t *obj;
    daos_size_t size;
    int ret = -1;

    if (!(ptr = g_new0(virStorageBackendDFSState, 1)))
        return -1;

    if (virStorageBackendDFSOpenConn(ptr, def) < 0)
        goto cleanup;

    if (dfs_mount(def->source.name, def->source.path, O_RDWR, &dfs) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("failed to mount DFS"));
        goto cleanup;
    }

    if (dfs_lookup(dfs, NULL, def->source.path, O_RDWR, &obj, NULL, NULL) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("failed to lookup DFS pool"));
        dfs_umount(dfs);
        goto cleanup;
    }

    if (dfs_get_size(dfs, obj, &size) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("failed to get DFS pool size"));
        dfs_release(obj);
        dfs_umount(dfs);
        goto cleanup;
    }

    def->capacity = size;
    def->allocation = size;
    def->available = size - def->allocation;

    dfs_release(obj);
    dfs_umount(dfs);

    ret = 0;

cleanup:
    virStorageBackendDFSCloseConn(ptr);
    VIR_FREE(ptr);
    return ret;
}

int
virStorageBackendDFSRegister(void)
{
    if (virStorageBackendRegister(&virStorageBackendDFS) < 0)
        return -1;

    return virStorageBackendNamespaceInit(VIR_STORAGE_POOL_DFS,
                                          &virStoragePoolDFSXMLNamespace);
}
