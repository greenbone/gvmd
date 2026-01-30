/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Manager Manage library: NVT headers.
 */

#ifndef _GVMD_MANAGE_NVTS_H
#define _GVMD_MANAGE_NVTS_H

#include "manage_nvts_common.h"
#include "manage_nvts_openvasd.h"
#include "manage_nvts_osp.h"

void
set_skip_update_nvti_cache (gboolean);

void
set_vt_ref_insert_size (int);

void
set_vt_sev_insert_size (int);

int
update_or_rebuild_nvts (int);

int
nvts_feed_version_status_from_scanner ();

int
nvts_feed_version_status_from_timestamp ();

int
manage_update_nvts_from_feed (gboolean);

void
manage_discovery_nvts ();

void
nvts_discovery_oid_cache_reload ();

gboolean
nvts_oids_all_discovery_cached (GSList *oids);

pid_t
manage_sync_nvts (int (*) (pid_t*));

#endif /* not _GVMD_MANAGE_NVTS_H */
