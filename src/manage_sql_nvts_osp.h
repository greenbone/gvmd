/* Copyright (C) 2010-2025 Greenbone AG
*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Manager Manage library: OSP NVT SQL backend headers.
 */

#ifndef _GVMD_MANAGE_SQL_NVTS_OSP_H
#define _GVMD_MANAGE_SQL_NVTS_OSP_H

#include "manage_nvts_osp.h"
#include "manage_sql_nvts_common.h"

int
update_or_rebuild_nvts_osp (int update);

char *
osp_scanner_feed_version (const gchar *update_socket);

int
update_nvt_cache_osp (const gchar *update_socket, gchar *db_feed_version,
                      gchar *scanner_feed_version, int rebuild);

int
nvts_feed_version_status_internal_osp (const gchar *update_socket,
                                   gchar **db_feed_version_out,
                                   gchar **scanner_feed_version_out);

int
update_scanner_preferences_osp (const gchar *update_socket);

#endif // not _GVMD_MANAGE_SQL_NVTS_OSP_H
