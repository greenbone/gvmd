/* Copyright (C) 2010-2025 Greenbone AG
*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Manager Manage library: OSP SQL backend headers.
 */

#ifndef MANAGE_NVTS_OSP_H
#define MANAGE_NVTS_OSP_H

#include "manage_sql_nvts_common.h"

const char *
get_osp_vt_update_socket ();

void
set_osp_vt_update_socket (const char *new_socket);

int
check_osp_vt_update_socket ();

int
update_or_rebuild_nvts_osp (int update);

char *
osp_scanner_feed_version (const gchar *update_socket);

int
update_nvt_cache_osp (const gchar *update_socket, gchar *db_feed_version,
                      gchar *scanner_feed_version, int rebuild);
int
manage_update_nvt_cache_osp (const gchar *update_socket);

int
nvts_feed_version_status_internal_osp (const gchar *update_socket,
                                   gchar **db_feed_version_out,
                                   gchar **scanner_feed_version_out);

int
update_scanner_preferences_osp (const gchar *update_socket);

#endif //MANAGE_NVTS_OSP_H
