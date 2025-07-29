/* Copyright (C) 2010-2025 Greenbone AG
*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
