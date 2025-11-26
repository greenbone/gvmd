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
 * @brief Manager Manage library: openvasd SQL backend headers.
 */

#if OPENVASD
#ifndef MANAGE_NVTS_OPENVASD_H
#define MANAGE_NVTS_OPENVASD_H

#include "manage_sql_nvts_common.h"

int
manage_update_nvt_cache_openvasd ();

int
nvts_feed_info_internal_from_openvasd (const gchar *scanner_uuid,
                                       gchar **vts_version);

int
update_or_rebuild_nvts_openvasd (int update);

int
nvts_feed_version_status_internal_openvasd (gchar **db_feed_version_out,
                                            gchar **scanner_feed_version_out);

int
update_scanner_preferences_openvasd (scanner_t scanner);

#endif //MANAGE_NVTS_OPENVASD_H
#endif
