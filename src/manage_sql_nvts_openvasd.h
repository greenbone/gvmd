/* Copyright (C) 2010-2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Manager Manage library: openvasd NVT SQL backend headers.
 */

#ifndef _GVMD_SQL_MANAGE_NVTS_OPENVASD_H
#define _GVMD_SQL_MANAGE_NVTS_OPENVASD_H

#include "manage_nvts_openvasd.h"
#include "manage_sql_nvts_common.h"
#include "manage_resources_types.h"

int
update_or_rebuild_nvts_openvasd (int update);

int
nvts_feed_version_status_internal_openvasd (gchar **db_feed_version_out,
                                            gchar **scanner_feed_version_out);

int
update_scanner_preferences_openvasd (scanner_t scanner);

#endif // not _GVMD_MANAGE_SQL_NVTS_OPENVASD_H
