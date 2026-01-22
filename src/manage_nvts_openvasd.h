/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Manager Manage library: openvasd NVT headers.
 */

#ifndef _GVMD_MANAGE_NVTS_OPENVASD_H
#define _GVMD_MANAGE_NVTS_OPENVASD_H

int
manage_update_nvt_cache_openvasd ();

int
nvts_feed_info_internal_from_openvasd (const gchar *, gchar **);

#endif // not _GVMD_MANAGE_NVTS_OPENVASD_H
