/* Copyright (C) 2026 Greenbone AG
*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Manager Manage library: OSP NVT headers.
 */

#ifndef _GVMD_MANAGE_NVTS_OSP_H
#define _GVMD_MANAGE_NVTS_OSP_H

#include <glib.h>

const char *
get_osp_vt_update_socket ();

void
set_osp_vt_update_socket (const char *new_socket);

int
check_osp_vt_update_socket ();

int
manage_update_nvt_cache_osp (const gchar *);

#endif // not _GVMD_MANAGE_NVTS_OSP_H
