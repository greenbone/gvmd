/* Copyright (C) 2010-2025 Greenbone AG
*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Manager Manage library: Common SQL backend headers.
 */

#ifndef _GVMD_MANAGE_NVTS_COMMON_H
#define _GVMD_MANAGE_NVTS_COMMON_H

/**
 * @brief Default for vt_ref_insert_size.
 */
#define VT_REF_INSERT_SIZE_DEFAULT 50000

/**
 * @brief Default for vt_sev_insert_size.
 *
 * There are about 80k vt_severities.
 */
#define VT_SEV_INSERT_SIZE_DEFAULT 100000

#endif // not _GVMD_MANAGE_NVTS_COMMON_H
