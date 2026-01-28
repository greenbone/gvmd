/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/*
 * @file
 * @brief Manager Manage library: SecInfo headers.
 */

#ifndef _GVMD_MANAGE_SECINFO_H
#define _GVMD_MANAGE_SECINFO_H

/**
 * @brief Default for affected_products_query_size.
 */
#define AFFECTED_PRODUCTS_QUERY_SIZE_DEFAULT 20000

/**
 * @brief Default for secinfo_copy.
 */
#define SECINFO_FAST_INIT_DEFAULT 1

/**
 * @brief Default for secinfo_commit_size.
 */
#define SECINFO_COMMIT_SIZE_DEFAULT 0

int
manage_rebuild_scap (GSList *, const db_conn_info_t *);

void
set_affected_products_query_size (int);

void
set_secinfo_commit_size (int);

void
set_secinfo_update_strategy (int);

void
set_secinfo_fast_init (int);

#endif /* not _GVMD_MANAGE_SECINFO_H */
