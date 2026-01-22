/* Copyright (C) 2010-2025 Greenbone AG
*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Manager Manage library: Common SQL backend headers.
 */

#ifndef _GVMD_MANAGE_SQL_NVTS_COMMON_H
#define _GVMD_MANAGE_SQL_NVTS_COMMON_H

#include "manage_nvts_common.h"
#include <glib.h>
#include <gvm/base/nvti.h>

/**
 * @brief SQL batch.
 */
typedef struct
{
  GString *sql;  ///< SQL buffer.
  int max;       ///< Max number of inserts.
  int size;      ///< Number of inserts.
} batch_t;

batch_t *
batch_start (int max);

int
batch_check (batch_t *b);

void
batch_end (batch_t *b);

void
insert_nvt (const nvti_t *nvti, int rebuild, batch_t *vt_refs_batch,
            batch_t *vt_sevs_batch);
void
insert_nvt_preferences_list (GList *nvt_preferences_list, int rebuild);

void
set_nvts_check_time (int count_new, int count_modified);

void
check_old_preference_names (const gchar *table);

void
check_preference_names (int trash, time_t modification_time);

void
prepare_nvts_insert (int rebuild);

void
finalize_nvts_insert (int count_new_vts, int count_modified_vts,
                               const gchar *scanner_feed_version, int rebuild);

int
update_preferences_from_nvti (nvti_t *nvti, GList **preferences);

void
update_nvt_end (const time_t old_nvts_last_modified);

#endif // not _GVMD_MANAGE_SQL_NVTS_COMMON_H
