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
 * @file manage_sql_nvts_common.h
 * @brief Manager Manage library: Common SQL backend headers.
 */

#ifndef MANAGE_SQL_NVTS_COMMON_H
#define MANAGE_SQL_NVTS_COMMON_H

#include <glib.h>
#include <gvm/base/nvti.h>

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

const char *
get_osp_vt_update_socket ();

void
set_osp_vt_update_socket (const char *new_socket);

int
check_osp_vt_update_socket ();

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

#endif //MANAGE_SQL_NVTS_COMMON_H
