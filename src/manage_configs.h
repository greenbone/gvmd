/* Copyright (C) 2019-2021 Greenbone Networks GmbH
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

#ifndef _GVMD_MANAGE_CONFIGS_H
#define _GVMD_MANAGE_CONFIGS_H

#include "iterator.h"
#include "manage_get.h"
#include "manage_preferences.h"

typedef resource_t config_t;

preference_t *
get_nvt_preference_by_id (const char *,
                          const char *,
                          const char *,
                          const char *,
                          const char *);

/**
 * @brief An NVT selector.
 */
typedef struct
{
  char *name;           ///< Name of NVT selector.
  char *type;           ///< Name of NVT selector.
  int include;          ///< Whether family/NVT is included or excluded.
  char *family_or_nvt;  ///< Family or NVT that this selector selects.
} nvt_selector_t;

int
create_config (const char*, const char*, int, const char*, int, const array_t*,
               const array_t*, const char*, const char*, config_t*, char**);

int
create_config_from_scanner (const char*, const char *, const char *,
                            const char *, char **);

int
copy_config (const char*, const char*, const char *, const char *, config_t*);

int
delete_config (const char*, int);

int
sync_config (const char *);

gboolean
find_config_with_permission (const char*, config_t*, const char *);

char *
config_uuid (config_t);

int
config_type (config_t);

char *
config_nvt_timeout (config_t, const char *);

int
config_predefined_uuid (const gchar *);

void
init_user_config_iterator (iterator_t*, config_t, int, int, const char*);

int
init_config_iterator (iterator_t*, const get_data_t*);

const char*
config_iterator_nvt_selector (iterator_t*);

int
config_iterator_nvt_count (iterator_t*);

int
config_iterator_family_count (iterator_t*);

int
config_iterator_nvts_growing (iterator_t*);

int
config_iterator_type (iterator_t*);

int
config_iterator_families_growing (iterator_t*);

int
config_iterator_scanner_trash (iterator_t*);

const char*
config_iterator_usage_type (iterator_t*);

int
config_iterator_predefined (iterator_t*);

char*
config_nvt_selector (config_t);

int
config_in_use (config_t);

int
config_writable (config_t);

int
config_count (const get_data_t *);

int
trash_config_in_use (config_t);

int
trash_config_writable (config_t);

int
trash_config_readable_uuid (const gchar *);

int
config_families_growing (config_t);

int
config_nvts_growing (config_t);

int
manage_modify_config_start (const char *, config_t *);

void
manage_modify_config_cancel ();

void
manage_modify_config_commit ();

int
manage_set_config_preference (config_t, const char*, const char*, const char*);

void
init_config_preference_iterator (iterator_t *, config_t);

const char*
config_preference_iterator_name (iterator_t *);

const char*
config_preference_iterator_value (iterator_t *);

const char*
config_preference_iterator_type (iterator_t *);

const char*
config_preference_iterator_default (iterator_t *);

const char*
config_preference_iterator_hr_name (iterator_t *);

int
manage_set_config (config_t, const char*, const char *, const char *);

int
manage_set_config_nvts (config_t, const char*, GPtrArray*);

int
manage_set_config_families (config_t, GPtrArray*, GPtrArray*, GPtrArray*, int,
                            gchar **);

void
init_config_timeout_iterator (iterator_t*, config_t);

const char*
config_timeout_iterator_oid (iterator_t *);

const char*
config_timeout_iterator_nvt_name (iterator_t *);

const char*
config_timeout_iterator_value (iterator_t *);

void
update_config_preference (const char *, const char *, const char *,
                          const char *, gboolean);

gboolean
configs_feed_dir_exists ();

void
manage_sync_configs ();

int
manage_rebuild_configs ();

gboolean
should_sync_configs ();

#endif /* not _GVMD_MANAGE_CONFIGS_H */
