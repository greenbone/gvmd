/* Copyright (C) 2024 Greenbone AG
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
 * @file manage_report_configs.h
 * @brief GVM management layer: Report configs.
 *
 * Non-SQL report config code for the GVM management layer.
 */

#ifndef _GVMD_MANAGE_REPORT_CONFIGS_H
#define _GVMD_MANAGE_REPORT_CONFIGS_H

#include "manage.h"
#include "manage_report_formats.h"

#include <glib.h>


gboolean
find_report_config_with_permission (const char*, report_config_t*,
                                    const char *);

/**
 * @brief Struct for defining a report format param.
 */
typedef struct
{
  gchar *name;             ///< Name.
  gchar *value;            ///< Value of param.
  int   use_default_value; ///< Whether to use default value
} report_config_param_data_t;

void
report_config_param_data_free (report_config_param_data_t*);

int
create_report_config (const char *, const char *, const char *, array_t *,
                      report_config_t *, gchar **);

int
copy_report_config (const char *, const char *, report_config_t*);

int
modify_report_config (const char *, const char *, const char *, array_t *,
                      gchar **);

int
delete_report_config (const char *, int);

char *
report_config_uuid (report_config_t);

report_format_t
report_config_report_format (report_config_t);

int
report_config_in_use (report_config_t);

int
trash_report_config_in_use (report_config_t);

int
trash_report_config_writable (report_config_t);

int
report_config_writable (report_config_t);

int
report_config_count (const get_data_t *);


int
init_report_config_iterator (iterator_t*, const get_data_t *);

const char*
report_config_iterator_report_format_id (iterator_t *);

int
report_config_iterator_report_format_readable (iterator_t* iterator);

const char*
report_config_iterator_report_format_name (iterator_t *);

report_format_t
report_config_iterator_report_format (iterator_t *);


void
init_report_config_param_iterator(iterator_t*, report_config_t, int);

report_config_param_t
report_config_param_iterator_rowid (iterator_t *);

const char*
report_config_param_iterator_name (iterator_t *);

report_format_param_type_t
report_config_param_iterator_type (iterator_t *);

const char*
report_config_param_iterator_type_name (iterator_t *);

const char*
report_config_param_iterator_value (iterator_t *);

const char*
report_config_param_iterator_fallback_value (iterator_t *);

long long int
report_config_param_iterator_type_min (iterator_t *);

long long int
report_config_param_iterator_type_max (iterator_t *);

report_format_param_t
report_config_param_iterator_format_param (iterator_t *);

int
report_config_param_iterator_using_default (iterator_t *);

#endif /* not _GVMD_MANAGE_REPORT_CONFIGS_H */
