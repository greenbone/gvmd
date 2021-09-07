/* Copyright (C) 2020 Greenbone Networks GmbH
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

#ifndef _GVMD_MANAGE_REPORT_FORMATS_H
#define _GVMD_MANAGE_REPORT_FORMATS_H

#include "manage.h"

#include <glib.h>

gboolean
find_report_format_with_permission (const char*, report_format_t*,
                                    const char *);

/**
 * @brief Struct for defining a report format param.
 */
typedef struct
{
  gchar *fallback;  ///< Fallback value.
  gchar *name;      ///< Name.
  gchar *type;      ///< Type (boolean, string, integer, ...).
  gchar *type_max;  ///< Maximum value for integer type.
  gchar *type_min;  ///< Minimum value for integer type.
  gchar *value;     ///< Value of param.
} create_report_format_param_t;

int
create_report_format (const char *, const char *, const char *, const char *,
                      const char *, const char *, array_t *, array_t *,
                      array_t *, const char *, report_format_t *);

int
copy_report_format (const char *, const char *, report_format_t*);

int
modify_report_format (const char *, const char *, const char *, const char *,
                      const char *, const char *);

int
delete_report_format (const char *, int);

int
verify_report_format (const char *);

char *
report_format_uuid (report_format_t);

char *
report_format_owner_uuid (report_format_t);

char *
report_format_name (report_format_t);

char *
report_format_content_type (report_format_t);

char *
report_format_extension (report_format_t);

int
report_format_global (report_format_t);

int
trash_report_format_global (report_format_t);

int
report_format_predefined (report_format_t);

int
trash_report_format_predefined (report_format_t);

int
report_format_active (report_format_t);

int
report_format_trust (report_format_t);

int
report_format_in_use (report_format_t);

int
trash_report_format_in_use (report_format_t);

int
trash_report_format_writable (report_format_t);

int
report_format_writable (report_format_t);

int
report_format_count (const get_data_t *);

int
init_report_format_iterator (iterator_t*, const get_data_t *);

const char*
report_format_iterator_extension (iterator_t *);

const char*
report_format_iterator_content_type (iterator_t *);

const char*
report_format_iterator_description (iterator_t *);

int
report_format_iterator_active (iterator_t *);

const char*
report_format_iterator_signature (iterator_t *);

const char*
report_format_iterator_trust (iterator_t *);

const char*
report_format_iterator_summary (iterator_t *);

time_t
report_format_iterator_trust_time (iterator_t *);

void
init_report_format_alert_iterator (iterator_t*, report_format_t);

const char*
report_format_alert_iterator_name (iterator_t*);

const char*
report_format_alert_iterator_uuid (iterator_t*);

int
report_format_alert_iterator_readable (iterator_t*);

/**
 * @brief A report format file iterator.
 */
typedef struct
{
  GPtrArray *start;    ///< Array of files.
  gpointer *current;   ///< Current file.
  gchar *dir_name;     ///< Dir holding files.
} file_iterator_t;

int
init_report_format_file_iterator (file_iterator_t*, report_format_t);

void
cleanup_file_iterator (file_iterator_t*);

gboolean
next_file (file_iterator_t*);

const char*
file_iterator_name (file_iterator_t*);

gchar*
file_iterator_content_64 (file_iterator_t*);

/**
 * @brief Report format param types.
 *
 * These numbers are used in the database, so if the number associated with
 * any symbol changes then a migrator must be added to update existing data.
 */
typedef enum
{
  REPORT_FORMAT_PARAM_TYPE_BOOLEAN = 0,
  REPORT_FORMAT_PARAM_TYPE_INTEGER = 1,
  REPORT_FORMAT_PARAM_TYPE_SELECTION = 2,
  REPORT_FORMAT_PARAM_TYPE_STRING = 3,
  REPORT_FORMAT_PARAM_TYPE_TEXT = 4,
  REPORT_FORMAT_PARAM_TYPE_REPORT_FORMAT_LIST = 5,
  REPORT_FORMAT_PARAM_TYPE_ERROR = 100
} report_format_param_type_t;

const char *
report_format_param_type_name (report_format_param_type_t);

report_format_param_type_t
report_format_param_type_from_name (const char *);

void
init_report_format_param_iterator (iterator_t*, report_format_t, int,
                                   int, const char*);

report_format_param_t
report_format_param_iterator_param (iterator_t*);

const char*
report_format_param_iterator_name (iterator_t *);

const char*
report_format_param_iterator_value (iterator_t *);

const char*
report_format_param_iterator_type_name (iterator_t *);

report_format_param_type_t
report_format_param_iterator_type (iterator_t *);

long long int
report_format_param_iterator_type_min (iterator_t *);

long long int
report_format_param_iterator_type_max (iterator_t *);

const char*
report_format_param_iterator_fallback (iterator_t *);

void
init_param_option_iterator (iterator_t*, report_format_param_t, int,
                            const char *);

const char*
param_option_iterator_value (iterator_t *);

gboolean
report_formats_feed_dir_exists ();

void
manage_sync_report_formats ();

int
manage_rebuild_report_formats ();

gboolean
should_sync_report_formats ();

#endif /* not _GVMD_MANAGE_REPORT_FORMATS_H */
