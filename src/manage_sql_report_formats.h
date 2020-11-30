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

#ifndef _GVMD_MANAGE_SQL_REPORT_FORMATS_H
#define _GVMD_MANAGE_SQL_REPORT_FORMATS_H

#include "manage.h"
#include "manage_sql.h"

#include <glib.h>

gboolean
lookup_report_format (const char*, report_format_t*);

gboolean
find_report_format_no_acl (const char *, report_format_t *);

gboolean
find_trash_report_format_no_acl (const char *, report_format_t *);

int
create_report_format_no_acl (const char *, const char *, const char *,
                             const char *, const char *, const char *,
                             array_t *, array_t *, array_t *, const char *,
                             int, report_format_t *);

const char**
report_format_filter_columns ();

column_t*
report_format_select_columns ();

int
restore_report_format (const char *);

gchar *
apply_report_format (gchar *, gchar *, gchar *, gchar *,
                     GList **);

gboolean
delete_report_formats_user (user_t, iterator_t *);

void
delete_report_format_dirs_user (const gchar *, iterator_t *);

int
empty_trashcan_report_formats ();

gboolean
inherit_report_formats (user_t, user_t, iterator_t *);

void
inherit_report_format_dir (const gchar *, const gchar *, user_t);

void
update_report_format (report_format_t, const gchar *, const gchar *,
                      const gchar *, const gchar *, const gchar *,
                      const gchar *, const gchar *, array_t *, array_t *,
                      array_t *);

int
report_format_updated_in_feed (report_format_t, const gchar *);

int
migrate_predefined_report_formats ();

int
check_db_report_formats ();

int
check_db_report_formats_trash ();

#endif /* not _GVMD_MANAGE_SQL_REPORT_FORMATS_H */
