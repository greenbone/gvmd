/* Copyright (C) 2020 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _GVMD_MANAGE_SQL_REPORT_FORMATS_H
#define _GVMD_MANAGE_SQL_REPORT_FORMATS_H

#include "manage.h"
#include "manage_sql.h"

#include <glib.h>

gchar *
report_format_trash_dir (const gchar *);

int
check_report_format (const gchar *);

gboolean
lookup_report_format (const char*, report_format_t*);

const char**
report_format_filter_columns ();

column_t*
report_format_select_columns ();

int
restore_report_format (const char *);

#endif /* not _GVMD_MANAGE_SQL_REPORT_FORMATS_H */
