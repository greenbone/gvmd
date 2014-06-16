/* OpenVAS Manager
 * $Id$
 * Description: Headers for OpenVAS Manager: the SQL library.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2012 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * or, at your option, any later version as published by the Free
 * Software Foundation
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

#ifndef OPENVAS_MANAGER_SQL_H
#define OPENVAS_MANAGER_SQL_H

#include "manage.h"  /* For iterator_t. */

#include <sqlite3.h>
#include <glib.h>

extern sqlite3 *
task_db;

gchar *
sql_nquote (const char *, size_t);

gchar *
sql_quote (const char *);

gchar *
sql_insert (const char *);

void
sql (char * sql, ...);

int
sql_error (char* sql, ...);

int
sql_giveup (char * sql, ...);

void
sql_quiet (char * sql, ...);

int
sql_x (unsigned int, unsigned int, char *, va_list, sqlite3_stmt **);

double
sql_double (unsigned int, unsigned int, char* sql, ...);

int
sql_int (unsigned int, unsigned int, char *, ...);

char *
sql_string (unsigned int, unsigned int, char *, ...);

char *
sql_string_quiet (unsigned int, unsigned int, char *, ...);

int
sql_int64 (long long int * ret, unsigned int, unsigned int, char *, ...);

void
sql_make_uuid (sqlite3_context *, int argc, sqlite3_value **);

void
sql_hosts_contains (sqlite3_context *, int argc, sqlite3_value **);

void
sql_clean_hosts (sqlite3_context *, int argc, sqlite3_value **);

void
sql_uniquify (sqlite3_context *, int argc, sqlite3_value **);

void
sql_iso_time (sqlite3_context *, int argc, sqlite3_value **);

void
sql_parse_time (sqlite3_context *, int argc, sqlite3_value **);

void
sql_next_time (sqlite3_context *, int, sqlite3_value **);

void
sql_now (sqlite3_context *, int argc, sqlite3_value **);

void
sql_tag (sqlite3_context *, int, sqlite3_value**);

void
sql_max_hosts (sqlite3_context *, int, sqlite3_value **);

void
sql_rename_column (const char *, const char *, const char *, const char *);

void
sql_common_cve (sqlite3_context *, int argc, sqlite3_value **);

void
sql_current_offset (sqlite3_context *, int, sqlite3_value **);

void
sql_report_progress (sqlite3_context *, int, sqlite3_value**);

void
sql_report_severity (sqlite3_context *, int, sqlite3_value**);

void
sql_report_severity_count (sqlite3_context *, int, sqlite3_value**);

void
sql_task_severity (sqlite3_context *, int argc, sqlite3_value **);

void
sql_severity_matches_type (sqlite3_context *, int argc, sqlite3_value **);

void
sql_severity_matches_ov (sqlite3_context *, int argc, sqlite3_value **);

void
sql_severity_to_level (sqlite3_context *, int argc, sqlite3_value **);

void
sql_severity_to_type (sqlite3_context *, int argc, sqlite3_value **);

void
sql_task_trend (sqlite3_context *, int argc, sqlite3_value **);

void
sql_threat_level (sqlite3_context *, int argc, sqlite3_value **);

void
sql_regexp (sqlite3_context *, int, sqlite3_value**);

void
sql_run_status_name (sqlite3_context *, int, sqlite3_value **);

void
sql_resource_name (sqlite3_context *, int, sqlite3_value **);

void
sql_resource_exists (sqlite3_context *, int, sqlite3_value **);

void
sql_severity_in_level (sqlite3_context *, int, sqlite3_value**);

void
sql_user_can_everything (sqlite3_context *, int, sqlite3_value **);


/* Iterators. */

sqlite3_stmt *
sql_prepare (const char* sql, ...);

void
init_prepared_iterator (iterator_t*, sqlite3_stmt*);

void
init_iterator (iterator_t*, const char*, ...);

long long int
iterator_int64 (iterator_t*, int);

const char*
iterator_string (iterator_t*, int);

const char*
iterator_column_name (iterator_t*, int);

int
iterator_column_count (iterator_t*);

void
cleanup_iterator (iterator_t*);

gboolean
next (iterator_t*);

#endif /* not OPENVAS_MANAGER_SQL_H */
