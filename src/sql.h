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

#ifndef OPENVAS_MANAGER_SQL_H
#define OPENVAS_MANAGER_SQL_H

#include "iterator.h"

#include <glib.h>


/* Helpers. */

int
sql_is_sqlite3 ();

const char *
sql_schema ();

const char *
sql_greatest ();

const char *
sql_select_limit (int);

const char *
sql_regexp_op ();

const char *
sql_ilike_op ();

const char *
sql_database ();

const char *
sql_default_database ();

int
sql_is_open ();

int
sql_open (const char *);

void
sql_close ();

void
sql_close_fork ();

int
sql_changes ();

resource_t
sql_last_insert_id ();

gchar *
sql_nquote (const char *, size_t);

gchar *
sql_quote (const char *);

gchar *
sql_insert (const char *);

void
sql (char * sql, ...);

void
sqli (resource_t *, char *, ...);

int
sql_error (char* sql, ...);

int
sql_giveup (char * sql, ...);

void
sql_quiet (char * sql, ...);

double
sql_double (char* sql, ...);

int
sql_int (char *, ...);

char *
sql_string (char *, ...);

int
sql_int64 (long long int * ret, char *, ...);

void
sql_rename_column (const char *, const char *, const char *, const char *);


/* Transactions. */

void
sql_begin_exclusive ();

int
sql_begin_exclusive_giveup ();

void
sql_begin_immediate ();

int
sql_begin_immediate_giveup ();

void
sql_commit ();

void
sql_rollback ();


/* Iterators. */

/* These functions are for "internal" use.  They may only be accessed by code
 * that is allowed to run SQL statements directly. */

void
init_prepared_iterator (iterator_t*, sql_stmt_t*);

void
init_iterator (iterator_t*, const char*, ...);

double
iterator_double (iterator_t*, int);

int
iterator_int (iterator_t*, int);

long long int
iterator_int64 (iterator_t*, int);

int
iterator_null (iterator_t*, int);

const char*
iterator_string (iterator_t*, int);

const char*
iterator_column_name (iterator_t*, int);

int
iterator_column_count (iterator_t*);


/* Prepared statements. */

sql_stmt_t *
sql_prepare (const char* sql, ...);

int
sql_bind_blob (sql_stmt_t *, int, const void *, int);

int
sql_bind_int64 (sql_stmt_t *, int, long long int *);

int
sql_bind_text (sql_stmt_t *, int, const gchar *, gsize);

int
sql_bind_double (sql_stmt_t *, int, double *);

int
sql_exec (sql_stmt_t *);

void
sql_finalize (sql_stmt_t *);

int
sql_reset (sql_stmt_t *);

double
sql_column_double (sql_stmt_t *, int);

const char *
sql_column_text (sql_stmt_t *, int);

int
sql_column_int (sql_stmt_t *, int);

long long int
sql_column_int64 (sql_stmt_t *, int);

int
sql_cancel_internal ();

#endif /* not OPENVAS_MANAGER_SQL_H */
