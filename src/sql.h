/* Copyright (C) 2012-2022 Greenbone AG
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

/*
 * @file sql.h
 * @brief Headers for Greenbone Vulnerability Manager: the SQL library.
 */

#ifndef _GVMD_SQL_H
#define _GVMD_SQL_H

#include "iterator.h"
#include "manage.h"

#include <glib.h>

/* Helpers. */

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

void
sql_recursive_triggers_off ();

int
sql_is_open ();

int
sql_open (const db_conn_info_t *);

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
sql_ascii_escape_and_quote (const char *);

gchar *
sql_insert (const char *);

void
sql (char *sql, ...);

int
sql_error (char *sql, ...);

int
sql_giveup (char *sql, ...);

double
sql_double (char *sql, ...);

int
sql_int (char *, ...);

char *
sql_string (char *, ...);

int
sql_int64 (long long int *ret, char *, ...);

long long int
sql_int64_0 (char *sql, ...);

void
sql_rename_column (const char *, const char *, const char *, const char *);

int
sql_cancel_internal ();

/* Transactions. */

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
init_iterator (iterator_t *, const char *, ...);

void
iterator_rewind (iterator_t *iterator);

double
iterator_double (iterator_t *, int);

int
iterator_int (iterator_t *, int);

long long int
iterator_int64 (iterator_t *, int);

int
iterator_null (iterator_t *, int);

const char *
iterator_string (iterator_t *, int);

gchar **
iterator_array (iterator_t *, int);

const char *
iterator_column_name (iterator_t *, int);

int
iterator_column_count (iterator_t *);

#endif /* not _GVMD_SQL_H */
