/* Copyright (C) 2012-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/*
 * @file
 * @brief Headers for Greenbone Vulnerability Manager: the SQL library.
 */

#ifndef _GVMD_SQL_H
#define _GVMD_SQL_H

#include "iterator.h"

#include <glib.h>

/**
 * @brief Data structure for info used to connect to the database
 */
typedef struct
{
  gchar *name;              ///< The database name
  gchar *host;              ///< The database host or socket directory
  gchar *port;              ///< The database port or socket file extension
  gchar *user;              ///< The database user name
  time_t semaphore_timeout; ///< Semaphore timeout for database connections
} db_conn_info_t;

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
sql_ascii_escape_and_quote (const char *, const char *);

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

int
sql_table_lock_wait (const char *, int);

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

int
sql_copy_write_str (const char *, int);

int
sql_copy_end ();

gchar *
sql_copy_escape (const char *);

#endif /* not _GVMD_SQL_H */
