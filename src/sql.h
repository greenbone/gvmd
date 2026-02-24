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

/**
 * @brief Enum for defining the type of SQL prepared statement parameters.
 */
typedef enum
{
  SQL_PARAM_TYPE_NULL = 0, ///< null value
  SQL_PARAM_TYPE_DOUBLE,   ///< double precision floating point number
  SQL_PARAM_TYPE_INT,      ///< integer
  SQL_PARAM_TYPE_STRING,   ///< string
  SQL_PARAM_TYPE_RESOURCE, ///< resource row id (resource_t)
} sql_param_type_t;

/**
 * @brief Union type for SQL prepared statement parameters values.
 */
typedef union
{
  const double double_value;       ///< double precision floating point value
  const int int_value;             ///< integer value
  const char *str_value;           ///< string value
  const resource_t resource_value; ///< resource row id (resource_t) value
} sql_param_value_t;

/**
 * @brief Struct type for defining SQL prepared statement parameters.
 *
 * This struct type encapsulates the data type and value of a parameter
 * to be bound to an SQL prepared statement.
 *
 * SQL template strings using the dollar sign + number syntax (e.g. "$1"),
 * do not contain any type information unlike printf-style template / format
 * string, where it is contained in the placeholders (e.g. "%s" for strings).
 *
 * Therefore this type is used to pass both the value and data type of
 * paramaters to generic functions using the SQL prepared statement syntax.
 * Most of them will expect pointers to sql_param_t structs as variadic
 * arguments list with a NULL sentinel at the end.
 * This sentinel is different from null values, which are represented by
 * structs with the type set to SQL_PARAM_TYPE_NULL.
 *
 * To keep the code shorter and to ensure consistency between type and value,
 * sql_param_t* literals can be generated with macros using the pattern
 * "SQL_{TYPE}_PARAM (value)", e.g." SQL_INT_PARAM (123)".
 */
typedef struct
{
  sql_param_type_t type;   ///< The data type of the parameter
  sql_param_value_t value; ///< The value of the parameter
} sql_param_t;

/**
 * @brief Macro for a sql_param_t* literal representing a null value.
 */
#define SQL_NULL_PARAM &((const sql_param_t){.type = SQL_PARAM_TYPE_NULL})

/**
 * @brief Macro for a sql_param_t* literal representing a double value.
 */
#define SQL_DOUBLE_PARAM(p_value)                      \
  &((const sql_param_t){.type = SQL_PARAM_TYPE_DOUBLE, \
                        .value.double_value = p_value})

/**
 * @brief Macro for a sql_param_t* literal representing an int value.
 */
#define SQL_INT_PARAM(p_value) \
  &((const sql_param_t){.type = SQL_PARAM_TYPE_INT, .value.int_value = p_value})

/**
 * @brief Macro for a sql_param_t* literal representing a string value.
 */
#define SQL_STR_PARAM(p_value)                         \
  &((const sql_param_t){.type = SQL_PARAM_TYPE_STRING, \
                        .value.str_value = p_value})

/**
 * @brief Macro for a sql_param_t* literal representing a resource_t value.
 */
#define SQL_RESOURCE_PARAM(p_value)                      \
  &((const sql_param_t){.type = SQL_PARAM_TYPE_RESOURCE, \
                        .value.resource_value = p_value})

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
sql (const char *sql, ...);

void
sql_ps (const char *sql, ...);

int
sql_error (const char *sql, ...);

int
sql_error_ps (const char *sql, ...);

int
sql_giveup (const char *sql, ...);

int
sql_giveup_ps (const char *sql, ...);

double
sql_double (const char *sql, ...);

double
sql_double_ps (const char *sql, ...);

int
sql_int (const char *, ...);

int
sql_int_ps (const char *, ...);

char *
sql_string (const char *, ...);

char *
sql_string_ps (const char *, ...);

int
sql_int64 (long long int *ret, const char *, ...);

int
sql_int64_ps (long long int *ret, const char *, ...);

long long int
sql_int64_0 (const char *sql, ...);

long long int
sql_int64_0_ps (const char *sql, ...);

int
sql_cancel_internal ();

int
sql_table_exists (const gchar *, const gchar *);

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

int
sql_table_shared_lock_wait (const char *, int);

/* Iterators. */

/* These functions are for "internal" use.  They may only be accessed by code
 * that is allowed to run SQL statements directly. */

void
init_iterator (iterator_t *, const char *, ...);

void
init_ps_iterator (iterator_t *, const char *, ...) __attribute__ ((sentinel));

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
