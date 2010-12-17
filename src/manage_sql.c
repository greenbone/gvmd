/* OpenVAS Manager
 * $Id$
 * Description: Manager Manage library: SQL backend.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2009,2010 Greenbone Networks GmbH
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

/**
 * @file  manage_sql.c
 * @brief The OpenVAS Manager management library (SQLite implementation).
 *
 * This file defines the SQLite specific portions of the OpenVAS manager
 * management library.
 */

#include "manage_sql.h"
#include "lsc_user.h"
#include "tracef.h"

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openvas/base/openvas_string.h>
#include <openvas/misc/openvas_auth.h>
#include <openvas/misc/openvas_logging.h>
#include <openvas/misc/openvas_uuid.h>
#include <openvas/misc/resource_request.h>

#ifdef S_SPLINT_S
#include "splint.h"
#endif


/* Internal types and preprocessor definitions. */

/**
 * @brief Database ROWID of 'Full and fast' config.
 */
#define CONFIG_ID_FULL_AND_FAST 1

/**
 * @brief Database ROWID of 'Full and fast ultimate' config.
 */
#define CONFIG_ID_FULL_AND_FAST_ULTIMATE 2

/**
 * @brief Database ROWID of 'Full and very deep' config.
 */
#define CONFIG_ID_FULL_AND_VERY_DEEP 3

/**
 * @brief Database ROWID of 'Full and very deep ultimate' config.
 */
#define CONFIG_ID_FULL_AND_VERY_DEEP_ULTIMATE 4

/**
 * @brief UUID of 'Full and fast' config.
 */
#define CONFIG_UUID_FULL_AND_FAST "daba56c8-73ec-11df-a475-002264764cea"

/**
 * @brief UUID of 'Full and fast ultimate' config.
 */
#define CONFIG_UUID_FULL_AND_FAST_ULTIMATE \
 "698f691e-7489-11df-9d8c-002264764cea"

/**
 * @brief UUID of 'Full and very deep' config.
 */
#define CONFIG_UUID_FULL_AND_VERY_DEEP "708f25c4-7489-11df-8094-002264764cea"

/**
 * @brief UUID of 'Full and very deep ultimate' config.
 */
#define CONFIG_UUID_FULL_AND_VERY_DEEP_ULTIMATE \
 "74db13d6-7489-11df-91b9-002264764cea"

/**
 * @brief UUID of 'Empty' config.
 */
#define CONFIG_UUID_EMPTY "085569ce-73ed-11df-83c3-002264764cea"

/**
 * @brief UUID of 'All' NVT selector.
 */
#define MANAGE_NVT_SELECTOR_UUID_ALL "54b45713-d4f4-4435-b20d-304c175ed8c5"

/**
 * @brief UUID of 'Localhost' target.
 */
#define TARGET_UUID_LOCALHOST "b493b7a8-7489-11df-a3ec-002264764cea"

/**
 * @brief Trust constant for error.
 */
#define TRUST_ERROR 0

/**
 * @brief Trust constant for yes.
 */
#define TRUST_YES 1

/**
 * @brief Trust constant for no.
 */
#define TRUST_NO 2

/**
 * @brief Trust constant for unknown.
 */
#define TRUST_UNKNOWN 3


/* Headers for symbols defined in manage.c which are private to libmanage. */

/**
 * @brief Flag to force authentication to succeed.  For scheduled tasks.
 */
int authenticate_allow_all;

const char *threat_message_type (const char *);

const char *message_type_threat (const char *);

int delete_reports (task_t);

int delete_slave_task (slave_t, const char *);


/* Static headers. */

static void
init_preference_iterator (iterator_t*, config_t, const char*);

static const char*
preference_iterator_name (iterator_t*);

static const char*
preference_iterator_value (iterator_t*);

static void
nvt_selector_add (const char*, const char*, const char*, int);

static int
nvt_selector_families_growing (const char*);

static int
nvt_selector_family_count (const char*, int);

static int
nvt_selector_nvts_growing (const char*);

static int
nvt_selector_nvts_growing_2 (const char*, int);

static void
nvt_selector_remove_selector (const char*, const char*, int);

static int
insert_rc_into_config (config_t, const char*, const char*, char*);

static void
update_config_caches (config_t);

static void
update_all_config_caches ();

static void
set_target_hosts (target_t, const char *);

static gchar*
select_config_nvts (config_t, const char*, int, const char*);

int
family_count ();

const char*
task_threat_level (task_t);

static const char*
task_previous_threat_level (task_t);

static char*
task_owner_uuid (task_t);

static int
insert_nvt_selectors (const char *, const array_t*);

static int
validate_param_value (report_format_t, report_format_param_t param, const char *,
                      const char *);

static target_t
duplicate_target (target_t, const char *);


/* Variables. */

/**
 * @brief Handle on the database.
 */
sqlite3* task_db = NULL;

/**
 * @brief Memory cache of NVT information from the database.
 */
nvtis_t* nvti_cache = NULL;

/**
 * @brief Name of the database file.
 */
gchar* task_db_name = NULL;


/* SQL helpers. */

/**
 * @brief Quotes a string of a known length to be passed to sql statements.
 *
 * @param[in]  string  String to quote.
 * @param[in]  length  Size of \p string.
 *
 * @return Freshly allocated, quoted string. Free with g_free.
 */
static gchar*
sql_nquote (const char* string, size_t length)
{
  gchar *new, *new_start;
  const gchar *start, *end;
  int count = 0;

  /* Count number of apostrophes. */

  start = string;
  while ((start = strchr (start, '\''))) start++, count++;

  /* Allocate new string. */

  new = new_start = g_malloc0 (length + count + 1);

  /* Copy string, replacing apostrophes with double apostrophes. */

  start = string;
  end = string + length;
  for (; start < end; start++, new++)
    {
      char ch = *start;
      if (ch == '\'')
        {
          *new = '\'';
          new++;
          *new = '\'';
        }
      else
        *new = ch;
    }

  return new_start;
}

/**
 * @brief Quotes a string to be passed to sql statements.
 *
 * @param[in]  string  String to quote, has to be \\0 terminated.
 *
 * @return Freshly allocated, quoted string. Free with g_free.
 */
static gchar*
sql_quote (const char* string)
{
  return sql_nquote (string, strlen (string));
}

/**
 * @brief Get the SQL insert expression for a string.
 *
 * @param[in]  string  The string, which may be NULL.
 *
 * @return Freshly allocated expression suitable for an INSERT statement,
 *         including SQL quotation marks.
 */
static gchar *
sql_insert (const char *string)
{
  if (string)
    {
      gchar *quoted_value = sql_quote (string);
      gchar *insert = g_strdup_printf ("'%s'", quoted_value);
      g_free (quoted_value);
      return insert;
    }
  return g_strdup ("NULL");
}

/**
 * @brief Perform an SQL statement.
 *
 * @param[in]  sql    Format string for SQL statement.
 * @param[in]  ...    Arguments for format string.
 */
static void
sql (char* sql, ...)
{
  const char* tail;
  int ret;
  sqlite3_stmt* stmt;
  va_list args;
  gchar* formatted;

  va_start (args, sql);
  formatted = g_strdup_vprintf (sql, args);
  va_end (args);

  tracef ("   sql: %s\n", formatted);

  /* Prepare statement. */

  while (1)
    {
      ret = sqlite3_prepare (task_db, (char*) formatted, -1, &stmt, &tail);
      if (ret == SQLITE_BUSY) continue;
      g_free (formatted);
      if (ret == SQLITE_OK)
        {
          if (stmt == NULL)
            {
              g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              abort ();
            }
          break;
        }
      g_warning ("%s: sqlite3_prepare failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      abort ();
    }

  /* Run statement. */

  while (1)
    {
      ret = sqlite3_step (stmt);
      if (ret == SQLITE_BUSY) continue;
      if (ret == SQLITE_DONE) break;
      if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
        {
          if (ret == SQLITE_ERROR) ret = sqlite3_reset (stmt);
          g_warning ("%s: sqlite3_step failed: %s\n",
                     __FUNCTION__,
                     sqlite3_errmsg (task_db));
          abort ();
        }
    }

  sqlite3_finalize (stmt);
}

/**
 * @brief Get a particular cell from a SQL query.
 *
 * @param[in]   col          Column.
 * @param[in]   row          Row.
 * @param[in]   sql          Format string for SQL query.
 * @param[in]   args         Arguments for format string.
 * @param[out]  stmt_return  Return from statement.
 *
 * @return 0 success, 1 too few rows, -1 error.
 */
static int
sql_x (/*@unused@*/ unsigned int col, unsigned int row, char* sql,
       va_list args, sqlite3_stmt** stmt_return)
{
  const char* tail;
  int ret;
  sqlite3_stmt* stmt;
  gchar* formatted;

  //va_start (args, sql);
  formatted = g_strdup_vprintf (sql, args);
  //va_end (args);

  tracef ("   sql_x: %s\n", formatted);

  /* Prepare statement. */

  while (1)
    {
      ret = sqlite3_prepare (task_db, (char*) formatted, -1, &stmt, &tail);
      if (ret == SQLITE_BUSY) continue;
      g_free (formatted);
      *stmt_return = stmt;
      if (ret == SQLITE_OK)
        {
          if (stmt == NULL)
            {
              g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              return -1;
            }
          break;
        }
      g_warning ("%s: sqlite3_prepare failed: %s",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      return -1;
    }

  /* Run statement. */

  while (1)
    {
      ret = sqlite3_step (stmt);
      if (ret == SQLITE_BUSY) continue;
      if (ret == SQLITE_DONE)
        {
          return 1;
        }
      if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
        {
          if (ret == SQLITE_ERROR) ret = sqlite3_reset (stmt);
          g_warning ("%s: sqlite3_step failed: %s",
                     __FUNCTION__,
                     sqlite3_errmsg (task_db));
          return -1;
        }
      if (row == 0) break;
      row--;
      tracef ("   sql_x row %i\n", row);
    }

  tracef ("   sql_x end\n");
  return 0;
}

/**
 * @brief Get a particular cell from a SQL query, as an int.
 *
 * @warning Aborts on invalid queries.
 *
 * @warning Aborts when the query returns fewer rows than \p row.  The
 *          caller must ensure that the query will return sufficient rows.
 *
 * @param[in]  col    Column.
 * @param[in]  row    Row.
 * @param[in]  sql    Format string for SQL query.
 * @param[in]  ...    Arguments for format string.
 *
 * @return Result of the query as an integer.
 */
static int
sql_int (unsigned int col, unsigned int row, char* sql, ...)
{
  sqlite3_stmt* stmt;
  va_list args;
  int ret;

  int sql_x_ret;
  va_start (args, sql);
  sql_x_ret = sql_x (col, row, sql, args, &stmt);
  va_end (args);
  if (sql_x_ret)
    {
      sqlite3_finalize (stmt);
      abort ();
    }
  ret = sqlite3_column_int (stmt, col);
  sqlite3_finalize (stmt);
  return ret;
}

/**
 * @brief Get a particular cell from a SQL query, as an string.
 *
 * @param[in]  col    Column.
 * @param[in]  row    Row.
 * @param[in]  sql    Format string for SQL query.
 * @param[in]  ...    Arguments for format string.
 *
 * @return Freshly allocated string containing the result, NULL otherwise.
 *         NULL means that either the selected value was NULL or there were
 *         fewer rows in the result than \p row.
 */
static char*
sql_string (unsigned int col, unsigned int row, char* sql, ...)
{
  sqlite3_stmt* stmt;
  const unsigned char* ret2;
  char* ret;
  int sql_x_ret;

  va_list args;
  va_start (args, sql);
  sql_x_ret = sql_x (col, row, sql, args, &stmt);
  va_end (args);
  if (sql_x_ret)
    {
      sqlite3_finalize (stmt);
      return NULL;
    }
  ret2 = sqlite3_column_text (stmt, col);
  ret = g_strdup ((char*) ret2);
  sqlite3_finalize (stmt);
  return ret;
}

/**
 * @brief Get a particular cell from a SQL query, as an int64.
 *
 * @param[in]  ret    Return value.
 * @param[in]  col    Column.
 * @param[in]  row    Row.
 * @param[in]  sql    Format string for SQL query.
 * @param[in]  ...    Arguments for format string.
 *
 * @return 0 success, 1 too few rows, -1 error.
 */
static int
sql_int64 (long long int* ret, unsigned int col, unsigned int row, char* sql, ...)
{
  sqlite3_stmt* stmt;
  int sql_x_ret;
  va_list args;

  va_start (args, sql);
  sql_x_ret = sql_x (col, row, sql, args, &stmt);
  va_end (args);
  switch (sql_x_ret)
    {
      case  0:
        break;
      case  1:
        sqlite3_finalize (stmt);
        return 1;
        break;
      default:
        assert (0);
        /* Fall through. */
      case -1:
        sqlite3_finalize (stmt);
        return -1;
        break;
    }
  *ret = sqlite3_column_int64 (stmt, col);
  sqlite3_finalize (stmt);
  return 0;
}

/**
 * @brief Make a UUID.
 *
 * This is a callback for a scalar SQL function of zero arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
static void
sql_make_uuid (sqlite3_context *context, int argc, sqlite3_value** argv)
{
  char *uuid;

  assert (argc == 0);

  uuid = openvas_uuid_make ();
  if (uuid == NULL)
    {
      sqlite3_result_error (context, "Failed to create UUID", -1);
      return;
    }

  sqlite3_result_text (context, uuid, -1, free);
}

/**
 * @brief Check if a host list contains a host
 *
 * This is a callback for a scalar SQL function of two arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
static void
sql_hosts_contains (sqlite3_context *context, int argc, sqlite3_value** argv)
{
  gchar **split, **point, *stripped_host;
  const unsigned char *hosts, *host;

  assert (argc == 2);

  hosts = sqlite3_value_text (argv[0]);
  if (hosts == NULL)
    {
      sqlite3_result_error (context, "Failed to get hosts argument", -1);
      return;
    }

  host = sqlite3_value_text (argv[1]);
  if (host == NULL)
    {
      sqlite3_result_error (context, "Failed to get host argument", -1);
      return;
    }

  stripped_host = g_strstrip (g_strdup ((gchar*) host));
  split = g_strsplit ((gchar*) hosts, ",", 0);
  point = split;
  while (*point)
    {
      if (strcmp (g_strstrip (*point), stripped_host) == 0)
        {
          g_strfreev (split);
          g_free (stripped_host);
          sqlite3_result_int (context, 1);
          return;
        }
      point++;
    }
  g_strfreev (split);
  g_free (stripped_host);

  sqlite3_result_int (context, 0);
}

/**
 * @brief Make a name unique.
 *
 * This is a callback for a scalar SQL function of three argument.
 *
 * It's up to the caller to ensure there is a read-only transaction.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
static void
sql_uniquify (sqlite3_context *context, int argc, sqlite3_value** argv)
{
  const unsigned char *proposed_name, *type;
  gchar *candidate_name, *quoted_candidate_name;
  unsigned int number;
  sqlite3_int64 owner;

  assert (argc == 3);

  type = sqlite3_value_text (argv[0]);
  if (type == NULL)
    {
      sqlite3_result_error (context, "Failed to get type argument", -1);
      return;
    }

  proposed_name = sqlite3_value_text (argv[1]);
  if (proposed_name == NULL)
    {
      sqlite3_result_error (context,
                            "Failed to get proposed name argument",
                            -1);
      return;
    }

  owner = sqlite3_value_int64 (argv[2]);

  number = 0;
  candidate_name = g_strdup_printf ("%s %i", proposed_name, ++number);
  quoted_candidate_name = sql_quote (candidate_name);

  while (sql_int (0, 0,
                  "SELECT COUNT (*) FROM %ss WHERE name = '%s'"
                   " AND ((owner IS NULL) OR (owner = %llu));",
                  type,
                  quoted_candidate_name,
                  owner))
    {
      g_free (candidate_name);
      g_free (quoted_candidate_name);
      candidate_name = g_strdup_printf ("%s %u", proposed_name, ++number);
      quoted_candidate_name = sql_quote (candidate_name);
    }

  g_free (quoted_candidate_name);

  sqlite3_result_text (context, candidate_name, -1, SQLITE_TRANSIENT);
  g_free (candidate_name);
}


/* General helpers. */

/**
 * @brief Test whether a string equal to a given string exists in an array.
 *
 * @param[in]  array   Array of gchar* pointers.
 * @param[in]  string  String.
 *
 * @return 1 if a string equal to \arg string exists in \arg array, else 0.
 */
static int
member (GPtrArray *array, const char *string)
{
  const gchar *item;
  int index = 0;
  while ((item = (gchar*) g_ptr_array_index (array, index++)))
    if (strcmp (item, string) == 0) return 1;
  return 0;
}

/**
 * @brief Test whether a user owns a resource.
 *
 * @param[in]  resource  Type of resource, for example "task".
 * @param[in]  uuid      UUID of resource.
 *
 * @return 1 if user owns resource, else 0.
 */
static int
user_owns_uuid (const char *resource, const char *uuid)
{
  int ret;

  assert (current_credentials.uuid);

  ret = sql_int (0, 0,
                 "SELECT count(*) FROM %ss"
                 " WHERE uuid = '%s'"
                 " AND ((owner IS NULL) OR (owner ="
                 " (SELECT users.ROWID FROM users WHERE users.uuid = '%s')));",
                 resource,
                 uuid,
                 current_credentials.uuid);

  return ret;
}

/**
 * @brief Test whether a user owns a resource.
 *
 * @param[in]  resource  Type of resource, for example "report_format".
 * @param[in]  field     Field to compare with value.
 * @param[in]  value     Identifier value of resource.
 *
 * @return 1 if user owns resource, else 0.
 */
static int
user_owns (const char *resource, const char *field, const char *value)
{
  int ret;

  assert (current_credentials.uuid);

  ret = sql_int (0, 0,
                 "SELECT count(*) FROM %ss"
                 " WHERE %s = '%s'"
                 " AND ((owner IS NULL) OR (owner ="
                 " (SELECT users.ROWID FROM users WHERE users.uuid = '%s')));",
                 resource,
                 field,
                 value,
                 current_credentials.uuid);

  return ret;
}

/**
 * @brief Test whether a user owns a result.
 *
 * @param[in]  uuid      UUID of result.
 *
 * @return 1 if user owns result, else 0.
 */
static int
user_owns_result (const char *uuid)
{
  int ret;

  assert (current_credentials.uuid);

  ret = sql_int (0, 0,
                 "SELECT count(*) FROM results, report_results, reports"
                 " WHERE results.uuid = '%s'"
                 " AND report_results.result = results.ROWID"
                 " AND report_results.report = reports.ROWID"
                 " AND ((reports.owner IS NULL) OR (reports.owner ="
                 " (SELECT users.ROWID FROM users WHERE users.uuid = '%s')));",
                 uuid,
                 current_credentials.uuid);

  return ret;
}

/**
 * @brief Ensure a string is in an array.
 *
 * @param[in]  array   Array.
 * @param[in]  string  String.  Copied into array.
 */
static void
array_add_new_string (array_t *array, const gchar *string)
{
  guint index;
  for (index = 0; index < array->len; index++)
    if (strcmp (g_ptr_array_index (array, index), string) == 0)
      return;
  array_add (array, g_strdup (string));
}


/* Creation. */

/**
 * @brief Create all tables.
 */
static void
create_tables ()
{
  sql ("CREATE TABLE IF NOT EXISTS agents (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment, installer TEXT, installer_64 TEXT, installer_filename, installer_signature_64 TEXT, installer_trust INTEGER, installer_trust_time, howto_install TEXT, howto_use TEXT);");
  sql ("CREATE TABLE IF NOT EXISTS config_preferences (id INTEGER PRIMARY KEY, config INTEGER, type, name, value);");
  sql ("CREATE TABLE IF NOT EXISTS configs (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, nvt_selector, comment, family_count INTEGER, nvt_count INTEGER, families_growing INTEGER, nvts_growing INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS escalator_condition_data (id INTEGER PRIMARY KEY, escalator INTEGER, name, data);");
  sql ("CREATE TABLE IF NOT EXISTS escalator_event_data (id INTEGER PRIMARY KEY, escalator INTEGER, name, data);");
  sql ("CREATE TABLE IF NOT EXISTS escalator_method_data (id INTEGER PRIMARY KEY, escalator INTEGER, name, data);");
  sql ("CREATE TABLE IF NOT EXISTS escalators (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment, event INTEGER, condition INTEGER, method INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS lsc_credentials (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, login, password, comment, public_key TEXT, private_key TEXT, rpm TEXT, deb TEXT, exe TEXT);");
  sql ("CREATE TABLE IF NOT EXISTS meta (id INTEGER PRIMARY KEY, name UNIQUE, value);");
  sql ("CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, nvt, creation_time, modification_time, text, hosts, port, threat, task INTEGER, result INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS nvt_preferences (id INTEGER PRIMARY KEY, name, value);");
  /* nvt_selectors types: 0 all, 1 family, 2 NVT (NVT_SELECTOR_TYPE_* in manage.h). */
  sql ("CREATE TABLE IF NOT EXISTS nvt_selectors (id INTEGER PRIMARY KEY, name, exclude INTEGER, type INTEGER, family_or_nvt, family);");
  sql ("CREATE INDEX IF NOT EXISTS nvt_selectors_by_name ON nvt_selectors (name);");
  sql ("CREATE INDEX IF NOT EXISTS nvt_selectors_by_family_or_nvt ON nvt_selectors (type, family_or_nvt);");
  sql ("CREATE TABLE IF NOT EXISTS nvts (id INTEGER PRIMARY KEY, oid, version, name, summary, description, copyright, cve, bid, xref, tag, sign_key_ids, category INTEGER, family, cvss_base, risk_factor);");
  sql ("CREATE INDEX IF NOT EXISTS nvts_by_oid ON nvts (oid);");
  sql ("CREATE INDEX IF NOT EXISTS nvts_by_name ON nvts (name);");
  sql ("CREATE INDEX IF NOT EXISTS nvts_by_family ON nvts (family);");
  sql ("CREATE TABLE IF NOT EXISTS overrides (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, nvt, creation_time, modification_time, text, hosts, port, threat, new_threat, task INTEGER, result INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS report_hosts (id INTEGER PRIMARY KEY, report INTEGER, host, start_time, end_time, attack_state, current_port, max_port);");
  sql ("CREATE INDEX IF NOT EXISTS report_hosts_by_report ON report_hosts (report);");
  sql ("CREATE TABLE IF NOT EXISTS report_format_param_options (id INTEGER PRIMARY KEY, report_format_param, value);");
  sql ("CREATE TABLE IF NOT EXISTS report_format_params (id INTEGER PRIMARY KEY, report_format, name, type INTEGER, value, type_min, type_max, type_regex, fallback);");
  sql ("CREATE TABLE IF NOT EXISTS report_formats (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, extension, content_type, summary, description, signature, trust INTEGER, trust_time, flags INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS report_results (id INTEGER PRIMARY KEY, report INTEGER, result INTEGER);");
  sql ("CREATE INDEX IF NOT EXISTS report_results_by_report ON report_results (report);");
  sql ("CREATE INDEX IF NOT EXISTS report_results_by_result ON report_results (result);");
  sql ("CREATE TABLE IF NOT EXISTS reports (id INTEGER PRIMARY KEY, uuid, owner INTEGER, hidden INTEGER, task INTEGER, date INTEGER, start_time, end_time, nbefile, comment, scan_run_status INTEGER, slave_progress, slave_task_uuid);");
  sql ("CREATE TABLE IF NOT EXISTS results (id INTEGER PRIMARY KEY, uuid, task INTEGER, subnet, host, port, nvt, type, description)");
  sql ("CREATE INDEX IF NOT EXISTS results_by_task ON results (task);");
  sql ("CREATE INDEX IF NOT EXISTS results_by_type ON results (type);");
  sql ("CREATE TABLE IF NOT EXISTS schedules (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, comment, first_time, period, period_months, duration);");
  sql ("CREATE TABLE IF NOT EXISTS slaves (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, comment, host, port, login, password);");
  sql ("CREATE TABLE IF NOT EXISTS targets (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, hosts, comment, lsc_credential INTEGER, smb_lsc_credential INTEGER, port_range);");
  sql ("CREATE TABLE IF NOT EXISTS task_files (id INTEGER PRIMARY KEY, task INTEGER, name, content);");
  sql ("CREATE TABLE IF NOT EXISTS task_escalators (id INTEGER PRIMARY KEY, task INTEGER, escalator INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS tasks   (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, hidden INTEGER, time, comment, description, run_status INTEGER, start_time, end_time, config INTEGER, target INTEGER, schedule INTEGER, schedule_next_time, slave INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS users   (id INTEGER PRIMARY KEY, uuid UNIQUE, name, password);");

  sql ("ANALYZE;");
}

/**
 * @brief Create all tables, using the version 4 schema.
 */
static void
create_tables_version_4 ()
{
  sql ("CREATE TABLE IF NOT EXISTS config_preferences (id INTEGER PRIMARY KEY, config INTEGER, type, name, value);");
  sql ("CREATE TABLE IF NOT EXISTS configs (id INTEGER PRIMARY KEY, name UNIQUE, nvt_selector, comment, family_count INTEGER, nvt_count INTEGER, families_growing INTEGER, nvts_growing INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS lsc_credentials (id INTEGER PRIMARY KEY, name, password, comment, public_key TEXT, private_key TEXT, rpm TEXT, deb TEXT, exe TEXT);");
  sql ("CREATE TABLE IF NOT EXISTS meta    (id INTEGER PRIMARY KEY, name UNIQUE, value);");
  sql ("CREATE TABLE IF NOT EXISTS nvt_preferences (id INTEGER PRIMARY KEY, name, value);");
  /* nvt_selectors types: 0 all, 1 family, 2 NVT (NVT_SELECTOR_TYPE_* above). */
  sql ("CREATE TABLE IF NOT EXISTS nvt_selectors (id INTEGER PRIMARY KEY, name, exclude INTEGER, type INTEGER, family_or_nvt, family);");
  sql ("CREATE TABLE IF NOT EXISTS nvts (id INTEGER PRIMARY KEY, oid, version, name, summary, description, copyright, cve, bid, xref, tag, sign_key_ids, category INTEGER, family);");
  sql ("CREATE TABLE IF NOT EXISTS report_hosts (id INTEGER PRIMARY KEY, report INTEGER, host, start_time, end_time, attack_state, current_port, max_port);");
  sql ("CREATE TABLE IF NOT EXISTS report_results (id INTEGER PRIMARY KEY, report INTEGER, result INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS reports (id INTEGER PRIMARY KEY, uuid, hidden INTEGER, task INTEGER, date INTEGER, start_time, end_time, nbefile, comment, scan_run_status INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS results (id INTEGER PRIMARY KEY, task INTEGER, subnet, host, port, nvt, type, description)");
  sql ("CREATE TABLE IF NOT EXISTS targets (id INTEGER PRIMARY KEY, name, hosts, comment);");
  sql ("CREATE TABLE IF NOT EXISTS task_files (id INTEGER PRIMARY KEY, task INTEGER, name, content);");
  sql ("CREATE TABLE IF NOT EXISTS tasks   (id INTEGER PRIMARY KEY, uuid, name, hidden INTEGER, time, comment, description, owner" /** @todo INTEGER */ ", run_status INTEGER, start_time, end_time, config, target);");
  sql ("CREATE TABLE IF NOT EXISTS users   (id INTEGER PRIMARY KEY, name UNIQUE, password);");
}


/* Iterators. */

/**
 * @brief Initialise an iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  sql       Format string for SQL.
 */
static void
init_iterator (iterator_t* iterator, const char* sql, ...)
{
  int ret;
  const char* tail;
  sqlite3_stmt* stmt;
  va_list args;
  gchar* formatted;

  va_start (args, sql);
  formatted = g_strdup_vprintf (sql, args);
  va_end (args);

  tracef ("   sql: %s\n", formatted);

  iterator->done = FALSE;
  while (1)
    {
      ret = sqlite3_prepare (task_db, formatted, -1, &stmt, &tail);
      if (ret == SQLITE_BUSY) continue;
      g_free (formatted);
      iterator->stmt = stmt;
      if (ret == SQLITE_OK)
        {
          if (stmt == NULL)
            {
              g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              abort ();
            }
          break;
        }
      g_warning ("%s: sqlite3_prepare failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      abort ();
    }
}

/**
 * @brief Get an integer column from an iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  col       Column offset.
 *
 * @return Value of given column.
 */
long long int
iterator_int64 (iterator_t* iterator, int col)
{
  if (iterator->done) abort ();
  return (long long int) sqlite3_column_int64 (iterator->stmt, col);
}

/**
 * @brief Get a string column from an iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  col       Column offset.
 *
 * @return Value of given column.
 */
const char*
iterator_string (iterator_t* iterator, int col)
{
  if (iterator->done) abort ();
  return (const char*) sqlite3_column_text (iterator->stmt, col);
}

/**
 * @brief Cleanup an iterator.
 *
 * @param[in]  iterator  Iterator.
 */
void
cleanup_iterator (iterator_t* iterator)
{
  sqlite3_finalize (iterator->stmt);
}

/**
 * @brief Increment an iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return TRUE if there was a next item, else FALSE.
 */
gboolean
next (iterator_t* iterator)
{
  int ret;

  if (iterator->done) return FALSE;

  while ((ret = sqlite3_step (iterator->stmt)) == SQLITE_BUSY);
  if (ret == SQLITE_DONE)
    {
      iterator->done = TRUE;
      return FALSE;
    }
  if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
    {
      if (ret == SQLITE_ERROR) ret = sqlite3_reset (iterator->stmt);
      g_warning ("%s: sqlite3_step failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      abort ();
    }
  return TRUE;
}


/* Migration. */

/**
 * @section procedure_writing_migrator Procedure for writing a migrator
 *
 * Every change that affects the database schema or the format of the data in
 * the database must have a migrator so that someone using an older version of
 * the database can update to the newer version.
 *
 * Simply adding a new table to the database is, however, OK.  At startup, the
 * manager will automatically add a table if it is missing from the database.
 *
 *  - Ensure that the ChangeLog notes the changes to the database and
 *    the increase of OPENVASMD_DATABASE_VERSION, with an entry like
 *
 *        * CMakeLists.txt (OPENVASMD_DATABASE_VERSION): Increase to 6, for...
 *
 *        * src/tasks_sql.h (create_tables): Add new column...
 *
 *  - Add the migrator function in the style of the others.  In particular,
 *    the function must check the version, do the modification and then set
 *    the new version, all inside an exclusive transaction.  Use the generic
 *    iterator (init_iterator, iterator_string, iterator_int64...) because the
 *    specialised iterators (like init_target_iterator) can change behaviour
 *    across Manager SVN versions.  Use copies of any other "manage" interfaces,
 *    for example update_all_config_caches, as these may also change in later
 *    versions of the Manager.
 *
 *  - Remember to ensure that tables exist in the migrator before the migrator
 *    modifies them.  If a migrator modifies a table then the table must either
 *    have existed in database version 0 (listed below), or some earlier
 *    migrator must have added the table, or the migrator must add the table
 *    (using the original schema of the table).
 *
 *  - Add the migrator to the database_migrators array.
 *
 *  - Test that everything still works for a database that has been migrated
 *    from the previous version.
 *
 *  - Test that everything still works for a database that has been migrated
 *    from version 0.
 *
 *  - Commit with a ChangeLog heading like
 *
 *        Add database migration from version 5 to 6.
 *
 * SQL that created database version 0:
 *
 *     CREATE TABLE IF NOT EXISTS config_preferences
 *       (config INTEGER, type, name, value);
 *
 *     CREATE TABLE IF NOT EXISTS configs
 *       (name UNIQUE, nvt_selector, comment, family_count INTEGER,
 *        nvt_count INTEGER, families_growing INTEGER, nvts_growing INTEGER);
 *
 *     CREATE TABLE IF NOT EXISTS meta
 *       (name UNIQUE, value);
 *
 *     CREATE TABLE IF NOT EXISTS nvt_selectors
 *       (name, exclude INTEGER, type INTEGER, family_or_nvt);
 *
 *     CREATE TABLE IF NOT EXISTS nvts
 *       (oid, version, name, summary, description, copyright, cve, bid, xref,
 *        tag, sign_key_ids, category, family);
 *
 *     CREATE TABLE IF NOT EXISTS report_hosts
 *       (report INTEGER, host, start_time, end_time, attack_state,
 *        current_port, max_port);
 *
 *     CREATE TABLE IF NOT EXISTS report_results
 *       (report INTEGER, result INTEGER);
 *
 *     CREATE TABLE IF NOT EXISTS reports
 *       (uuid, hidden INTEGER, task INTEGER, date INTEGER, start_time,
 *        end_time, nbefile, comment);
 *
 *     CREATE TABLE IF NOT EXISTS results
 *       (task INTEGER, subnet, host, port, nvt, type, description);
 *
 *     CREATE TABLE IF NOT EXISTS targets
 *       (name, hosts, comment);
 *
 *     CREATE TABLE IF NOT EXISTS tasks
 *       (uuid, name, hidden INTEGER, time, comment, description, owner,
 *        run_status, start_time, end_time, config, target);
 *
 *     CREATE TABLE IF NOT EXISTS users
 *       (name UNIQUE, password);
 */

/**
 * @brief Backup the database to a file.
 *
 * @param[in]   database     Database to backup.
 * @param[out]  backup_file  Freshly allocated name of backup file.
 *
 * @return 0 success, -1 error.
 */
static int
backup_db (const gchar *database, gchar **backup_file)
{
  gchar *command;
  int ret;

  sql ("BEGIN EXCLUSIVE;");

  command = g_strdup_printf ("cp %s %s.bak > /dev/null 2>&1"
                             "&& cp %s-journal %s.bak-journal > /dev/null 2>&1",
                             database,
                             database,
                             database,
                             database);
  tracef ("   command: %s\n", command);
  ret = system (command);
  g_free (command);

  if (ret == -1 || WEXITSTATUS (ret))
    {
      sql ("ROLLBACK;");
      return -1;
    }

  sql ("COMMIT;");

  if (backup_file)
    *backup_file = g_strdup_printf ("%s.bak", database);

  return 0;
}

/**
 * @brief Backup the database to a file.
 *
 * @param[in]  database  Location of manage database.
 *
 * @return 0 success, -1 error.
 */
int
manage_backup_db (const gchar *database)
{
  int ret;
  const gchar *db = database ? database : OPENVAS_STATE_DIR "/mgr/tasks.db";

  init_manage_process (0, db);

  ret = backup_db (db, NULL);

  cleanup_manage_process (TRUE);

  return ret;
}

/**
 * @brief Return the database version supported by this manager.
 *
 * @return Database version supported by this manager.
 */
int
manage_db_supported_version ()
{
  return OPENVASMD_DATABASE_VERSION;
}

/**
 * @brief Return the database version of the actual database.
 *
 * @return Database version read from database if possible, else -1.
 */
int
manage_db_version ()
{
  int number;
  char *version = sql_string (0, 0,
                              "SELECT value FROM meta"
                              " WHERE name = 'database_version' LIMIT 1;");
  if (version)
    {
      number = atoi (version);
      free (version);
      return number;
    }
  return -1;
}

/**
 * @brief Set the database version of the actual database.
 *
 * @param  version  New version number.
 */
static void
set_db_version (int version)
{
  /** @todo Check that this (and others) still works with id column. */
  sql ("INSERT OR REPLACE INTO meta (name, value)"
       " VALUES ('database_version', '%i');",
       version);
}

/**
 * @brief A migrator.
 */
typedef struct
{
  int version;         ///< Version that the migrator produces.
  int (*function) ();  ///< Function that does the migration.  NULL if too hard.
} migrator_t;

/**
 * @brief Migrate the database from version 0 to version 1.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_0_to_1 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 0. */

  if (manage_db_version () != 0)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* In SVN the database version flag changed from 0 to 1 on 2009-09-30,
   * while the database changed to the version 1 schema on 2009-08-29.  This
   * means the database could be flagged as version 0 while it has a version
   * 1 schema.  In this case the ADD COLUMN below would fail.  A work around
   * would be simply to update the version number to 1 in the database by
   * hand. */

  sql ("ALTER TABLE reports ADD COLUMN scan_run_status INTEGER;");

  /* SQLite 3.1.3 and earlier requires a VACUUM before it can read
   * from the new column.  However, vacuuming might change the ROWIDs,
   * which would screw up the data.  Debian 5.0 (Lenny) is 3.5.9-6
   * already. */

  sql ("UPDATE reports SET scan_run_status = '%u';",
       TASK_STATUS_INTERNAL_ERROR);

  sql ("UPDATE reports SET scan_run_status = '%u'"
       " WHERE start_time IS NULL OR end_time IS NULL;",
       TASK_STATUS_STOPPED);

  sql ("UPDATE reports SET scan_run_status = '%u'"
       " WHERE end_time IS NOT NULL;",
       TASK_STATUS_DONE);

  /* Set the database version to 1. */

  set_db_version (1);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 1 to version 2.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_1_to_2 ()
{
  iterator_t nvts;

  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 1. */

  if (manage_db_version () != 1)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The category column in nvts changed type from string to int.  This
   * may be a redundant conversion, as SQLite may have converted these
   * values automatically in each query anyway. */

  init_iterator (&nvts, "SELECT ROWID, category FROM nvts;");
  while (next (&nvts))
    {
      int category;
      const char *category_string;

      category_string = (const char*) sqlite3_column_text (nvts.stmt, 1);

      category = atoi (category_string);
      sql ("UPDATE nvts SET category = %i WHERE ROWID = %llu;",
           category,
           iterator_int64 (&nvts, 0));
    }
  cleanup_iterator (&nvts);

  /* Set the database version to 2. */

  set_db_version (2);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 2 to version 3.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_2_to_3 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 2. */

  if (manage_db_version () != 2)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Add tables added since version 2 that are adjust later in the
   * migration. */

  sql ("CREATE TABLE IF NOT EXISTS lsc_credentials (name, comment, rpm, deb, dog);");

  /* The lsc_credentials table changed: package columns changed type from BLOB
   * to string, new columns "password", "public key" and "private key" appeared
   * and the dog column changed name to exe.
   *
   * Just remove all the LSC credentials, as credential generation only
   * started working after version 3. */

  sql ("DELETE from lsc_credentials;");
  /* Before revision 5769 this could have caused problems, because these
   * columns are added on the end of the table, so columns referenced by
   * position in * queries may have been wrong (for example, with the iterator
   * returned by init_lsc_credential_iterator).  Since 5769 the queries
   * name all columns explicitly. */
  sql ("ALTER TABLE lsc_credentials ADD COLUMN password;");
  sql ("ALTER TABLE lsc_credentials ADD COLUMN public_key TEXT;");
  sql ("ALTER TABLE lsc_credentials ADD COLUMN private_key TEXT;");
  sql ("ALTER TABLE lsc_credentials ADD COLUMN exe TEXT;");

  /* Set the database version to 3. */

  set_db_version (3);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 3 to version 4.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_3_to_4 ()
{
  iterator_t nvts;

  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 3. */

  if (manage_db_version () != 3)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The nvt_selectors table got a family column. */

  sql ("ALTER TABLE nvt_selectors ADD COLUMN family;");

  init_nvt_selector_iterator (&nvts, NULL, (config_t) 0, 2);
  while (next (&nvts))
    {
      gchar *quoted_name = sql_quote (nvt_selector_iterator_name (&nvts));
      gchar *quoted_nvt = sql_quote (nvt_selector_iterator_nvt (&nvts));
      sql ("UPDATE nvt_selectors SET family ="
           " (SELECT family FROM nvts where oid = '%s')"
           " WHERE name = '%s';",
           quoted_nvt, quoted_name);
      g_free (quoted_name);
      g_free (quoted_nvt);
    }
  cleanup_iterator (&nvts);

  /* Set the database version to 4. */

  set_db_version (4);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Move all the data to the new tables for the 4 to 5 migrator.
 */
static void
migrate_4_to_5_copy_data ()
{
  iterator_t rows;

  /* Table config_preferences. */
  init_iterator (&rows,
                 "SELECT rowid, config, type, name, value"
                 " FROM config_preferences_4;");
  while (next (&rows))
    {
      gchar *quoted_type = sql_insert (iterator_string (&rows, 2));
      gchar *quoted_name = sql_insert (iterator_string (&rows, 3));
      gchar *quoted_value = sql_insert (iterator_string (&rows, 4));
      sql ("INSERT into config_preferences (id, config, type, name, value)"
           " VALUES (%llu, %llu, %s, %s, %s);",
           iterator_int64 (&rows, 0),
           iterator_int64 (&rows, 1),
           quoted_type,
           quoted_name,
           quoted_value);
      g_free (quoted_type);
      g_free (quoted_name);
      g_free (quoted_value);
    }
  cleanup_iterator (&rows);
  sql ("DROP TABLE config_preferences_4;");

  /* Table configs. */
  init_iterator (&rows,
                 "SELECT rowid, name, nvt_selector, comment, family_count,"
                 " nvt_count, families_growing, nvts_growing"
                 " FROM configs_4;");
  while (next (&rows))
    {
      gchar *quoted_name = sql_insert (iterator_string (&rows, 1));
      gchar *quoted_nvt_selector = sql_insert (iterator_string (&rows, 2));
      gchar *quoted_comment = sql_insert (iterator_string (&rows, 3));
      sql ("INSERT into configs"
           " (id, name, nvt_selector, comment, family_count, nvt_count,"
           "  families_growing, nvts_growing)"
           " VALUES"
           " (%llu, %s, %s, %s, %llu, %llu, %llu, %llu);",
           iterator_int64 (&rows, 0),
           quoted_name,
           quoted_nvt_selector,
           quoted_comment,
           iterator_int64 (&rows, 4),
           iterator_int64 (&rows, 5),
           iterator_int64 (&rows, 6),
           iterator_int64 (&rows, 7));
      g_free (quoted_name);
      g_free (quoted_nvt_selector);
      g_free (quoted_comment);
    }
  cleanup_iterator (&rows);
  sql ("DROP TABLE configs_4;");

  /* Table lsc_credentials. */
  init_iterator (&rows,
                 "SELECT rowid, name, password, comment, public_key,"
                 " private_key, rpm, deb, exe"
                 " FROM lsc_credentials_4;");
  while (next (&rows))
    {
      gchar *quoted_name = sql_insert (iterator_string (&rows, 1));
      gchar *quoted_password = sql_insert (iterator_string (&rows, 2));
      gchar *quoted_comment = sql_insert (iterator_string (&rows, 3));
      gchar *quoted_public_key = sql_insert (iterator_string (&rows, 4));
      gchar *quoted_private_key = sql_insert (iterator_string (&rows, 5));
      gchar *quoted_rpm = sql_insert (iterator_string (&rows, 6));
      gchar *quoted_deb = sql_insert (iterator_string (&rows, 7));
      gchar *quoted_exe = sql_insert (iterator_string (&rows, 8));
      sql ("INSERT into lsc_credentials"
           " (id, name, password, comment, public_key, private_key, rpm, deb,"
           "  exe)"
           " VALUES"
           " (%llu, %s, %s, %s, %s, %s, %s, %s, %s);",
           iterator_int64 (&rows, 0),
           quoted_name,
           quoted_password,
           quoted_comment,
           quoted_public_key,
           quoted_private_key,
           quoted_rpm,
           quoted_deb,
           quoted_exe);
      g_free (quoted_name);
      g_free (quoted_password);
      g_free (quoted_comment);
      g_free (quoted_public_key);
      g_free (quoted_private_key);
      g_free (quoted_rpm);
      g_free (quoted_deb);
      g_free (quoted_exe);
    }
  cleanup_iterator (&rows);
  sql ("DROP TABLE lsc_credentials_4;");

  /* Table meta. */
  init_iterator (&rows, "SELECT rowid, name, value FROM meta_4;");
  while (next (&rows))
    {
      gchar *quoted_name = sql_insert (iterator_string (&rows, 1));
      gchar *quoted_value = sql_insert (iterator_string (&rows, 2));
      sql ("INSERT into meta (id, name, value)"
           " VALUES (%llu, %s, %s);",
           iterator_int64 (&rows, 0),
           quoted_name,
           quoted_value);
      g_free (quoted_name);
      g_free (quoted_value);
    }
  cleanup_iterator (&rows);
  sql ("DROP TABLE meta_4;");

  /* Table nvt_preferences. */
  init_iterator (&rows, "SELECT rowid, name, value FROM nvt_preferences_4;");
  while (next (&rows))
    {
      gchar *quoted_name = sql_insert (iterator_string (&rows, 1));
      gchar *quoted_value = sql_insert (iterator_string (&rows, 2));
      sql ("INSERT into nvt_preferences (id, name, value)"
           " VALUES (%llu, %s, %s);",
           iterator_int64 (&rows, 0),
           quoted_name,
           quoted_value);
      g_free (quoted_name);
      g_free (quoted_value);
    }
  cleanup_iterator (&rows);
  sql ("DROP TABLE nvt_preferences_4;");

  /* Table nvt_selectors. */
  init_iterator (&rows,
                 "SELECT rowid, name, exclude, type, family_or_nvt, family"
                 " FROM nvt_selectors_4;");
  while (next (&rows))
    {
      gchar *quoted_name = sql_insert (iterator_string (&rows, 1));
      gchar *quoted_family_or_nvt = sql_insert (iterator_string (&rows, 4));
      gchar *quoted_family = sql_insert (iterator_string (&rows, 5));
      sql ("INSERT into nvt_selectors"
           " (id, name, exclude, type, family_or_nvt, family)"
           " VALUES"
           " (%llu, %s, %llu, %llu, %s, %s);",
           iterator_int64 (&rows, 0),
           quoted_name,
           iterator_int64 (&rows, 2),
           iterator_int64 (&rows, 3),
           quoted_family_or_nvt,
           quoted_family);
      g_free (quoted_name);
      g_free (quoted_family_or_nvt);
      g_free (quoted_family);
    }
  cleanup_iterator (&rows);
  sql ("DROP TABLE nvt_selectors_4;");

  /* Table nvts. */
  init_iterator (&rows,
                 "SELECT rowid, oid, version, name, summary, description,"
                 " copyright, cve, bid, xref, tag, sign_key_ids, category,"
                 " family"
                 " FROM nvts_4;");
  while (next (&rows))
    {
      gchar *quoted_oid = sql_insert (iterator_string (&rows, 1));
      gchar *quoted_version = sql_insert (iterator_string (&rows, 2));
      gchar *quoted_name = sql_insert (iterator_string (&rows, 3));
      gchar *quoted_summary = sql_insert (iterator_string (&rows, 4));
      gchar *quoted_description = sql_insert (iterator_string (&rows, 5));
      gchar *quoted_copyright = sql_insert (iterator_string (&rows, 6));
      gchar *quoted_cve = sql_insert (iterator_string (&rows, 7));
      gchar *quoted_bid = sql_insert (iterator_string (&rows, 8));
      gchar *quoted_xref = sql_insert (iterator_string (&rows, 9));
      gchar *quoted_tag = sql_insert (iterator_string (&rows, 10));
      gchar *quoted_sign_key_ids = sql_insert (iterator_string (&rows, 11));
      gchar *quoted_family = sql_insert (iterator_string (&rows, 13));

      {
        /* Starting from revision 5726 on 2009-10-26 (just before 0.9.2),
         * the Manager converts semicolons in OTP NVT descriptions to newlines
         * before entering them in the database.  Convert the existing
         * semicolons here, because it is a convenient place to do it. */
        gchar* pos = quoted_description;
        while ((pos = strchr (pos, ';')))
          pos[0] = '\n';
      }

      sql ("INSERT into nvts"
           " (id, oid, version, name, summary, description, copyright, cve,"
           "  bid, xref, tag, sign_key_ids, category, family)"
           " VALUES"
           " (%llu, %s, %s, %s, %s, %s, %s, %s, %s, %s,"
           "  %s, %s, %llu, %s);",
           iterator_int64 (&rows, 0),
           quoted_oid,
           quoted_version,
           quoted_name,
           quoted_summary,
           quoted_description,
           quoted_copyright,
           quoted_cve,
           quoted_bid,
           quoted_xref,
           quoted_tag,
           quoted_sign_key_ids,
           iterator_int64 (&rows, 12),
           quoted_family);
      g_free (quoted_oid);
      g_free (quoted_version);
      g_free (quoted_name);
      g_free (quoted_summary);
      g_free (quoted_description);
      g_free (quoted_copyright);
      g_free (quoted_cve);
      g_free (quoted_bid);
      g_free (quoted_xref);
      g_free (quoted_tag);
      g_free (quoted_sign_key_ids);
      g_free (quoted_family);
    }
  cleanup_iterator (&rows);
  sql ("DROP TABLE nvts_4;");

  /* Table report_hosts. */
  init_iterator (&rows,
                 "SELECT rowid, report, host, start_time, end_time,"
                 " attack_state, current_port, max_port"
                 " FROM report_hosts_4;");
  while (next (&rows))
    {
      gchar *quoted_host = sql_insert (iterator_string (&rows, 2));
      gchar *quoted_start_time = sql_insert (iterator_string (&rows, 3));
      gchar *quoted_end_time = sql_insert (iterator_string (&rows, 4));
      gchar *quoted_attack_state = sql_insert (iterator_string (&rows, 5));
      gchar *quoted_current_port = sql_insert (iterator_string (&rows, 6));
      gchar *quoted_max_port = sql_insert (iterator_string (&rows, 7));
      sql ("INSERT into report_hosts"
           " (id, report, host, start_time, end_time, attack_state,"
           "  current_port, max_port)"
           " VALUES"
           " (%llu, %llu, %s, %s, %s, %s, %s, %s);",
           iterator_int64 (&rows, 0),
           iterator_int64 (&rows, 1),
           quoted_host,
           quoted_start_time,
           quoted_end_time,
           quoted_attack_state,
           quoted_current_port,
           quoted_max_port);
      g_free (quoted_host);
      g_free (quoted_start_time);
      g_free (quoted_end_time);
      g_free (quoted_attack_state);
      g_free (quoted_current_port);
      g_free (quoted_max_port);
    }
  cleanup_iterator (&rows);
  sql ("DROP TABLE report_hosts_4;");

  /* Table report_results. */
  init_iterator (&rows, "SELECT rowid, report, result FROM report_results_4;");
  while (next (&rows))
    {
      sql ("INSERT into report_results (id, report, result)"
           " VALUES (%llu, %llu, %llu)",
           iterator_int64 (&rows, 0),
           iterator_int64 (&rows, 1),
           iterator_int64 (&rows, 2));
    }
  cleanup_iterator (&rows);
  sql ("DROP TABLE report_results_4;");

  /* Table reports. */
  init_iterator (&rows,
                 "SELECT rowid, uuid, hidden, task, date, start_time, end_time,"
                 " nbefile, comment, scan_run_status"
                 " FROM reports_4;");
  while (next (&rows))
    {
      gchar *quoted_uuid = sql_insert (iterator_string (&rows, 1));
      gchar *quoted_start_time = sql_insert (iterator_string (&rows, 5));
      gchar *quoted_end_time = sql_insert (iterator_string (&rows, 6));
      gchar *quoted_nbefile = sql_insert (iterator_string (&rows, 7));
      gchar *quoted_comment = sql_insert (iterator_string (&rows, 8));
      sql ("INSERT into reports"
           " (id, uuid, hidden, task, date, start_time, end_time, nbefile,"
           "  comment, scan_run_status)"
           " VALUES"
           " (%llu, %s, %llu, %llu, %llu, %s, %s, %s, %s, %llu);",
           iterator_int64 (&rows, 0),
           quoted_uuid,
           iterator_int64 (&rows, 2),
           iterator_int64 (&rows, 3),
           iterator_int64 (&rows, 4),
           quoted_start_time,
           quoted_end_time,
           quoted_nbefile,
           quoted_comment,
           iterator_int64 (&rows, 9));
      g_free (quoted_uuid);
      g_free (quoted_start_time);
      g_free (quoted_end_time);
      g_free (quoted_nbefile);
      g_free (quoted_comment);
    }
  cleanup_iterator (&rows);
  sql ("DROP TABLE reports_4;");

  /* Table results. */
  init_iterator (&rows,
                 "SELECT rowid, task, subnet, host, port, nvt, type,"
                 " description"
                 " FROM results_4;");
  while (next (&rows))
    {
      gchar *quoted_subnet = sql_insert (iterator_string (&rows, 2));
      gchar *quoted_host = sql_insert (iterator_string (&rows, 3));
      gchar *quoted_port = sql_insert (iterator_string (&rows, 4));
      gchar *quoted_nvt = sql_insert (iterator_string (&rows, 5));
      gchar *quoted_type = sql_insert (iterator_string (&rows, 6));
      gchar *quoted_description = sql_insert (iterator_string (&rows, 7));
      sql ("INSERT into results"
           " (id, task, subnet, host, port, nvt, type, description)"
           " VALUES"
           " (%llu, %llu, %s, %s, %s, %s, %s, %s);",
           iterator_int64 (&rows, 0),
           iterator_int64 (&rows, 1),
           quoted_subnet,
           quoted_host,
           quoted_port,
           quoted_nvt,
           quoted_type,
           quoted_description);
      g_free (quoted_subnet);
      g_free (quoted_host);
      g_free (quoted_port);
      g_free (quoted_nvt);
      g_free (quoted_type);
      g_free (quoted_description);
    }
  cleanup_iterator (&rows);
  sql ("DROP TABLE results_4;");

  /* Table targets. */
  init_iterator (&rows, "SELECT rowid, name, hosts, comment FROM targets_4;");
  while (next (&rows))
    {
      gchar *quoted_name = sql_insert (iterator_string (&rows, 1));
      gchar *quoted_hosts = sql_insert (iterator_string (&rows, 2));
      gchar *quoted_comment = sql_insert (iterator_string (&rows, 3));
      sql ("INSERT into targets (id, name, hosts, comment)"
           " VALUES (%llu, %s, %s, %s);",
           iterator_int64 (&rows, 0),
           quoted_name,
           quoted_hosts,
           quoted_comment);
      g_free (quoted_name);
      g_free (quoted_hosts);
      g_free (quoted_comment);
    }
  cleanup_iterator (&rows);
  sql ("DROP TABLE targets_4;");

  /* Table task_files. */
  init_iterator (&rows, "SELECT rowid, task, name, content FROM task_files_4;");
  while (next (&rows))
    {
      gchar *quoted_name = sql_insert (iterator_string (&rows, 2));
      gchar *quoted_content = sql_insert (iterator_string (&rows, 3));
      sql ("INSERT into task_files (id, task, name, content)"
           " VALUES (%llu, %llu, %s, %s);",
           iterator_int64 (&rows, 0),
           iterator_int64 (&rows, 1),
           quoted_name,
           quoted_content);
      g_free (quoted_name);
      g_free (quoted_content);
    }
  cleanup_iterator (&rows);
  sql ("DROP TABLE task_files_4;");

  /* Table tasks. */
  init_iterator (&rows,
                 "SELECT rowid, uuid, name, hidden, time, comment, description,"
                 " owner, run_status, start_time, end_time, config, target"
                 " FROM tasks_4;");
  while (next (&rows))
    {
      gchar *quoted_uuid = sql_insert (iterator_string (&rows, 1));
      gchar *quoted_name = sql_insert (iterator_string (&rows, 2));
      gchar *quoted_time = sql_insert (iterator_string (&rows, 4));
      gchar *quoted_comment = sql_insert (iterator_string (&rows, 5));
      gchar *quoted_description = sql_insert (iterator_string (&rows, 6));
      gchar *quoted_start_time = sql_insert (iterator_string (&rows, 9));
      gchar *quoted_end_time = sql_insert (iterator_string (&rows, 10));
      gchar *quoted_config = sql_insert (iterator_string (&rows, 11));
      gchar *quoted_target = sql_insert (iterator_string (&rows, 12));
      sql ("INSERT into tasks"
           " (id, uuid, name, hidden, time, comment, description, owner,"
           "  run_status, start_time, end_time, config, target)"
           " VALUES"
           " (%llu, %s, %s, %llu, %s, %s, %s, %llu, %llu, %s,"
           "  %s, %s, %s);",
           iterator_int64 (&rows, 0),
           quoted_uuid,
           quoted_name,
           iterator_int64 (&rows, 3),
           quoted_time,
           quoted_comment,
           quoted_description,
           iterator_int64 (&rows, 7),
           iterator_int64 (&rows, 8),
           quoted_start_time,
           quoted_end_time,
           quoted_config,
           quoted_target);
      g_free (quoted_uuid);
      g_free (quoted_name);
      g_free (quoted_time);
      g_free (quoted_comment);
      g_free (quoted_description);
      g_free (quoted_start_time);
      g_free (quoted_end_time);
      g_free (quoted_config);
      g_free (quoted_target);
    }
  cleanup_iterator (&rows);
  sql ("DROP TABLE tasks_4;");

  /* Table users. */
  init_iterator (&rows, "SELECT rowid, name, password FROM users_4;");
  while (next (&rows))
    {
      gchar *quoted_name = sql_insert (iterator_string (&rows, 1));
      gchar *quoted_password = sql_insert (iterator_string (&rows, 2));
      sql ("INSERT into users (id, name, password)"
           " VALUES (%llu, %s, %s);",
           iterator_int64 (&rows, 0),
           quoted_name,
           quoted_password);
      g_free (quoted_name);
      g_free (quoted_password);
    }
  cleanup_iterator (&rows);
  sql ("DROP TABLE users_4;");
}

/**
 * @brief Migrate the database from version 4 to version 5.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_4_to_5 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 4. */

  if (manage_db_version () != 4)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Every table got an "id INTEGER PRIMARY KEY" column.  As the column is a
   * primary key, every table must be recreated and the data transfered.
   *
   * Also, starting from revision 5726 on 2009-10-26 (just before 0.9.2),
   * the Manager converts semicolons in OTP NVT descriptions to newlines
   * before entering them in the database.  Convert the existing
   * semicolons while transfering the data.  This should have been an
   * entirely separate version and migration between the current 4 and 5. */

  /* Ensure that all tables exist that will be adjusted below. */

  /* Both introduced between version 1 and 2. */
  sql ("CREATE TABLE IF NOT EXISTS nvt_preferences (name, value);");
  sql ("CREATE TABLE IF NOT EXISTS task_files (task INTEGER, name, content);");

  /* Move the tables away. */

  sql ("ALTER TABLE config_preferences RENAME TO config_preferences_4;");
  sql ("ALTER TABLE configs RENAME TO configs_4;");
  sql ("ALTER TABLE lsc_credentials RENAME TO lsc_credentials_4;");
  sql ("ALTER TABLE meta RENAME TO meta_4;");
  sql ("ALTER TABLE nvt_preferences RENAME TO nvt_preferences_4;");
  sql ("ALTER TABLE nvt_selectors RENAME TO nvt_selectors_4;");
  sql ("ALTER TABLE nvts RENAME TO nvts_4;");
  sql ("ALTER TABLE report_hosts RENAME TO report_hosts_4;");
  sql ("ALTER TABLE report_results RENAME TO report_results_4;");
  sql ("ALTER TABLE reports RENAME TO reports_4;");
  sql ("ALTER TABLE results RENAME TO results_4;");
  sql ("ALTER TABLE targets RENAME TO targets_4;");
  sql ("ALTER TABLE task_files RENAME TO task_files_4;");
  sql ("ALTER TABLE tasks RENAME TO tasks_4;");
  sql ("ALTER TABLE users RENAME TO users_4;");

  /* Create the new tables in version 4 format. */

  create_tables_version_4 ();

  /* Copy the data into the new tables, dropping the old tables. */

  migrate_4_to_5_copy_data ();

  /* Set the database version to 5. */

  set_db_version (5);

  sql ("COMMIT;");

  /* All the moving may have left much empty space, so vacuum. */

  sql ("VACUUM;");

  return 0;
}

/**
 * @brief Move a config that is using a predefined ID.
 *
 * @param[in]  predefined_config_name  Name of the predefined config.
 * @param[in]  predefined_config_id    Row ID of the predefined config.
 */
static void
migrate_5_to_6_move_other_config (const char *predefined_config_name,
                                  config_t predefined_config_id)
{
  if (sql_int (0, 0,
               "SELECT COUNT(*) = 0 FROM configs"
               " WHERE name = '%s';",
               predefined_config_name)
      && sql_int (0, 0,
                  "SELECT COUNT(*) = 1 FROM configs"
                  " WHERE ROWID = %llu;",
                  predefined_config_id))
    {
      config_t config;
      char *name;
      gchar *quoted_name;

      sql ("INSERT into configs (nvt_selector, comment, family_count,"
           " nvt_count, nvts_growing, families_growing)"
           " SELECT nvt_selector, comment, family_count,"
           " nvt_count, nvts_growing, families_growing"
           " FROM configs"
           " WHERE ROWID = %llu;",
           predefined_config_id);
      /* This ID will be larger then predefined_config_id because
       * predefined_config_id exists already.  At worst the ID will be one
       * larger. */
      config = sqlite3_last_insert_rowid (task_db);
      sql ("UPDATE config_preferences SET config = %llu WHERE config = %llu;",
           config,
           predefined_config_id);
      name = sql_string (0, 0,
                         "SELECT name FROM configs WHERE ROWID = %llu;",
                         predefined_config_id);
      if (name == NULL)
        {
          sql ("ROLLBACK;");
          abort ();
        }
      quoted_name = sql_quote (name);
      free (name);
      /* Table tasks references config by name, so it stays the same. */
      sql ("DELETE FROM configs WHERE ROWID = %llu;",
           predefined_config_id);
      sql ("UPDATE configs SET name = '%s' WHERE ROWID = %llu;",
           quoted_name,
           config);
      g_free (quoted_name);
    }
}

/**
 * @brief Migrate the database from version 5 to version 6.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_5_to_6 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 5. */

  if (manage_db_version () != 5)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The predefined configs got predefined ID's and the manager now also
   * caches counts for growing configs. */

  /* Fail with a message if the predefined configs have somehow got ID's
   * other than the usual ones. */

  if (sql_int (0, 0,
               "SELECT COUNT(*) = 0 OR ROWID == 1 FROM configs"
               " WHERE name = 'Full and fast';")
      && sql_int (0, 0,
                  "SELECT COUNT(*) = 0 OR ROWID == 2 FROM configs"
                  " WHERE name = 'Full and fast ultimate';")
      && sql_int (0, 0,
                  "SELECT COUNT(*) = 0 OR ROWID == 3 FROM configs"
                  " WHERE name = 'Full and very deep';")
      && sql_int (0, 0,
                  "SELECT COUNT(*) = 0 OR ROWID == 4 FROM configs"
                  " WHERE name = 'Full and very deep ultimate';"))
    {
      /* Any predefined configs are OK.  Move any other configs that have the
       * predefined ID's. */

      /* The ID of the moved config may be only one larger, so these must
       * be done in ID order. */
      migrate_5_to_6_move_other_config ("Full and fast", 1);
      migrate_5_to_6_move_other_config ("Full and fast ultimate", 2);
      migrate_5_to_6_move_other_config ("Full and very deep", 3);
      migrate_5_to_6_move_other_config ("Full and very deep ultimate", 4);
    }
  else
    {
      g_warning ("%s: a predefined config has moved from the standard location,"
                 " giving up\n",
                 __FUNCTION__);
      sql ("ROLLBACK;");
      return -1;
    }

  /* This would need a duplicate version of update_all_config_caches that
   * worked with the version 6 database.  Just let the cache be wrong.  This
   * is a very old version now. */
#if 0
  /* Update cache counts for growing configs. */

  update_all_config_caches ();
#endif

  /* Set the database version to 6. */

  set_db_version (6);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 6 to version 7.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_6_to_7 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 6. */

  if (manage_db_version () != 6)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Add lsc_credential column to targets table. */
  sql ("ALTER TABLE targets ADD COLUMN lsc_credential INTEGER;");
  sql ("UPDATE targets SET lsc_credential = 0;");

  /* Set the database version to 7. */

  set_db_version (7);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 7 to version 8.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_7_to_8 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 7. */

  if (manage_db_version () != 7)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The lsc_credentials table got a login column. */

  sql ("ALTER TABLE lsc_credentials ADD COLUMN login;");
  sql ("UPDATE lsc_credentials SET login = name;");

  /* Set the database version to 8. */

  set_db_version (8);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 8 to version 9.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_8_to_9 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 8. */

  if (manage_db_version () != 8)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /** @todo Does ROLLBACK happen when these fail? */

  /* Ensure that all tables that will be modified here exist.  These were
   * all added after version 8 anyway. */

  sql ("CREATE TABLE IF NOT EXISTS escalators"
       " (id INTEGER PRIMARY KEY, name UNIQUE, comment, event INTEGER,"
       "  condition INTEGER, method INTEGER);");

  sql ("CREATE TABLE IF NOT EXISTS agents"
       " (id INTEGER PRIMARY KEY, name UNIQUE, comment, installer TEXT,"
       "  howto_install TEXT, howto_use TEXT);");

  /* Many tables got an owner column. */

  sql ("ALTER TABLE targets ADD COLUMN owner INTEGER;");
  sql ("UPDATE targets SET owner = NULL;");

  sql ("ALTER TABLE configs ADD COLUMN owner INTEGER;");
  sql ("UPDATE configs SET owner = NULL;");

  sql ("ALTER TABLE lsc_credentials ADD COLUMN owner INTEGER;");
  sql ("UPDATE lsc_credentials SET owner = NULL;");

  sql ("ALTER TABLE escalators ADD COLUMN owner INTEGER;");
  sql ("UPDATE escalators SET owner = NULL;");

  sql ("ALTER TABLE reports ADD COLUMN owner INTEGER;");
  sql ("UPDATE reports SET owner = NULL;");

  sql ("ALTER TABLE agents ADD COLUMN owner INTEGER;");
  sql ("UPDATE agents SET owner = NULL;");

  /* The owner column in tasks changed type from string to int.  This
   * may be a redundant conversion, as SQLite may have converted these
   * values automatically in each query anyway. */

  sql ("UPDATE tasks SET owner = CAST (owner AS INTEGER);"),

  /* Set the database version to 9. */

  set_db_version (9);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 9 to version 10.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_9_to_10 ()
{
  iterator_t rows;

  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 9. */

  if (manage_db_version () != 9)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The user table got a unique "uuid" column and lost the
   * uniqueness of its "name" column. */

  /** @todo ROLLBACK on failure. */

  sql ("ALTER TABLE users RENAME TO users_9;");

  sql ("CREATE TABLE users"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, name, password);");

  init_iterator (&rows, "SELECT rowid, name, password FROM users_9;");
  while (next (&rows))
    {
      gchar *quoted_name, *quoted_password, *uuid;

      uuid = openvas_user_uuid (iterator_string (&rows, 1));
      if (uuid == NULL)
        {
          uuid = openvas_uuid_make ();
          if (uuid == NULL)
            {
              cleanup_iterator (&rows);
              sql ("ROLLBACK;");
              return -1;
            }
        }

      quoted_name = sql_insert (iterator_string (&rows, 1));
      quoted_password = sql_insert (iterator_string (&rows, 2));
      sql ("INSERT into users (id, uuid, name, password)"
           " VALUES (%llu, '%s', %s, %s);",
           iterator_int64 (&rows, 0),
           uuid,
           quoted_name,
           quoted_password);
      g_free (uuid);
      g_free (quoted_name);
      g_free (quoted_password);
    }
  cleanup_iterator (&rows);
  sql ("DROP TABLE users_9;");

  /* Set the database version to 10. */

  set_db_version (10);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 10 to version 11.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_10_to_11 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 10. */

  if (manage_db_version () != 10)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The config and target columns of the tasks table changed from the name
   * of the config/target to the ROWID of the config/target.
   *
   * Recreate the table, in order to add INTEGER to the column definitions. */

  /** @todo ROLLBACK on failure. */

  sql ("ALTER TABLE tasks RENAME TO tasks_10;");

  sql ("CREATE TABLE tasks"
       " (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, hidden INTEGER,"
       "  time, comment, description, run_status INTEGER, start_time,"
       "  end_time, config INTEGER, target INTEGER);");

  sql ("INSERT into tasks"
       " (id, uuid, owner, name, hidden, time, comment, description,"
       "  run_status, start_time, end_time, config, target)"
       " SELECT"
       "  id, uuid, owner, name, hidden, time, comment, description,"
       "  run_status, start_time, end_time,"
       "  (SELECT ROWID FROM configs WHERE configs.name = tasks_10.config),"
       "  (SELECT ROWID FROM targets WHERE targets.name = tasks_10.target)"
       " FROM tasks_10;");

  sql ("DROP TABLE tasks_10;");

  /* Set the database version to 11. */

  set_db_version (11);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 11 to version 12.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_11_to_12 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 11. */

  if (manage_db_version () != 11)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Tables agents, configs and escalators were relieved of the UNIQUE
   * constraint on the name column.
   *
   * Recreate the tables, in order to remove the contraint. */

  /** @todo ROLLBACK on failure. */

  sql ("ALTER TABLE agents RENAME TO agents_11;");

  sql ("CREATE TABLE agents"
       " (id INTEGER PRIMARY KEY, owner INTEGER, name, comment,"
       "  installer TEXT, howto_install TEXT, howto_use TEXT);");

  sql ("INSERT into agents"
       " (id, owner, name, comment, installer, howto_install, howto_use)"
       " SELECT"
       "  id, owner, name, comment, installer, howto_install, howto_use"
       " FROM agents_11;");

  sql ("DROP TABLE agents_11;");

  sql ("ALTER TABLE configs RENAME TO configs_11;");

  sql ("CREATE TABLE configs"
       " (id INTEGER PRIMARY KEY, owner INTEGER, name, nvt_selector, comment,"
       "  family_count INTEGER, nvt_count INTEGER, families_growing INTEGER,"
       "  nvts_growing INTEGER);");

  sql ("INSERT into configs"
       " (id, owner, name, nvt_selector, comment, family_count, nvt_count,"
       "  families_growing, nvts_growing)"
       " SELECT"
       "  id, owner, name, nvt_selector, comment, family_count, nvt_count,"
       "  families_growing, nvts_growing"
       " FROM configs_11;");

  sql ("DROP TABLE configs_11;");

  sql ("ALTER TABLE escalators RENAME TO escalators_11;");

  sql ("CREATE TABLE escalators"
       " (id INTEGER PRIMARY KEY, owner INTEGER, name, comment, event INTEGER,"
       "  condition INTEGER, method INTEGER);");

  sql ("INSERT into escalators"
       " (id, owner, name, comment, event, condition, method)"
       " SELECT"
       "  id, owner, name, comment, event, condition, method"
       " FROM escalators_11;");

  sql ("DROP TABLE escalators_11;");

  /* Set the database version to 12. */

  set_db_version (12);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 12 to version 13.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_12_to_13 ()
{
  iterator_t rows;

  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 12. */

  if (manage_db_version () != 12)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Table nvt_selectors column name changed to a UUID.
   *
   * Replace names with UUIDs, ensuring that the 'All' selector gets the
   * predefined UUID. */

  /** @todo ROLLBACK on failure. */

  init_iterator (&rows, "SELECT distinct name FROM nvt_selectors;");
  while (next (&rows))
    {
      gchar *quoted_name, *uuid;

      if (strcmp (iterator_string (&rows, 0), "All") == 0)
        continue;

      uuid = openvas_uuid_make ();
      if (uuid == NULL)
        {
          cleanup_iterator (&rows);
          sql ("ROLLBACK;");
          return -1;
        }

      quoted_name = sql_insert (iterator_string (&rows, 0));

      sql ("UPDATE nvt_selectors SET name = '%s' WHERE name = %s;",
           uuid,
           quoted_name);

      sql ("UPDATE configs SET nvt_selector = '%s' WHERE nvt_selector = %s;",
           uuid,
           quoted_name);

      g_free (uuid);
      g_free (quoted_name);
    }
  cleanup_iterator (&rows);

  if (sql_int (0, 0,
               "SELECT COUNT(*) FROM nvt_selectors WHERE name = '"
               MANAGE_NVT_SELECTOR_UUID_ALL "';"))
    sql ("DELETE FROM nvt_selectors WHERE name = 'All';");
  else
    sql ("UPDATE nvt_selectors"
         " SET name = '" MANAGE_NVT_SELECTOR_UUID_ALL "'"
         " WHERE name = 'All';");

  sql ("UPDATE configs"
       " SET nvt_selector = '" MANAGE_NVT_SELECTOR_UUID_ALL "'"
       " WHERE nvt_selector = 'All';");

  /* Set the database version to 13. */

  set_db_version (13);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 13 to version 14.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_13_to_14 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 13. */

  if (manage_db_version () != 13)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Table results got a UUID column. */

  /** @todo ROLLBACK on failure. */

  sql ("ALTER TABLE results ADD COLUMN uuid;");
  sql ("UPDATE results SET uuid = make_uuid();");

  /* Set the database version to 14. */

  set_db_version (14);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 14 to version 15.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_14_to_15 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 14. */

  if (manage_db_version () != 14)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Table tasks got columns for scheduling info. */

  /** @todo ROLLBACK on failure. */

  sql ("ALTER TABLE tasks ADD COLUMN schedule INTEGER;");
  sql ("ALTER TABLE tasks ADD COLUMN schedule_next_time;");
  sql ("UPDATE tasks SET schedule = 0, schedule_next_time = 0;");

  /* Set the database version to 15. */

  set_db_version (15);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 15 to version 16.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_15_to_16 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 15. */

  if (manage_db_version () != 15)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Table schedules got a period_months column. */

  /** @todo ROLLBACK on failure. */

  sql ("CREATE TABLE IF NOT EXISTS schedules"
       " (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, comment,"
       "  first_time, period, duration);");

  sql ("ALTER TABLE schedules ADD COLUMN period_months;");
  sql ("UPDATE schedules SET period_months = 0;");

  /* GSA was hardcoded to set the comment to "comment" before revision 7157,
   * so clear all task comments here. */

  sql ("UPDATE tasks SET comment = '';");

  /* Set the database version to 16. */

  set_db_version (16);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 16 to version 17.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_16_to_17 ()
{
  iterator_t rows;

  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 16. */

  if (manage_db_version () != 16)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Table nvts got columns for CVSS base and risk factor. */

  /** @todo ROLLBACK on failure. */

  sql ("ALTER TABLE nvts ADD COLUMN cvss_base;");
  sql ("ALTER TABLE nvts ADD COLUMN risk_factor;");

  /* Move the CVSS and risk values out of any existing tags. */

  init_iterator (&rows, "SELECT ROWID, tag FROM nvts;");
  while (next (&rows))
    {
      gchar *tags, *cvss_base, *risk_factor;

      parse_tags (iterator_string (&rows, 1), &tags, &cvss_base, &risk_factor);

      sql ("UPDATE nvts SET cvss_base = '%s', risk_factor = '%s', tag = '%s'"
           " WHERE ROWID = %llu;",
           cvss_base ? cvss_base : "",
           risk_factor ? risk_factor : "",
           tags ? tags : "",
           iterator_int64 (&rows, 0));

      g_free (tags);
      g_free (cvss_base);
      g_free (risk_factor);
    }
  cleanup_iterator (&rows);

  /* Set the database version to 17. */

  set_db_version (17);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Set the pref for migrate_17_to_18.
 *
 * @param[in]  config  Config to set pref on.
 */
static void
migrate_17_to_18_set_pref (config_t config)
{
  if (sql_int (0, 0,
               "SELECT count(*) FROM config_preferences"
               " WHERE config = %llu"
               " AND name ="
               " 'Ping Host[checkbox]:Mark unrechable Hosts as dead"
               " (not scanning)'",
               config)
      == 0)
    sql ("INSERT into config_preferences (config, type, name, value)"
         " VALUES (%llu, 'PLUGINS_PREFS',"
         " 'Ping Host[checkbox]:Mark unrechable Hosts as dead (not scanning)',"
         " 'yes');",
         config);
}

/**
 * @brief Migrate the database from version 17 to version 18.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_17_to_18 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 17. */

  if (manage_db_version () != 17)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* NVT "Ping Host" was added to the predefined configs, with the
   * "Mark unrechable..." preference set to "yes". */

  /** @todo ROLLBACK on failure. */

  /* Add "Ping Host" to the "All" NVT selector. */

  if (sql_int (0, 0,
               "SELECT count(*) FROM nvt_selectors WHERE name ="
               " '" MANAGE_NVT_SELECTOR_UUID_ALL "'"
               " AND family_or_nvt = '1.3.6.1.4.1.25623.1.0.100315';")
      == 0)
    {
      sql ("INSERT into nvt_selectors"
           " (name, exclude, type, family_or_nvt, family)"
           " VALUES ('" MANAGE_NVT_SELECTOR_UUID_ALL "', 0, "
           G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
           /* OID of the "Ping Host" NVT. */
           " '1.3.6.1.4.1.25623.1.0.100315', 'Port scanners');");
    }

  /* Ensure the preference is set on the predefined configs. */

  migrate_17_to_18_set_pref (CONFIG_ID_FULL_AND_FAST);
  migrate_17_to_18_set_pref (CONFIG_ID_FULL_AND_FAST_ULTIMATE);
  migrate_17_to_18_set_pref (CONFIG_ID_FULL_AND_VERY_DEEP);
  migrate_17_to_18_set_pref (CONFIG_ID_FULL_AND_VERY_DEEP_ULTIMATE);

  /* Set the database version to 18. */

  set_db_version (18);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 18 to version 19.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_18_to_19 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 18. */

  if (manage_db_version () != 18)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Many tables got a unique UUID column.  As a result the predefined
   * configs and target got fixed UUIDs.
   *
   * Recreate the tables, in order to add the unique contraint. */

  /** @todo ROLLBACK on failure. */

  sql ("ALTER TABLE agents RENAME TO agents_18;");

  sql ("CREATE TABLE agents"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  installer TEXT, howto_install TEXT, howto_use TEXT);");

  sql ("INSERT into agents"
       " (id, uuid, owner, name, comment, installer, howto_install, howto_use)"
       " SELECT"
       "  id, make_uuid (), owner, name, comment, installer, howto_install, howto_use"
       " FROM agents_18;");

  sql ("DROP TABLE agents_18;");

  sql ("ALTER TABLE configs RENAME TO configs_18;");

  sql ("CREATE TABLE configs"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name,"
       "  nvt_selector, comment, family_count INTEGER, nvt_count INTEGER,"
       "  families_growing INTEGER, nvts_growing INTEGER);");

  sql ("INSERT into configs"
       " (id, uuid, owner, name, nvt_selector, comment, family_count,"
       "  nvt_count, families_growing, nvts_growing)"
       " SELECT"
       "  id, make_uuid (), owner, name, nvt_selector, comment, family_count,"
       "  nvt_count, families_growing, nvts_growing"
       " FROM configs_18;");

  sql ("DROP TABLE configs_18;");

  sql ("ALTER TABLE escalators RENAME TO escalators_18;");

  sql ("CREATE TABLE escalators"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  event INTEGER, condition INTEGER, method INTEGER);");

  sql ("INSERT into escalators"
       " (id, uuid, owner, name, comment, event, condition, method)"
       " SELECT"
       "  id, make_uuid (), owner, name, comment, event, condition, method"
       " FROM escalators_18;");

  sql ("DROP TABLE escalators_18;");

  sql ("ALTER TABLE lsc_credentials RENAME TO lsc_credentials_18;");

  sql ("CREATE TABLE lsc_credentials"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, login,"
       "  password, comment, public_key TEXT, private_key TEXT, rpm TEXT,"
       "  deb TEXT, exe TEXT);");

  sql ("INSERT into lsc_credentials"
       " (id, uuid, owner, name, login, password, comment, public_key,"
       "  private_key, rpm, deb, exe)"
       " SELECT"
       "  id, make_uuid (), owner, name, login, password, comment, public_key,"
       "  private_key, rpm, deb, exe"
       " FROM lsc_credentials_18;");

  sql ("DROP TABLE lsc_credentials_18;");

  sql ("ALTER TABLE targets RENAME TO targets_18;");

  sql ("CREATE TABLE targets"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, hosts,"
       "  comment, lsc_credential INTEGER);");

  sql ("INSERT into targets"
       " (id, uuid, owner, name, hosts, comment, lsc_credential)"
       " SELECT"
       "  id, make_uuid (), owner, name, hosts, comment, lsc_credential"
       " FROM targets_18;");

  sql ("DROP TABLE targets_18;");

  /* Set the new predefined UUIDs. */

  sql ("UPDATE configs"
       " SET uuid = '" CONFIG_UUID_FULL_AND_FAST "'"
       " WHERE ROWID = " G_STRINGIFY (CONFIG_ID_FULL_AND_FAST) ";");

  sql ("UPDATE configs"
       " SET uuid = '" CONFIG_UUID_FULL_AND_FAST_ULTIMATE "'"
       " WHERE ROWID = " G_STRINGIFY (CONFIG_ID_FULL_AND_FAST_ULTIMATE) ";");

  sql ("UPDATE configs"
       " SET uuid = '" CONFIG_UUID_FULL_AND_VERY_DEEP "'"
       " WHERE ROWID = " G_STRINGIFY (CONFIG_ID_FULL_AND_VERY_DEEP) ";");

  sql ("UPDATE configs"
       " SET uuid = '" CONFIG_UUID_FULL_AND_VERY_DEEP_ULTIMATE "'"
       " WHERE ROWID = "
       G_STRINGIFY (CONFIG_ID_FULL_AND_VERY_DEEP_ULTIMATE) ";");

  sql ("UPDATE configs"
       " SET uuid = '" CONFIG_UUID_EMPTY "'"
       " WHERE name = 'empty';");

  sql ("UPDATE targets"
       " SET uuid = '" TARGET_UUID_LOCALHOST "'"
       " WHERE name = 'Localhost';");

  /* Set the database version to 19. */

  set_db_version (19);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 19 to version 20.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_19_to_20 ()
{
  iterator_t rows;

  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 19. */

  if (manage_db_version () != 19)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The agents table got new columns.  In particular the installer column
   * moved to installer_64 and the table got a new installer column with the
   * plain installer. */

  /** @todo ROLLBACK on failure. */

  sql ("ALTER TABLE agents ADD COLUMN installer_64 TEXT;");
  sql ("ALTER TABLE agents ADD COLUMN installer_signature_64 TEXT;");
  sql ("ALTER TABLE agents ADD COLUMN installer_trust INTEGER;");

  init_iterator (&rows, "SELECT ROWID, installer FROM agents;");
  while (next (&rows))
    {
      const char *tail, *installer_64 = iterator_string (&rows, 1);
      gchar *installer, *formatted;
      gsize installer_size;
      int ret;
      sqlite3_stmt* stmt;

      sql ("UPDATE agents SET"
           " installer_trust = %i,"
           " installer_64 = installer,"
           " installer_signature_64 = ''"
           " WHERE ROWID = %llu",
           TRUST_UNKNOWN,
           iterator_int64 (&rows, 0));

      formatted = g_strdup_printf ("UPDATE agents SET installer = $installer"
                                   " WHERE ROWID = %llu;",
                                   iterator_int64 (&rows, 0));

      /* Prepare statement. */

      while (1)
        {
          ret = sqlite3_prepare (task_db, (char*) formatted, -1, &stmt, &tail);
          if (ret == SQLITE_BUSY) continue;
          g_free (formatted);
          if (ret == SQLITE_OK)
            {
              if (stmt == NULL)
                {
                  g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s\n",
                             __FUNCTION__,
                             sqlite3_errmsg (task_db));
                  cleanup_iterator (&rows);
                  sql ("ROLLBACK;");
                  return -1;
                }
              break;
            }
          g_warning ("%s: sqlite3_prepare failed: %s\n",
                     __FUNCTION__,
                     sqlite3_errmsg (task_db));
          cleanup_iterator (&rows);
          sql ("ROLLBACK;");
          return -1;
        }

      if (strlen (installer_64) > 0)
        installer = (gchar*) g_base64_decode (installer_64, &installer_size);
      else
        installer = g_strdup ("");

      /* Bind the packages to the "$values" in the SQL statement. */

      while (1)
        {
          ret = sqlite3_bind_text (stmt,
                                   1,
                                   installer,
                                   installer_size,
                                   SQLITE_TRANSIENT);
          if (ret == SQLITE_BUSY) continue;
          if (ret == SQLITE_OK) break;
          g_warning ("%s: sqlite3_prepare failed: %s\n",
                     __FUNCTION__,
                     sqlite3_errmsg (task_db));
          cleanup_iterator (&rows);
          sql ("ROLLBACK;");
          g_free (installer);
          return -1;
        }
      g_free (installer);

      /* Run the statement. */

      while (1)
        {
          ret = sqlite3_step (stmt);
          if (ret == SQLITE_BUSY) continue;
          if (ret == SQLITE_DONE) break;
          if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
            {
              if (ret == SQLITE_ERROR) ret = sqlite3_reset (stmt);
              g_warning ("%s: sqlite3_step failed: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              cleanup_iterator (&rows);
              sql ("ROLLBACK;");
              return -1;
            }
        }

      sqlite3_finalize (stmt);
    }
  cleanup_iterator (&rows);

  /* Set the database version to 20. */

  set_db_version (20);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 20 to version 21.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_20_to_21 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 20. */

  if (manage_db_version () != 20)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The agents table got an installer_filename columns. */

  /** @todo ROLLBACK on failure. */

  sql ("ALTER TABLE agents ADD COLUMN installer_filename TEXT;");

  /* Set the database version to 21. */

  set_db_version (21);

  sql ("COMMIT;");

  return 0;
}

/** @todo Defined in omp.c! */
int file_utils_rmdir_rf (const gchar *);

/**
 * @brief Migrate the report formats from version 21 to version 22.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_21_to_22 ()
{
  iterator_t rows;

  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 21. */

  if (manage_db_version () != 21)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the report formats.
   *
   * The name of the report format directories on disk changed from the report
   * format name to the report format UUID. */

  /** @todo ROLLBACK on failure. */

  /* Ensure that the report_formats table exists. */

  sql ("CREATE TABLE IF NOT EXISTS report_formats"
       " (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, extension,"
       "  content_type, summary, description);");

  /* Ensure that the predefined formats all exist in the database. */

  if (sql_int (0, 0, "SELECT count(*) FROM report_formats WHERE name = 'CPE';")
      == 0)
    sql ("INSERT into report_formats (uuid, owner, name, summary, description,"
         " extension, content_type)"
         " VALUES (make_uuid (), NULL, 'CPE',"
         " 'Common Product Enumeration CSV table.',"
         " 'CPE stands for Common Product Enumeration.  It is a structured naming scheme for\n"
         "information technology systems, platforms, and packages.  In other words: CPE\n"
         "provides a unique identifier for virtually any software product that is known for\n"
         "a vulnerability.\n"
         "\n"
         "The CPE dictionary is maintained by MITRE and NIST.  MITRE also maintains CVE\n"
         "(Common Vulnerability Enumeration) and other relevant security standards.\n"
         "\n"
         "The report selects all CPE tables from the results and forms a single table\n"
         "as a comma separated values file.\n',"
         " 'csv', 'text/csv');");

  if (sql_int (0, 0, "SELECT count(*) FROM report_formats WHERE name = 'HTML';")
      == 0)
    sql ("INSERT into report_formats (uuid, owner, name, summary, description,"
         " extension, content_type)"
         " VALUES (make_uuid (), NULL, 'HTML', 'Single page HTML report.',"
         " 'A single HTML page listing results of a scan.  Style information is embedded in\n"
         "the HTML, so the page is suitable for viewing in a browser as is.\n',"
         " 'html', 'text/html');");

  if (sql_int (0, 0, "SELECT count(*) FROM report_formats WHERE name = 'ITG';")
      == 0)
    sql ("INSERT into report_formats (uuid, owner, name, summary, description,"
         " extension, content_type)"
         " VALUES (make_uuid (), NULL, 'ITG',"
         " 'German \"IT-Grundschutz-Kataloge\" report.',"
         " 'Tabular report on the German \"IT-Grundschutz-Kataloge\",\n"
         "as published and maintained by the German Federal Agency for IT-Security.\n',"
         " 'csv', 'text/csv');");

  if (sql_int (0, 0, "SELECT count(*) FROM report_formats WHERE name = 'LaTeX';")
      == 0)
    sql ("INSERT into report_formats (uuid, owner, name, summary, description,"
         " extension, content_type)"
         " VALUES (make_uuid (), NULL, 'LaTeX',"
         " 'LaTeX source file.',"
         " 'Report as LaTeX source file for further processing.\n',"
         " 'tex', 'text/plain');");

  if (sql_int (0, 0, "SELECT count(*) FROM report_formats WHERE name = 'NBE';")
      == 0)
    sql ("INSERT into report_formats (uuid, owner, name, summary, description,"
         " extension, content_type)"
         " VALUES (make_uuid (), NULL, 'NBE', 'Legacy OpenVAS report.',"
         " 'The traditional OpenVAS Scanner text based format.',"
         " 'nbe', 'text/plain');");

  if (sql_int (0, 0, "SELECT count(*) FROM report_formats WHERE name = 'PDF';")
      == 0)
    sql ("INSERT into report_formats (uuid, owner, name, summary, description,"
         " extension, content_type)"
         " VALUES (make_uuid (), NULL, 'PDF',"
         " 'Portable Document Format report.',"
         " 'Scan results in Portable Document Format (PDF).',"
         "'pdf', 'application/pdf');");

  if (sql_int (0, 0, "SELECT count(*) FROM report_formats WHERE name = 'TXT';")
      == 0)
    sql ("INSERT into report_formats (uuid, owner, name, summary, description,"
         " extension, content_type)"
         " VALUES (make_uuid (), NULL, 'TXT', 'Plain text report.',"
         " 'Plain text report, best viewed with fixed font size.',"
         " 'txt', 'text/plain');");

  if (sql_int (0, 0, "SELECT count(*) FROM report_formats WHERE name = 'XML';")
      == 0)
    sql ("INSERT into report_formats (uuid, owner, name, summary, description,"
         " extension, content_type)"
         " VALUES (make_uuid (), NULL, 'XML',"
         " 'Raw XML report.',"
         " 'Complete scan report in OpenVAS Manager XML format.',"
         " 'xml', 'text/xml');");

  /* Update the UUIDs of the predefined formats to the new predefined UUIDs. */

  sql ("UPDATE report_formats SET uuid = 'a0704abb-2120-489f-959f-251c9f4ffebd'"
       " WHERE name = 'CPE'");

  sql ("UPDATE report_formats SET uuid = 'b993b6f5-f9fb-4e6e-9c94-dd46c00e058d'"
       " WHERE name = 'HTML'");

  sql ("UPDATE report_formats SET uuid = '929884c6-c2c4-41e7-befb-2f6aa163b458'"
       " WHERE name = 'ITG'");

  sql ("UPDATE report_formats SET uuid = '9f1ab17b-aaaa-411a-8c57-12df446f5588'"
       " WHERE name = 'LaTeX'");

  sql ("UPDATE report_formats SET uuid = 'f5c2a364-47d2-4700-b21d-0a7693daddab'"
       " WHERE name = 'NBE'");

  sql ("UPDATE report_formats SET uuid = '1a60a67e-97d0-4cbf-bc77-f71b08e7043d'"
       " WHERE name = 'PDF'");

  sql ("UPDATE report_formats SET uuid = '19f6f1b3-7128-4433-888c-ccc764fe6ed5'"
       " WHERE name = 'TXT'");

  sql ("UPDATE report_formats SET uuid = 'd5da9f67-8551-4e51-807b-b6a873d70e34'"
       " WHERE name = 'XML'");

  /* Rename the directories. */

  init_iterator (&rows, "SELECT ROWID, uuid, owner, name FROM report_formats;");
  while (next (&rows))
    {
      const char *name, *uuid;
      gchar *old_dir, *new_dir;

      uuid = iterator_string (&rows, 1);
      name = iterator_string (&rows, 3);

      if (sql_int (0, 0,
                   "SELECT owner is NULL FROM report_formats"
                   " WHERE ROWID = %llu;",
                   iterator_int64 (&rows, 0)))
        {
          /* Global. */
          old_dir = g_build_filename (OPENVAS_SYSCONF_DIR,
                                      "openvasmd",
                                      "global_report_formats",
                                      name,
                                      NULL);
          new_dir = g_build_filename (OPENVAS_SYSCONF_DIR,
                                      "openvasmd",
                                      "global_report_formats",
                                      uuid,
                                      NULL);
        }
      else
        {
          char *owner_uuid;
          owner_uuid = sql_string (0, 0,
                                   "SELECT uuid FROM users"
                                   " WHERE ROWID = %llu;",
                                   iterator_int64 (&rows, 2));
          if (owner_uuid == NULL)
            {
              g_warning ("%s: owner missing from users table\n", __FUNCTION__);
              cleanup_iterator (&rows);
              sql ("ROLLBACK;");
              return -1;
            }
          old_dir = g_build_filename (OPENVAS_SYSCONF_DIR,
                                      "openvasmd",
                                      "report_formats",
                                      owner_uuid,
                                      name,
                                      NULL);
          new_dir = g_build_filename (OPENVAS_SYSCONF_DIR,
                                      "openvasmd",
                                      "report_formats",
                                      owner_uuid,
                                      uuid,
                                      NULL);
          free (owner_uuid);
        }
      if (g_file_test (new_dir, G_FILE_TEST_EXISTS))
        {
          if (g_file_test (old_dir, G_FILE_TEST_EXISTS)
              && file_utils_rmdir_rf (old_dir))
            g_warning ("%s: failed to remove %s\n",
                       __FUNCTION__,
                       old_dir);
        }
      else if (rename (old_dir, new_dir))
        {
          g_warning ("%s: renaming %s to %s failed: %s\n",
                     __FUNCTION__,
                     old_dir,
                     new_dir,
                     strerror (errno));
          g_free (old_dir);
          g_free (new_dir);
          cleanup_iterator (&rows);
          sql ("ROLLBACK;");
          return -1;
        }
      g_free (old_dir);
      g_free (new_dir);
    }

  /* Set the database version to 22. */

  set_db_version (22);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the report formats from version 22 to version 23.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_22_to_23 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 22. */

  if (manage_db_version () != 22)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the report formats.
   *
   * The report_formats table got signature and trust columns. */

  /** @todo ROLLBACK on failure. */

  sql ("ALTER TABLE report_formats ADD COLUMN signature;");
  sql ("UPDATE report_formats SET signature = '';");

  sql ("ALTER TABLE report_formats ADD COLUMN trust;");
  sql ("UPDATE report_formats SET trust = %i;", TRUST_UNKNOWN);

  /* Set the database version to 23. */

  set_db_version (23);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 23 to version 24.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_23_to_24 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 23. */

  if (manage_db_version () != 23)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The 8 to 9 migrator cast owner to an integer because owner had
   * changed from a string to an integer.  This means empty strings would
   * be converted to 0 instead of NULL, so convert any 0's to NULL. */

  sql ("UPDATE tasks SET owner = NULL where owner = 0;"),

  /* Set the database version to 24. */

  set_db_version (24);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 24 to version 25.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_24_to_25 ()
{
  iterator_t rows;

  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 24. */

  if (manage_db_version () != 24)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Missing parameter chunking handling in the GSA may have resulted in
   * empty options in NVT radio preference values. */

  init_iterator (&rows, "SELECT ROWID, name, value FROM nvt_preferences;");
  while (next (&rows))
    {
      const char *name;
      int type_start = -1, type_end = -1, count;

      name = iterator_string (&rows, 1);

      /* NVT[radio]:Preference */
      count = sscanf (name, "%*[^[][%nradio%n]:", &type_start, &type_end);
      if (count == 0 && type_start > 0 && type_end > 0)
        {
          const char *value;
          gchar **split, **point, *quoted_value;
          GString *string;
          gboolean first;

          /* Flush any empty options (";a;;b;" becomes "a;b"). */
          first = TRUE;
          value = iterator_string (&rows, 2);
          split = g_strsplit (value, ";", 0);
          string = g_string_new ("");
          point = split;
          while (*point)
            {
              if (strlen (*point))
                {
                  if (first)
                    first = FALSE;
                  else
                    g_string_append_c (string, ';');
                  g_string_append (string, *point);
                }
              point++;
            }
          g_strfreev (split);

          quoted_value = sql_nquote (string->str, string->len);
          g_string_free (string, TRUE);
          sql ("UPDATE nvt_preferences SET value = '%s' WHERE ROWID = %llu",
               quoted_value,
               iterator_int64 (&rows, 0));
          g_free (quoted_value);
        }
    }
  cleanup_iterator (&rows);

  init_iterator (&rows,
                 "SELECT ROWID, name, value FROM config_preferences"
                 " WHERE type = 'PLUGINS_PREFS';");
  while (next (&rows))
    {
      const char *name;
      int type_start = -1, type_end = -1, count;

      name = iterator_string (&rows, 1);

      /* NVT[radio]:Preference */
      count = sscanf (name, "%*[^[][%nradio%n]:", &type_start, &type_end);
      if (count == 0 && type_start > 0 && type_end > 0)
        {
          const char *value;
          gchar **split, **point, *quoted_value;
          GString *string;
          gboolean first;

          /* Flush any empty options (";a;;b;" becomes "a;b"). */
          first = TRUE;
          value = iterator_string (&rows, 2);
          split = g_strsplit (value, ";", 0);
          string = g_string_new ("");
          point = split;
          while (*point)
            {
              if (strlen (*point))
                {
                  if (first)
                    first = FALSE;
                  else
                    g_string_append_c (string, ';');
                  g_string_append (string, *point);
                }
              point++;
            }
          g_strfreev (split);

          quoted_value = sql_nquote (string->str, string->len);
          g_string_free (string, TRUE);
          sql ("UPDATE config_preferences SET value = '%s' WHERE ROWID = %llu",
               quoted_value,
               iterator_int64 (&rows, 0));
          g_free (quoted_value);
        }
    }
  cleanup_iterator (&rows);

  /* Set the database version to 25. */

  set_db_version (25);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 25 to version 26.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_25_to_26 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 25. */

  if (manage_db_version () != 25)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The report_formats table got a trust_time column. */

  sql ("ALTER TABLE report_formats ADD column trust_time;");
  sql ("UPDATE report_formats SET trust_time = %i;", time (NULL));

  /* Set the database version to 26. */

  set_db_version (26);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 26 to version 27.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_26_to_27 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 26. */

  if (manage_db_version () != 26)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The reports table got a slave_progress column and the tasks table got a
   * slave column. */

  sql ("ALTER TABLE reports ADD column slave_progress;");
  sql ("UPDATE reports SET slave_progress = 0;");

  sql ("ALTER TABLE tasks ADD column slave;");
  sql ("UPDATE tasks SET slave = 0;");

  /* Set the database version to 27. */

  set_db_version (27);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 27 to version 28.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_27_to_28 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 27. */

  if (manage_db_version () != 27)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The report_formats table got a flags column. */

  sql ("ALTER TABLE report_formats ADD COLUMN flags INTEGER;");
  sql ("UPDATE report_formats SET flags = 1;");

  /* Set the database version to 28. */

  set_db_version (28);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 27 to version 28.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_28_to_29 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 28. */

  if (manage_db_version () != 28)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The reports table got a slave_task_uuid column. */

  sql ("ALTER TABLE reports ADD COLUMN slave_task_uuid;");
  sql ("UPDATE reports SET slave_task_uuid = ''");

  /* Set the database version to 29. */

  set_db_version (29);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 29 to version 30.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_29_to_30 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 29. */

  if (manage_db_version () != 29)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The agents table got an installer_trust_time column. */

  sql ("ALTER TABLE agents ADD column installer_trust_time;");
  sql ("UPDATE agents SET installer_trust_time = %i;", time (NULL));

  /* Set the database version to 30. */

  set_db_version (30);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 30 to version 31.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_30_to_31 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 30. */

  if (manage_db_version () != 30)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Slaves switched from being targets to being resources of their own.
   * Just clear any task slaves. */

  sql ("UPDATE tasks SET slave = 0;");

  /* Set the database version to 31. */

  set_db_version (31);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 31 to version 32.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_31_to_32 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 31. */

  if (manage_db_version () != 31)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* Ensure that the report_format_params table exists. */

  sql ("CREATE TABLE IF NOT EXISTS report_format_params"
       " (id INTEGER PRIMARY KEY, report_format, name, value);");

  /* The report_format_params table got a type column. */

  sql ("ALTER TABLE report_format_params ADD column type INTEGER;");
  sql ("UPDATE report_format_params SET type = 3;");

  /* Set the database version to 32. */

  set_db_version (32);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 32 to version 33.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_32_to_33 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 32. */

  if (manage_db_version () != 32)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The report_format_params table got a few new columns. */

  sql ("ALTER TABLE report_format_params ADD column type_min;");
  sql ("UPDATE report_format_params SET type_min = %lli;", LLONG_MIN);

  sql ("ALTER TABLE report_format_params ADD column type_max;");
  sql ("UPDATE report_format_params SET type_max = %lli;", LLONG_MAX);

  sql ("ALTER TABLE report_format_params ADD column type_regex;");
  sql ("UPDATE report_format_params SET type_regex = '';");

  sql ("ALTER TABLE report_format_params ADD column fallback;");
  sql ("UPDATE report_format_params SET fallback = value;");

  /* Set the database version to 33. */

  set_db_version (33);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Set the pref for migrate_33_to_34.
 *
 * @param[in]  config  Config to set pref on.
 */
static void
migrate_33_to_34_set_pref (config_t config)
{
  if (sql_int (0, 0,
               "SELECT count(*) FROM config_preferences"
               " WHERE config = %llu"
               " AND name ="
               " 'Login configurations[checkbox]:NTLMSSP';",
               config)
      == 0)
    sql ("INSERT into config_preferences (config, type, name, value)"
         " VALUES (%llu, 'PLUGINS_PREFS',"
         " 'Login configurations[checkbox]:NTLMSSP',"
         " 'yes');",
         config);
}

/**
 * @brief Migrate the database from version 33 to version 34.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_33_to_34 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 33. */

  if (manage_db_version () != 33)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The preference "NTLMSSP" was set to yes in the predefined configs. */

  /** @todo ROLLBACK on failure. */

  migrate_33_to_34_set_pref (CONFIG_ID_FULL_AND_FAST);
  migrate_33_to_34_set_pref (CONFIG_ID_FULL_AND_FAST_ULTIMATE);
  migrate_33_to_34_set_pref (CONFIG_ID_FULL_AND_VERY_DEEP);
  migrate_33_to_34_set_pref (CONFIG_ID_FULL_AND_VERY_DEEP_ULTIMATE);

  /* Set the database version to 34. */

  set_db_version (34);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 34 to version 35.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_34_to_35 ()
{
  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 34. */

  if (manage_db_version () != 34)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* The LSC credential element of the target resource was split into two
   * elements, for SSH and SMB. */

  /** @todo ROLLBACK on failure. */

  sql ("ALTER TABLE targets ADD column smb_lsc_credential;");
  sql ("UPDATE targets SET smb_lsc_credential = lsc_credential;");

  /* Set the database version to 35. */

  set_db_version (35);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Migrate the database from version 35 to version 36.
 *
 * @return 0 success, -1 error.
 */
static int
migrate_35_to_36 ()
{
  iterator_t tasks;
  char *scanner_range, *quoted_scanner_range;

  sql ("BEGIN EXCLUSIVE;");

  /* Ensure that the database is currently version 35. */

  if (manage_db_version () != 35)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /* Update the database. */

  /* For a time between 1.0.0 beta3 and 1.0.0 beta5 the Manager would create
   * the example task with name references to the target and config, instead
   * of ID references.  Correct this now. */

  sql ("UPDATE tasks SET"
       " target = (SELECT ROWID FROM configs WHERE name = 'Full and fast'),"
       " config = (SELECT ROWID FROM targets WHERE name = 'Localhost')"
       " WHERE uuid = '" MANAGE_EXAMPLE_TASK_UUID "';");

  /* Scanner preference "port_range" moved from config into target. */

  /** @todo ROLLBACK on failure. */

  sql ("ALTER TABLE targets ADD column port_range;");
  sql ("UPDATE targets SET port_range = NULL;");

  scanner_range = sql_string (0, 0,
                              "SELECT value FROM nvt_preferences"
                              " WHERE name = 'port_range'");
  if (scanner_range)
    {
      quoted_scanner_range = sql_quote (scanner_range);
      free (scanner_range);
    }
  else
    quoted_scanner_range = NULL;

  init_iterator (&tasks, "SELECT ROWID, target, config FROM tasks;");
  while (next (&tasks))
    {
      char *config_range, *quoted_config_range;
      target_t target;

      target = iterator_int64 (&tasks, 1);

      if (sql_int (0, 0,
                   "SELECT port_range IS NULL FROM targets WHERE ROWID = %llu;",
                   target)
          == 0)
        {
          gchar *name;

          /* Already used this target, use a copy of it. */

          name = sql_string (0, 0,
                             "SELECT name || ' Migration' FROM targets"
                             " WHERE ROWID = %llu;",
                             target);
          assert (name);
          target = duplicate_target (target, name);
          free (name);

          sql ("UPDATE tasks SET target = %llu WHERE ROWID = %llu",
               target,
               iterator_int64 (&tasks, 0));
        }

      config_range = sql_string (0, 0,
                                 "SELECT value FROM config_preferences"
                                 " WHERE config = %llu"
                                 " AND name = 'port_range';",
                                 iterator_int64 (&tasks, 2));

      if (config_range)
        {
          quoted_config_range = sql_quote (config_range);
          free (config_range);
        }
      else
        quoted_config_range = NULL;

      sql ("UPDATE targets SET port_range = '%s'"
           " WHERE ROWID = %llu;",
           quoted_config_range
            ? quoted_config_range
            : (quoted_scanner_range ? quoted_scanner_range : "default"),
           target);

      free (quoted_config_range);
    }
  cleanup_iterator (&tasks);

  sql ("UPDATE targets SET port_range = 'default' WHERE port_range IS NULL;");

  sql ("DELETE FROM config_preferences WHERE name = 'port_range';");
  sql ("DELETE FROM nvt_preferences WHERE name = 'port_range';");

  free (quoted_scanner_range);

  /* Set the database version to 36. */

  set_db_version (36);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Array of database version migrators.
 */
static migrator_t database_migrators[]
 = {{0, NULL},
    {1, migrate_0_to_1},
    {2, migrate_1_to_2},
    {3, migrate_2_to_3},
    {4, migrate_3_to_4},
    {5, migrate_4_to_5},
    {6, migrate_5_to_6},
    {7, migrate_6_to_7},
    {8, migrate_7_to_8},
    {9, migrate_8_to_9},
    {10, migrate_9_to_10},
    {11, migrate_10_to_11},
    {12, migrate_11_to_12},
    {13, migrate_12_to_13},
    {14, migrate_13_to_14},
    {15, migrate_14_to_15},
    {16, migrate_15_to_16},
    {17, migrate_16_to_17},
    {18, migrate_17_to_18},
    {19, migrate_18_to_19},
    {20, migrate_19_to_20},
    {21, migrate_20_to_21},
    {22, migrate_21_to_22},
    {23, migrate_22_to_23},
    {24, migrate_23_to_24},
    {25, migrate_24_to_25},
    {26, migrate_25_to_26},
    {27, migrate_26_to_27},
    {28, migrate_27_to_28},
    {29, migrate_28_to_29},
    {30, migrate_29_to_30},
    {31, migrate_30_to_31},
    {32, migrate_31_to_32},
    {33, migrate_32_to_33},
    {34, migrate_33_to_34},
    {35, migrate_34_to_35},
    {36, migrate_35_to_36},
    /* End marker. */
    {-1, NULL}};

/**
 * @brief Check whether a migration is available.
 *
 * @param[in]  old_version  Version to migrate from.
 * @param[in]  new_version  Version to migrate to.
 *
 * @return 1 yes, 0 no, -1 error.
 */
static int
migrate_is_available (int old_version, int new_version)
{
  migrator_t *migrators;

  migrators = database_migrators + old_version + 1;

  while ((migrators->version >= 0) && (migrators->version <= new_version))
    {
      if (migrators->function == NULL) return 0;
      if (migrators->version == new_version) return 1;
      migrators++;
    }

  return -1;
}

/**
 * @brief Migrate database to version supported by this manager.
 *
 * @param[in]  log_config  Log configuration.
 * @param[in]  database    Location of manage database.
 *
 * @return 0 success, 1 already on supported version, 2 too hard, -1 error.
 */
int
manage_migrate (GSList *log_config, const gchar *database)
{
  migrator_t *migrators;
  /* The version on the disk. */
  int old_version;
  /* The version that this program requires. */
  int new_version;

  g_log_set_handler (G_LOG_DOMAIN,
                     ALL_LOG_LEVELS,
                     (GLogFunc) openvas_log_func,
                     log_config);

  init_manage_process (0, database);

  old_version = manage_db_version ();
  new_version = manage_db_supported_version ();

  if (old_version == -1)
    {
      cleanup_manage_process (TRUE);
      return -1;
    }

  if (old_version == new_version)
    {
      cleanup_manage_process (TRUE);
      return 1;
    }

  switch (migrate_is_available (old_version, new_version))
    {
      case -1:
        cleanup_manage_process (TRUE);
        return -1;
      case  0:
        cleanup_manage_process (TRUE);
        return  2;
    }

  /* Call the migrators to take the DB from the old version to the new. */

  migrators = database_migrators + old_version + 1;

  while ((migrators->version >= 0) && (migrators->version <= new_version))
    {
      if (migrators->function == NULL)
        {
          cleanup_manage_process (TRUE);
          return -1;
        }

      tracef ("   Migrating to %i", migrators->version);

      if (migrators->function ())
        {
          cleanup_manage_process (TRUE);
          return -1;
        }
      migrators++;
    }

  cleanup_manage_process (TRUE);
  return 0;
}


/* Collation. */

/**
 * @brief Collate two message type strings.
 *
 * Callback for SQLite "collate_message_type" collation.
 *
 * A lower threat is considered less than a higher threat, so Medium is
 * less than High.
 *
 * @param[in]  data     Dummy for callback.
 * @param[in]  one_len  Length of first string.
 * @param[in]  arg_one  First string.
 * @param[in]  two_len  Length of second string.
 * @param[in]  arg_two  Second string.
 *
 * @return -1, 0 or 1 if first is less than, equal to or greater than second.
 */
int
collate_message_type (void* data,
                      int one_len, const void* arg_one,
                      int two_len, const void* arg_two)
{
  const char* one = (const char*) arg_one;
  const char* two = (const char*) arg_two;

  if (strncmp (one, "Security Hole", one_len) == 0)
    {
      if (strncmp (two, "Security Hole", two_len) == 0)
        return 0;
      return 1;
    }
  if (strncmp (two, "Security Hole", two_len) == 0) return -1;

  if (strncmp (one, "Security Warning", one_len) == 0)
    {
      if (strncmp (two, "Security Warning", two_len) == 0)
        return 0;
      return 1;
    }
  if (strncmp (two, "Security Warning", two_len) == 0) return -1;

  if (strncmp (one, "Security Note", one_len) == 0)
    {
      if (strncmp (two, "Security Note", two_len) == 0)
        return 0;
      return 1;
    }
  if (strncmp (two, "Security Note", two_len) == 0) return -1;

  if (strncmp (one, "Log Message", one_len) == 0)
    {
      if (strncmp (two, "Log Message", two_len) == 0)
        return 0;
      return 1;
    }
  if (strncmp (two, "Log Message", two_len) == 0) return -1;

  if (strncmp (one, "Debug Message", one_len) == 0)
    {
      if (strncmp (two, "Debug Message", two_len) == 0)
        return 0;
      return 1;
    }
  if (strncmp (two, "Debug Message", two_len) == 0) return -1;

  return strncmp (one, two, MIN (one_len, two_len));
}

/**
 * @brief Collate two threat levels.
 *
 * A lower threat is considered less than a higher threat, so Medium is
 * less than High.
 *
 * @param[in]  data     Dummy for callback.
 * @param[in]  one_len  Length of first string.
 * @param[in]  arg_one  First string.
 * @param[in]  two_len  Length of second string.
 * @param[in]  arg_two  Second string.
 *
 * @return -1, 0 or 1 if first is less than, equal to or greater than second.
 */
int
collate_threat (void* data,
                int one_len, const void* arg_one,
                int two_len, const void* arg_two)
{
  const char* one = (const char*) arg_one;
  const char* two = (const char*) arg_two;

  if (strncmp (one, "High", one_len) == 0)
    {
      if (strncmp (two, "High", two_len) == 0)
        return 0;
      return 1;
    }
  if (strncmp (two, "High", two_len) == 0) return -1;

  if (strncmp (one, "Medium", one_len) == 0)
    {
      if (strncmp (two, "Medium", two_len) == 0)
        return 0;
      return 1;
    }
  if (strncmp (two, "Medium", two_len) == 0) return -1;

  if (strncmp (one, "Low", one_len) == 0)
    {
      if (strncmp (two, "Low", two_len) == 0)
        return 0;
      return 1;
    }
  if (strncmp (two, "Low", two_len) == 0) return -1;

  if (strncmp (one, "Log", one_len) == 0)
    {
      if (strncmp (two, "Log", two_len) == 0)
        return 0;
      return 1;
    }
  if (strncmp (two, "Log", two_len) == 0) return -1;

  if (strncmp (one, "Debug", one_len) == 0)
    {
      if (strncmp (two, "Debug", two_len) == 0)
        return 0;
      return 1;
    }
  if (strncmp (two, "Debug", two_len) == 0) return -1;

  if (strncmp (one, "False Positive", one_len) == 0)
    {
      if (strncmp (two, "False Positive", two_len) == 0)
        return 0;
      return 1;
    }
  if (strncmp (two, "False Positive", two_len) == 0) return -1;

  return strncmp (one, two, MIN (one_len, two_len));
}

/**
 * @brief Compare two number strings for collate_ip.
 *
 * @param[in]  one_arg  First string.
 * @param[in]  two_arg  Second string.
 *
 * @return -1, 0 or 1 if first is less than, equal to or greater than second.
 */
static int
collate_ip_compare (const char *one_arg, const char *two_arg)
{
  int one = atoi (one_arg);
  int two = atoi (two_arg);
  return one == two ? 0 : (one < two ? -1 : 1);
}

/**
 * @brief Collate two IP addresses.
 *
 * For example, 127.0.0.2 is less than 127.0.0.3 and 127.0.0.10.
 *
 * Only works correctly for IPv4 addresses.
 *
 * @param[in]  data     Dummy for callback.
 * @param[in]  one_len  Length of first IP (a string).
 * @param[in]  arg_one  First string.
 * @param[in]  two_len  Length of second IP (a string).
 * @param[in]  arg_two  Second string.
 *
 * @return -1, 0 or 1 if first is less than, equal to or greater than second.
 */
int
collate_ip (void* data,
            int one_len, const void* arg_one,
            int two_len, const void* arg_two)
{
  int ret, one_dot, two_dot;
  char one_a[4], one_b[4], one_c[4], one_d[4];
  char two_a[4], two_b[4], two_c[4], two_d[4];
  const char* one = (const char*) arg_one;
  const char* two = (const char*) arg_two;

  if ((sscanf (one, "%3[0-9].%3[0-9].%3[0-9].%n%3[0-9]",
               one_a, one_b, one_c, &one_dot, one_d)
       == 4)
      && (sscanf (two, "%3[0-9].%3[0-9].%3[0-9].%n%3[0-9]",
                  two_a, two_b, two_c, &two_dot, two_d)
          == 4))
    {
      int ret = collate_ip_compare (one_a, two_a);
      if (ret) return ret < 0 ? -1 : 1;

      ret = collate_ip_compare (one_b, two_b);
      if (ret) return ret < 0 ? -1 : 1;

      ret = collate_ip_compare (one_c, two_c);
      if (ret) return ret < 0 ? -1 : 1;

      /* Ensure that the last number is limited to digits in the arg. */
      one_d[one_len - one_dot] = '\0';
      two_d[two_len - two_dot] = '\0';

      ret = collate_ip_compare (one_d, two_d);
      if (ret) return ret < 0 ? -1 : 1;

      return 0;
    }

  ret = strncmp (one, two, MIN (one_len, two_len));
  return ret == 0 ? 0 : (ret < 0 ? -1 : 1);
}


/* Events and Escalators. */

/**
 * @brief Find an escalator given a UUID.
 *
 * @param[in]   uuid       UUID of escalator.
 * @param[out]  escalator  Return.  0 if succesfully failed to find escalator.
 *
 * @return FALSE on success (including if failed to find escalator), TRUE on
 *         error.
 */
gboolean
find_escalator (const char* uuid, escalator_t* escalator)
{
  gchar *quoted_uuid = sql_quote (uuid);
  if (user_owns_uuid ("escalator", quoted_uuid) == 0)
    {
      g_free (quoted_uuid);
      *escalator = 0;
      return FALSE;
    }
  switch (sql_int64 (escalator, 0, 0,
                     "SELECT ROWID FROM escalators WHERE uuid = '%s';",
                     quoted_uuid))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *escalator = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        g_free (quoted_uuid);
        return TRUE;
        break;
    }
  g_free (quoted_uuid);
  return FALSE;
}

/**
 * @brief Create an escalator.
 *
 * @param[in]  name            Name of escalator.
 * @param[in]  comment         Comment on escalator.
 * @param[in]  event           Type of event.
 * @param[in]  event_data      Type-specific event data.
 * @param[in]  condition       Event condition.
 * @param[in]  condition_data  Condition-specific data.
 * @param[in]  method          Escalation method.
 * @param[in]  method_data     Data for escalation method.
 * @param[out] escalator       Created escalator on success.
 *
 * @return 0 success, 1 escalation exists already.
 */
int
create_escalator (const char* name, const char* comment,
                  event_t event, GPtrArray* event_data,
                  escalator_condition_t condition, GPtrArray* condition_data,
                  escalator_method_t method, GPtrArray* method_data,
                  escalator_t *escalator)
{
  int index;
  gchar *item, *quoted_comment;
  gchar *quoted_name = sql_quote (name);

  assert (current_credentials.uuid);

  sql ("BEGIN IMMEDIATE;");

  if (sql_int (0, 0,
               "SELECT COUNT(*) FROM escalators WHERE name = '%s'"
               " AND ((owner IS NULL) OR (owner ="
               " (SELECT users.ROWID FROM users WHERE users.uuid = '%s')));",
               quoted_name,
               current_credentials.uuid))
    {
      g_free (quoted_name);
      sql ("ROLLBACK;");
      return 1;
    }

  quoted_comment = comment ? sql_quote (comment) : NULL;

  sql ("INSERT INTO escalators (uuid, owner, name, comment, event, condition,"
       " method)"
       " VALUES (make_uuid (),"
       " (SELECT ROWID FROM users WHERE users.uuid = '%s'),"
       " '%s', '%s', %i, %i, %i);",
       current_credentials.uuid,
       quoted_name,
       quoted_comment ? quoted_comment : "",
       event,
       condition,
       method);

  *escalator = sqlite3_last_insert_rowid (task_db);

  index = 0;
  while ((item = (gchar*) g_ptr_array_index (condition_data, index++)))
    {
      gchar *name = sql_quote (item);
      gchar *data = sql_quote (item + strlen (item) + 1);
      sql ("INSERT INTO escalator_condition_data (escalator, name, data)"
           " VALUES (%llu, '%s', '%s');",
           *escalator,
           name,
           data);
      g_free (name);
      g_free (data);
    }

  index = 0;
  while ((item = (gchar*) g_ptr_array_index (event_data, index++)))
    {
      gchar *name = sql_quote (item);
      gchar *data = sql_quote (item + strlen (item) + 1);
      sql ("INSERT INTO escalator_event_data (escalator, name, data)"
           " VALUES (%llu, '%s', '%s');",
           *escalator,
           name,
           data);
      g_free (name);
      g_free (data);
    }

  index = 0;
  while ((item = (gchar*) g_ptr_array_index (method_data, index++)))
    {
      gchar *name = sql_quote (item);
      gchar *data = sql_quote (item + strlen (item) + 1);
      sql ("INSERT INTO escalator_method_data (escalator, name, data)"
           " VALUES (%llu, '%s', '%s');",
           *escalator,
           name,
           data);
      g_free (name);
      g_free (data);
    }

  g_free (quoted_comment);
  g_free (quoted_name);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Delete an escalator.
 *
 * @param[in]  escalator  Escalator.
 *
 * @return 0 success, 1 fail because a task refers to the escalator, -1 error.
 */
int
delete_escalator (escalator_t escalator)
{
  sql ("BEGIN IMMEDIATE;");
  if (sql_int (0, 0,
               "SELECT count(*) FROM task_escalators WHERE escalator = %llu;",
               escalator))
    {
      sql ("ROLLBACK;");
      return 1;
    }
  sql ("DELETE FROM escalator_condition_data WHERE escalator = %llu;",
       escalator);
  sql ("DELETE FROM escalator_event_data WHERE escalator = %llu;", escalator);
  sql ("DELETE FROM escalator_method_data WHERE escalator = %llu;", escalator);
  sql ("DELETE FROM escalators WHERE ROWID = %llu;", escalator);
  sql ("COMMIT;");
  return 0;
}

/**
 * @brief Return the UUID of a escalator.
 *
 * @param[in]   escalator  Escalator.
 * @param[out]  id         Pointer to a newly allocated string.
 *
 * @return 0.
 */
int
escalator_uuid (escalator_t escalator, char ** id)
{
  *id = sql_string (0, 0,
                    "SELECT uuid FROM escalators WHERE ROWID = %llu;",
                    escalator);
  return 0;
}

/**
 * @brief Return the condition associated with an escalator.
 *
 * @param[in]  escalator  Escalator.
 *
 * @return Condition.
 */
static escalator_condition_t
escalator_condition (escalator_t escalator)
{
  return sql_int (0, 0,
                  "SELECT condition FROM escalators WHERE ROWID = %llu;",
                  escalator);
}

/**
 * @brief Return the method associated with an escalator.
 *
 * @param[in]  escalator  Escalator.
 *
 * @return Method.
 */
static escalator_method_t
escalator_method (escalator_t escalator)
{
  return sql_int (0, 0,
                  "SELECT method FROM escalators WHERE ROWID = %llu;",
                  escalator);
}

/**
 * @brief Initialise an escalator iterator.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  escalator   Single escalator to iterator over, 0 for all.
 * @param[in]  task        Iterate over escalators for this task.  0 for all.
 * @param[in]  event       Iterate over escalators handling this event.  0 for
 *                         all.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for "ROWID".
 */
void
init_escalator_iterator (iterator_t *iterator, escalator_t escalator,
                         task_t task, event_t event, int ascending,
                         const char *sort_field)
{
  assert (escalator ? task == 0 : (task ? escalator == 0 : 1));
  assert (escalator ? event == 0 : (event ? escalator == 0 : 1));
  assert (event ? task : 1);
  assert (current_credentials.uuid);

  if (escalator)
    init_iterator (iterator,
                   "SELECT escalators.ROWID, uuid, name, comment,"
                   " 0, event, condition, method,"
                   " (SELECT count(*) > 0 FROM task_escalators"
                   "  WHERE task_escalators.escalator = escalators.ROWID)"
                   " FROM escalators"
                   " WHERE ROWID = %llu"
                   " AND ((owner IS NULL) OR (owner ="
                   " (SELECT ROWID FROM users WHERE users.uuid = '%s')))"
                   " ORDER BY %s %s;",
                   escalator,
                   current_credentials.uuid,
                   sort_field ? sort_field : "escalators.ROWID",
                   ascending ? "ASC" : "DESC");
  else if (task)
    init_iterator (iterator,
                   "SELECT escalators.ROWID, uuid, name, comment,"
                   " task_escalators.task, event, condition, method, 1"
                   " FROM escalators, task_escalators"
                   " WHERE task_escalators.escalator = escalators.ROWID"
                   " AND task_escalators.task = %llu AND event = %i"
                   " AND ((owner IS NULL) OR (owner ="
                   " (SELECT ROWID FROM users WHERE users.uuid = '%s')))"
                   " ORDER BY %s %s;",
                   task,
                   event,
                   current_credentials.uuid,
                   sort_field ? sort_field : "escalators.ROWID",
                   ascending ? "ASC" : "DESC");
  else
    init_iterator (iterator,
                   "SELECT escalators.ROWID, uuid, name, comment,"
                   " 0, event, condition, method,"
                   " (SELECT count(*) > 0 FROM task_escalators"
                   "  WHERE task_escalators.escalator = escalators.ROWID)"
                   " FROM escalators"
                   " WHERE ((owner IS NULL) OR (owner ="
                   " (SELECT ROWID FROM users WHERE users.uuid = '%s')))"
                   " ORDER BY %s %s;",
                   current_credentials.uuid,
                   sort_field ? sort_field : "escalators.ROWID",
                   ascending ? "ASC" : "DESC");
}

/**
 * @brief Return the escalator from an escalator iterator.
 *
 * @param[in]  iterator  Iterator.
 */
escalator_t
escalator_iterator_escalator (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return sqlite3_column_int64 (iterator->stmt, 0);
}

/**
 * @brief Return the UUID from an escalator iterator.
 *
 * @param[in]  iterator  Iterator.
 */
const char*
escalator_iterator_uuid (iterator_t* iterator)
{
  const char *ret;
  if (iterator->done) return NULL;
  ret = (const char*) sqlite3_column_text (iterator->stmt, 1);
  return ret;
}

/**
 * @brief Return the name from an escalator iterator.
 *
 * @param[in]  iterator  Iterator.
 */
const char*
escalator_iterator_name (iterator_t* iterator)
{
  const char *ret;
  if (iterator->done) return NULL;
  ret = (const char*) sqlite3_column_text (iterator->stmt, 2);
  return ret;
}

/**
 * @brief Return the comment on an escalator iterator.
 *
 * @param[in]  iterator  Iterator.
 */
const char *
escalator_iterator_comment (iterator_t* iterator)
{
  const char *ret;
  if (iterator->done) return NULL;
  ret = (const char*) sqlite3_column_text (iterator->stmt, 3);
  return ret;
}

/**
 * @brief Return the event from an escalator iterator.
 *
 * @param[in]  iterator  Iterator.
 */
int
escalator_iterator_event (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (int) sqlite3_column_int (iterator->stmt, 5);
  return ret;
}

/**
 * @brief Return the condition from an escalator iterator.
 *
 * @param[in]  iterator  Iterator.
 */
int
escalator_iterator_condition (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (int) sqlite3_column_int (iterator->stmt, 6);
  return ret;
}

/**
 * @brief Return the method from an escalator iterator.
 *
 * @param[in]  iterator  Iterator.
 */
int
escalator_iterator_method (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (int) sqlite3_column_int (iterator->stmt, 7);
  return ret;
}

/**
 * @brief Return whether an escalator is in use.
 *
 * @param[in]  iterator  Iterator.
 */
int
escalator_iterator_in_use (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (int) sqlite3_column_int (iterator->stmt, 8);
  return ret;
}

/**
 * @brief Initialise an escalator data iterator.
 *
 * @param[in]  iterator   Iterator.
 * @param[in]  escalator  Escalator.
 * @param[in]  table      Type of data: "condition", "event" or "method",
 *                        corresponds to substring of the table to select
 *                        from.
 */
void
init_escalator_data_iterator (iterator_t *iterator, escalator_t escalator,
                              const char *table)
{
  init_iterator (iterator,
                 "SELECT name, data FROM escalator_%s_data"
                 " WHERE escalator = %llu;",
                 table,
                 escalator);
}

/**
 * @brief Return the name from an escalator data iterator.
 *
 * @param[in]  iterator  Iterator.
 */
const char*
escalator_data_iterator_name (iterator_t* iterator)
{
  const char *ret;
  if (iterator->done) return NULL;
  ret = (const char*) sqlite3_column_text (iterator->stmt, 0);
  return ret;
}

/**
 * @brief Return the data from an escalator data iterator.
 *
 * @param[in]  iterator  Iterator.
 */
const char*
escalator_data_iterator_data (iterator_t* iterator)
{
  const char *ret;
  if (iterator->done) return NULL;
  ret = (const char*) sqlite3_column_text (iterator->stmt, 1);
  return ret;
}

/**
 * @brief Return data associated with an escalator.
 *
 * @param[in]  escalator  Escalator.
 * @param[in]  type       Type of data: "condition", "event" or "method".
 * @param[in]  name       Name of the data.
 *
 * @return Freshly allocated data if it exists, else NULL.
 */
char *
escalator_data (escalator_t escalator, const char *type, const char *name)
{
  gchar *quoted_name;
  char *data;

  assert (strcmp (type, "condition") == 0
          || strcmp (type, "event") == 0
          || strcmp (type, "method") == 0);

  quoted_name = sql_quote (name);
  data = sql_string (0, 0,
                     "SELECT data FROM escalator_%s_data"
                     " WHERE escalator = %llu AND name = '%s';",
                     type,
                     escalator,
                     quoted_name);
  g_free (quoted_name);
  return data;
}

/**
 * @brief Send an email.
 *
 * @param[in]  to_address    Address to send to.
 * @param[in]  from_address  Address to send to.
 * @param[in]  subject       Subject of email.
 * @param[in]  body          Body of email.
 *
 * @return 0 success, -1 error.
 */
static int
email (const char *to_address, const char *from_address, const char *subject,
       const char *body)
{
  int ret;
  gchar *command;

  tracef ("   EMAIL to %s from %s subject: %s, body: %s",
          to_address, from_address, subject, body);

  command = g_strdup_printf ("echo \""
                             "To: %s\n"
                             "From: %s\n"
                             "Subject: %s\n"
                             "\n"
                             "%s\""
                             " | /usr/sbin/sendmail %s"
                             " > /dev/null 2>&1",
                             to_address,
                             from_address ? from_address
                                          : "automated@openvas.org",
                             subject,
                             body,
                             to_address);

  tracef ("   command: %s\n", command);

  if (ret = system (command),
      /** @todo ret is always -1. */
      0 && ((ret) == -1
            || WEXITSTATUS (ret)))
    {
      g_warning ("%s: system failed with ret %i, %i, %s\n",
                 __FUNCTION__,
                 ret,
                 WEXITSTATUS (ret),
                 command);
      g_free (command);
      return -1;
    }
  g_free (command);
  return 0;
}

/**
 * @brief GET an HTTP resource.
 *
 * @param[in]  url  URL.
 *
 * @return 0 success, -1 error.
 */
static int
http_get (const char *url)
{
  int ret;
  gchar *standard_out = NULL;
  gchar *standard_err = NULL;
  gint exit_status;
  gchar **cmd;

  tracef ("   HTTP_GET %s", url);

  cmd = (gchar **) g_malloc (5 * sizeof (gchar *));
  cmd[0] = g_strdup ("/usr/bin/wget");
  cmd[1] = g_strdup ("-O");
  cmd[2] = g_strdup ("-");
  cmd[3] = g_strdup (url);
  cmd[4] = NULL;
  g_debug ("%s: Spawning in /tmp/: %s %s %s %s\n",
           __FUNCTION__, cmd[0], cmd[1], cmd[2], cmd[3]);
  if ((g_spawn_sync ("/tmp/",
                     cmd,
                     NULL,                  /* Environment. */
                     G_SPAWN_SEARCH_PATH,
                     NULL,                  /* Setup function. */
                     NULL,
                     &standard_out,
                     &standard_err,
                     &exit_status,
                     NULL)
       == FALSE)
      || (WIFEXITED (exit_status) == 0)
      || WEXITSTATUS (exit_status))
    {
      g_debug ("%s: wget failed: %d (WIF %i, WEX %i)",
               __FUNCTION__,
               exit_status,
               WIFEXITED (exit_status),
               WEXITSTATUS (exit_status));
      g_debug ("%s: stdout: %s\n", __FUNCTION__, standard_out);
      g_debug ("%s: stderr: %s\n", __FUNCTION__, standard_err);
      ret = -1;
    }
  else
    {
      if (strlen (standard_out) > 80)
        standard_out[80] = '\0';
      g_debug ("   HTTP_GET %s: %s", url, standard_out);
      ret = 0;
    }

  g_free (cmd[0]);
  g_free (cmd[1]);
  g_free (cmd[2]);
  g_free (cmd[3]);
  g_free (cmd[4]);
  g_free (cmd);
  g_free (standard_out);
  g_free (standard_err);
  return ret;
}

/**
 * @brief Format string for simple notice escalator email.
 */
#define REPORT_NOTICE_FORMAT                                                  \
 "Task '%s': %s\n"                                                            \
 "\n"                                                                         \
 "After the event %s,\n"                                                      \
 "the following condition was met: %s\n"                                      \
 "\n"                                                                         \
 "This email escalation is configured to apply report format '%s'.\n"         \
 "Full details and other report formats are available on the scan engine.\n"  \
 "\n"                                                                         \
 "%s%s%s"                                                                     \
 "\n"                                                                         \
 "%.*s"                                                                       \
 "%s"                                                                         \
 "\n"                                                                         \
 "\n"                                                                         \
 "Note:\n"                                                                    \
 "This email was sent to you as a configured security scan escalation.\n"     \
 "Please contact your local system administrator if you think you\n"          \
 "should not have received it.\n"

/**
 * @brief Maximum number of bytes of the report included in email escalations.
 */
#define MAX_CONTENT_LENGTH 2000

/**
 * @brief Format string for simple notice escalator email.
 */
#define SIMPLE_NOTICE_FORMAT                                                  \
 "%s.\n"                                                                      \
 "\n"                                                                         \
 "After the event %s,\n"                                                      \
 "the following condition was met: %s\n"                                      \
 "\n"                                                                         \
 "This email escalation is not configured to provide more details.\n"         \
 "Full details are stored on the scan engine.\n"                              \
 "\n"                                                                         \
 "\n"                                                                         \
 "Note:\n"                                                                    \
 "This email was sent to you as a configured security scan escalation.\n"     \
 "Please contact your local system administrator if you think you\n"          \
 "should not have received it.\n"

/**
 * @brief Escalate an event.
 *
 * @param[in]  escalator   Escalator.
 * @param[in]  task        Task.
 * @param[in]  event       Event.
 * @param[in]  event_data  Event data.
 * @param[in]  method      Method from escalator.
 * @param[in]  condition   Condition from escalator, which was met by event.
 *
 * @return 0 success, -1 error.
 */
static int
escalate_1 (escalator_t escalator, task_t task, event_t event,
            const void* event_data, escalator_method_t method,
            escalator_condition_t condition)
{
  g_log ("event escalator", G_LOG_LEVEL_MESSAGE,
         "The escalator for task %s was triggered "
         "(Event: %s, Condition: %s)",
         task_name (task),
         event_description (event, event_data, NULL),
         escalator_condition_description (condition, escalator));

  switch (method)
    {
      case ESCALATOR_METHOD_EMAIL:
        {
          char *to_address;

          to_address = escalator_data (escalator, "method", "to_address");

          if (to_address)
            {
              int ret;
              gchar *body, *subject;
              char *name, *notice, *from_address;

              from_address = escalator_data (escalator,
                                             "method",
                                             "from_address");

              notice = escalator_data (escalator, "method", "notice");
              name = task_name (task);
              if (notice && strcmp (notice, "0") == 0)
                {
                  gchar *event_desc, *condition_desc, *report_content;
                  char *format_uuid, *format_name;
                  report_t report;
                  report_format_t report_format = 0;
                  gsize content_length;

                  /* Message with report. */

                  switch (sql_int64 (&report, 0, 0,
                                     "SELECT max (ROWID) FROM reports"
                                     " WHERE task = %llu",
                                     task))
                    {
                      case 0:
                        if (report)
                          break;
                      case 1:        /* Too few rows in result of query. */
                      case -1:
                        free (notice);
                        free (name);
                        free (to_address);
                        free (from_address);
                        return -1;
                        break;
                      default:       /* Programming error. */
                        assert (0);
                        return -1;
                    }

                  format_uuid = escalator_data (escalator,
                                                "method",
                                                "notice_report_format");
                  if ((find_report_format (format_uuid, &report_format)
                       || (report_format == 0))
                      /* Fallback to TXT. */
                      && (find_report_format
                           ("19f6f1b3-7128-4433-888c-ccc764fe6ed5",
                            &report_format)
                          || (report_format == 0)))
                    {
                      g_free (format_uuid);
                      free (notice);
                      free (name);
                      free (to_address);
                      free (from_address);
                      return -1;
                    }
                  g_free (format_uuid);
                  format_name = report_format_name (report_format);

                  event_desc = event_description (event, event_data, NULL);
                  condition_desc = escalator_condition_description (condition,
                                                                    escalator);
                  subject = g_strdup_printf ("[OpenVAS-Manager] Task '%s': %s",
                                             name ? name : "Internal Error",
                                             event_desc);
                  report_content = manage_report (report,
                                                  report_format,
                                                  1,       /* Ascending. */
                                                  NULL,    /* Sort field. */
                                                  1,       /* Result hosts only. */
                                                  NULL,    /* Min CVSS base. */
                                                  NULL,    /* Levels. */
                                                  1,       /* Apply overrides. */
                                                  NULL,    /* Search phrase. */
                                                  1,       /* Notes. */
                                                  0,       /* Notes details. */
                                                  1,       /* Overrides. */
                                                  0,       /* Overrides details. */
                                                  0,       /* First results. */
                                                  1000,    /* Max results. */
                                                  &content_length,
                                                  NULL,    /* Extension. */
                                                  NULL);   /* Content type. */
                  body = g_strdup_printf (REPORT_NOTICE_FORMAT,
                                          name,
                                          event_desc,
                                          event_desc,
                                          condition_desc,
                                          format_name,
                                          ((content_length > MAX_CONTENT_LENGTH)
                                            ? "Note: This report exceeds the"
                                              " maximum length of "
                                            : ""),
                                          ((content_length > MAX_CONTENT_LENGTH)
                                            ? G_STRINGIFY (MAX_CONTENT_LENGTH)
                                            : ""),
                                          ((content_length > MAX_CONTENT_LENGTH)
                                            ? " characters and thus\n"
                                              "was truncated.\n"
                                            : ""),
                                          /* Cast for 64 bit.  Safe because
                                           * MAX_CONTENT_LENGTH is small. */
                                          (int) MIN (content_length,
                                                     MAX_CONTENT_LENGTH),
                                          report_content,
                                          ((content_length > MAX_CONTENT_LENGTH)
                                            ? "\n... (report truncated after"
                                              " "
                                              G_STRINGIFY (MAX_CONTENT_LENGTH)
                                              " characters)\n"
                                            : ""));
                  free (format_name);
                  g_free (report_content);
                  g_free (event_desc);
                  g_free (condition_desc);
                }
              else
                {
                  gchar *event_desc, *generic_desc, *condition_desc;

                  /* Simple notice message. */
                  event_desc = event_description (event, event_data, name);
                  generic_desc = event_description (event, event_data, NULL);
                  condition_desc = escalator_condition_description (condition,
                                                                    escalator);
                  subject = g_strdup_printf ("[OpenVAS-Manager] Task '%s':"
                                             " An event occurred",
                                             name);
                  body = g_strdup_printf (SIMPLE_NOTICE_FORMAT,
                                          event_desc,
                                          generic_desc,
                                          condition_desc);
                  g_free (event_desc);
                  g_free (generic_desc);
                  g_free (condition_desc);
                }
              free (name);
              free (notice);
              ret = email (to_address, from_address, subject, body);
              free (to_address);
              free (from_address);
              g_free (subject);
              g_free (body);
              return ret;
            }
          return -1;
          break;
        }
      case ESCALATOR_METHOD_HTTP_GET:
        {
          char *url;

          url = escalator_data (escalator, "method", "URL");

          if (url)
            {
              int ret, formatting;
              gchar *point, *end;
              GString *new_url;

              new_url = g_string_new ("");
              for (formatting = 0, point = url, end = (url + strlen (url));
                   point < end;
                   point++)
                if (formatting)
                  {
                    switch (*point)
                      {
                        case '$':
                          g_string_append_c (new_url, '$');
                          break;
                        case 'c':
                          {
                            gchar *condition_desc;
                            condition_desc = escalator_condition_description
                                              (condition, escalator);
                            g_string_append (new_url, condition_desc);
                            g_free (condition_desc);
                            break;
                          }
                        case 'e':
                          {
                            gchar *event_desc;
                            event_desc = event_description (event, event_data,
                                                            NULL);
                            g_string_append (new_url, event_desc);
                            g_free (event_desc);
                            break;
                          }
                        case 'n':
                          {
                            char *name = task_name (task);
                            g_string_append (new_url, name);
                            free (name);
                            break;
                          }
                        default:
                          g_string_append_c (new_url, '$');
                          g_string_append_c (new_url, *point);
                          break;
                      }
                    formatting = 0;
                  }
                else if (*point == '$')
                  formatting = 1;
                else
                  g_string_append_c (new_url, *point);

              ret = http_get (new_url->str);
              g_string_free (new_url, TRUE);
              g_free (url);
              return ret;
            }
          return -1;
          break;
        }
      case ESCALATOR_METHOD_SYSLOG:
        {
          char *submethod;
          gchar *message, *event_desc, *level;

          event_desc = event_description (event, event_data, NULL);
          message = g_strdup_printf ("%s: %s", event_name (event), event_desc);
          g_free (event_desc);

          submethod = escalator_data (escalator, "method", "submethod");
          level = g_strdup_printf ("event %s", submethod);
          g_free (submethod);

          tracef ("  syslog level: %s", level);
          tracef ("syslog message: %s", message);

          g_log (level, G_LOG_LEVEL_MESSAGE, "%s", message);

          g_free (level);
          g_free (message);

          return 0;
          break;
        }
      case ESCALATOR_METHOD_ERROR:
      default:
        break;
    }
  return -1;
}

/**
 * @brief Escalate an escalator with task and event data.
 *
 * @param[in]  escalator   Escalator.
 * @param[in]  task        Task.
 * @param[in]  event       Event.
 * @param[in]  event_data  Event data.
 *
 * @return 0 success, -1 error.
 */
int
escalate (escalator_t escalator, task_t task, event_t event,
          const void* event_data)
{
  escalator_condition_t condition = escalator_condition (escalator);
  escalator_method_t method = escalator_method (escalator);
  return escalate_1 (escalator, task, event, event_data, method, condition);
}

/**
 * @brief Return whether an event applies to a task and an escalator.
 *
 * @param[in]  event       Event.
 * @param[in]  event_data  Event data.
 * @param[in]  task        Task.
 * @param[in]  escalator   Escalator.
 *
 * @return 1 if event applies, else 0.
 */
static int
event_applies (event_t event, const void *event_data, task_t task,
               escalator_t escalator)
{
  switch (event)
    {
      case EVENT_TASK_RUN_STATUS_CHANGED:
        {
          int ret;
          char *escalator_event_data;

          escalator_event_data = escalator_data (escalator, "event", "status");
          if (escalator_event_data == NULL)
            return 0;
          ret = (task_run_status (task) == (task_status_t) event_data)
                && (strcmp (escalator_event_data,
                            run_status_name ((task_status_t) event_data))
                    == 0);
          free (escalator_event_data);
          return ret;
          break;
        }
      default:
        return 0;
        break;
    }
}

/**
 * @brief Return whether the condition of an escalator is met by a task.
 *
 * @param[in]  task       Task.
 * @param[in]  escalator  Escalator.
 * @param[in]  condition  Condition.
 *
 * @return 1 if met, else 0.
 */
static int
condition_met (task_t task, escalator_t escalator,
               escalator_condition_t condition)
{
  switch (condition)
    {
      case ESCALATOR_CONDITION_ALWAYS:
        return 1;
        break;
      case ESCALATOR_CONDITION_THREAT_LEVEL_AT_LEAST:
        {
          char *condition_level;
          const char *report_level;

          /* True if the threat level of the last finished report is at
           * least the given level. */

          condition_level = escalator_data (escalator, "condition", "level");
          report_level = task_threat_level (task);
          if (condition_level
              && report_level
              && (collate_threat (NULL,
                                  strlen (report_level),
                                  report_level,
                                  strlen (condition_level),
                                  condition_level)
                  > -1))
            {
              free (condition_level);
              return 1;
            }
          free (condition_level);
          break;
        }
      case ESCALATOR_CONDITION_THREAT_LEVEL_CHANGED:
        {
          char *direction;
          const char *last_level, *second_last_level;

          /* True if the threat level of the last finished report changed
           * in the given direction with respect to the second last finished
           * report. */

          direction = escalator_data (escalator, "condition", "direction");
          last_level = task_threat_level (task);
          second_last_level = task_previous_threat_level (task);
          if (direction
              && last_level
              && second_last_level)
            {
              int cmp = collate_threat (NULL,
                                        strlen (last_level),
                                        last_level,
                                        strlen (second_last_level),
                                        second_last_level);
              tracef ("cmp: %i\n", cmp);
              tracef ("direction: %s\n", direction);
              tracef ("last_level: %s\n", last_level);
              tracef ("second_last_level: %s\n", second_last_level);
              if (((strcasecmp (direction, "changed") == 0) && cmp)
                  || ((strcasecmp (direction, "increased") == 0) && (cmp > 0))
                  || ((strcasecmp (direction, "decreased") == 0) && (cmp < 0)))
                {
                  free (direction);
                  return 1;
                }
            }
          else if (direction
                   && last_level)
            {
              tracef ("direction: %s\n", direction);
              tracef ("last_level: %s\n", last_level);
              tracef ("second_last_level NULL\n");
              if ((strcasecmp (direction, "changed") == 0)
                  || (strcasecmp (direction, "increased") == 0))
                {
                  free (direction);
                  return 1;
                }
            }
          free (direction);
          break;
        }
      default:
        break;
    }
  return 0;
}

/**
 * @brief Produce an event.
 *
 * @param[in]  task        Task.
 * @param[in]  event       Event.
 * @param[in]  event_data  Event type specific details.
 */
static void
event (task_t task, event_t event, void* event_data)
{
  iterator_t escalators;
  tracef ("   EVENT %i on task %llu", event, task);
  init_escalator_iterator (&escalators, 0, task, event, 1, NULL);
  while (next (&escalators))
    {
      escalator_t escalator = escalator_iterator_escalator (&escalators);
      if (event_applies (event, event_data, task, escalator))
        {
          escalator_condition_t condition;

          condition = escalator_iterator_condition (&escalators);
          if (condition_met (task, escalator, condition))
            escalate_1 (escalator,
                        task,
                        event,
                        event_data,
                        escalator_iterator_method (&escalators),
                        condition);
        }
    }
  cleanup_iterator (&escalators);
}

/**
 * @brief Initialise an escalator task iterator.
 *
 * Iterate over all tasks that use the escalator.
 *
 * @param[in]  iterator   Iterator.
 * @param[in]  escalator  Escalator.
 * @param[in]  ascending  Whether to sort ascending or descending.
 */
void
init_escalator_task_iterator (iterator_t* iterator, escalator_t escalator,
                              int ascending)
{
  assert (escalator);
  assert (current_credentials.uuid);

  init_iterator (iterator,
                 "SELECT tasks.name, tasks.uuid FROM tasks, task_escalators"
                 " WHERE tasks.ROWID = task_escalators.task"
                 " AND task_escalators.escalator = %llu"
                 " AND hidden = 0"
                 " AND ((tasks.owner IS NULL) OR (tasks.owner ="
                 " (SELECT ROWID FROM users WHERE users.uuid = '%s')))"
                 " ORDER BY tasks.name %s;",
                 escalator,
                 current_credentials.uuid,
                 ascending ? "ASC" : "DESC");
}

/**
 * @brief Return the name from an escalator task iterator.
 *
 * @param[in]  iterator  Iterator.
 */
const char*
escalator_task_iterator_name (iterator_t* iterator)
{
  const char *ret;
  if (iterator->done) return NULL;
  ret = (const char*) sqlite3_column_text (iterator->stmt, 0);
  return ret;
}

/**
 * @brief Return the uuid from an escalator task iterator.
 *
 * @param[in]  iterator  Iterator.
 */
const char*
escalator_task_iterator_uuid (iterator_t* iterator)
{
  const char *ret;
  if (iterator->done) return NULL;
  ret = (const char*) sqlite3_column_text (iterator->stmt, 1);
  return ret;
}


/* Task functions. */

/**
 * @brief Append value to field of task.
 *
 * @param[in]  task   Task.
 * @param[in]  field  Field.
 * @param[in]  value  Value.
 */
static void
append_to_task_string (task_t task, const char* field, const char* value)
{
  char* current;
  gchar* quote;
  current = sql_string (0, 0,
                        "SELECT %s FROM tasks WHERE ROWID = %llu;",
                        field,
                        task);
  if (current)
    {
      gchar* new = g_strconcat ((const gchar*) current, value, NULL);
      free (current);
      quote = sql_nquote (new, strlen (new));
      g_free (new);
    }
  else
    quote = sql_nquote (value, strlen (value));
  sql ("UPDATE tasks SET %s = '%s' WHERE ROWID = %llu;",
       field,
       quote,
       task);
  g_free (quote);
}

/**
 * @brief Initialise a task iterator.
 *
 * If there is a current user select that user's tasks, otherwise select
 * all tasks.
 *
 * @param[in]  iterator    Task iterator.
 * @param[in]  task        Task to limit iteration to.  0 for all.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for "ROWID".
 */
void
init_task_iterator (iterator_t* iterator,
                    task_t task,
                    int ascending,
                    const char *sort_field)
{
  if (current_credentials.uuid)
    {
      if (task)
        init_iterator (iterator,
                       "SELECT ROWID, uuid, run_status FROM tasks"
                       /* Include NULL so everyone can see the example task. */
                       " WHERE ((owner IS NULL) OR owner ="
                       " (SELECT ROWID FROM users"
                       "  WHERE users.uuid = '%s'))"
                       " AND ROWID = %llu"
                       " ORDER BY %s %s;",
                       current_credentials.uuid,
                       task,
                       sort_field ? sort_field : "ROWID",
                       ascending ? "ASC" : "DESC");
      else
        init_iterator (iterator,
                       "SELECT ROWID, uuid, run_status FROM tasks WHERE owner ="
                       " (SELECT ROWID FROM users"
                       "  WHERE users.uuid = '%s')"
                       " ORDER BY %s %s;",
                       current_credentials.uuid,
                       sort_field ? sort_field : "ROWID",
                       ascending ? "ASC" : "DESC");
    }
  else
    {
      if (task)
        init_iterator (iterator,
                       "SELECT ROWID, uuid, run_status FROM tasks"
                       " WHERE ROWID = %llu"
                       " ORDER BY %s %s;",
                       task,
                       sort_field ? sort_field : "ROWID",
                       ascending ? "ASC" : "DESC");
      else
        init_iterator (iterator,
                       "SELECT ROWID, uuid, run_status FROM tasks"
                       " ORDER BY %s %s;",
                       sort_field ? sort_field : "ROWID",
                       ascending ? "ASC" : "DESC");
    }
}

/**
 * @brief Get the task from a task iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The task.
 */
task_t
task_iterator_task (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return (task_t) sqlite3_column_int64 (iterator->stmt, 0);
}

/**
 * @brief Get the UUID from a task iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Task UUID.
 */
const char *
task_iterator_uuid (iterator_t *iterator)
{
  const char *ret;
  if (iterator->done) return NULL;
  ret = (const char*) sqlite3_column_text (iterator->stmt, 1);
  return ret;
}

/**
 * @brief Get the run status from a task iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Task run status.
 */
task_status_t
task_iterator_run_status (iterator_t* iterator)
{
  task_status_t ret;
  if (iterator->done) return TASK_STATUS_INTERNAL_ERROR;
  ret = (unsigned int) sqlite3_column_int (iterator->stmt, 2);
  return ret;
}

/**
 * @brief Initialize the manage library for a process.
 *
 * Open the SQL database.
 *
 * @param[in]  update_nvt_cache  0 operate normally, -1 just update NVT cache,
 *                               -2 just rebuild NVT cache.
 * @param[in]  database          Location of manage database.
 */
void
init_manage_process (int update_nvt_cache, const gchar *database)
{
  gchar *mgr_dir;
  int ret;

  if (task_db)
    {
      if (update_nvt_cache == -2)
        {
          sql ("BEGIN EXCLUSIVE;");
          sql ("DELETE FROM nvts;");
          sql ("DELETE FROM nvt_preferences;");
          sql ("DELETE FROM meta WHERE name = 'nvts_checksum';");
        }
      return;
    }

  /* Ensure the mgr directory exists. */
  mgr_dir = g_build_filename (OPENVAS_STATE_DIR, "mgr", NULL);
  ret = g_mkdir_with_parents (mgr_dir, 0755 /* "rwxr-xr-x" */);
  g_free (mgr_dir);
  if (ret == -1)
    {
      g_warning ("%s: failed to create mgr directory: %s\n",
                 __FUNCTION__,
                 strerror (errno));
      abort ();
    }

#ifndef S_SPLINT_S
  /* Open the database. */
  if (sqlite3_open (database ? database
                             : OPENVAS_STATE_DIR "/mgr/tasks.db",
                    &task_db))
    {
      g_warning ("%s: sqlite3_open failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      abort ();
    }
#endif /* not S_SPLINT_S */

  if (update_nvt_cache)
    {
      if (update_nvt_cache == -2)
        {
          sql ("BEGIN EXCLUSIVE;");
          sql ("DELETE FROM nvts;");
          sql ("DELETE FROM nvt_preferences;");
          sql ("DELETE FROM meta WHERE name = 'nvts_checksum';");
        }
    }
  else
    {
      /* Define functions for SQL. */

      if (sqlite3_create_collation (task_db,
                                    "collate_message_type",
                                    SQLITE_UTF8,
                                    NULL,
                                    collate_message_type)
          != SQLITE_OK)
        {
          g_warning ("%s: failed to create collate_message_type", __FUNCTION__);
          abort ();
        }

      if (sqlite3_create_collation (task_db,
                                    "collate_ip",
                                    SQLITE_UTF8,
                                    NULL,
                                    collate_ip)
          != SQLITE_OK)
        {
          g_warning ("%s: failed to create collate_ip", __FUNCTION__);
          abort ();
        }

      if (sqlite3_create_function (task_db,
                                   "make_uuid",
                                   0,               /* Number of args. */
                                   SQLITE_UTF8,
                                   NULL,            /* Callback data. */
                                   sql_make_uuid,
                                   NULL,            /* xStep. */
                                   NULL)            /* xFinal. */
          != SQLITE_OK)
        {
          g_warning ("%s: failed to create make_uuid", __FUNCTION__);
          abort ();
        }

      if (sqlite3_create_function (task_db,
                                   "hosts_contains",
                                   2,               /* Number of args. */
                                   SQLITE_UTF8,
                                   NULL,            /* Callback data. */
                                   sql_hosts_contains,
                                   NULL,            /* xStep. */
                                   NULL)            /* xFinal. */
          != SQLITE_OK)
        {
          g_warning ("%s: failed to create host_contains", __FUNCTION__);
          abort ();
        }

      if (sqlite3_create_function (task_db,
                                   "uniquify",
                                   3,               /* Number of args. */
                                   SQLITE_UTF8,
                                   NULL,            /* Callback data. */
                                   sql_uniquify,
                                   NULL,            /* xStep. */
                                   NULL)            /* xFinal. */
          != SQLITE_OK)
        {
          g_warning ("%s: failed to create uniquify", __FUNCTION__);
          abort ();
        }
    }
}

/**
 * @brief Reinitialize the manage library for a process.
 *
 * This is essentially needed after a fork, to not carry open databases around
 * (refer to sqlite3 documentation).
 */
void
reinit_manage_process ()
{
  cleanup_manage_process (FALSE);
  init_manage_process (0, task_db_name);
}

/**
 * @brief Setup config preferences for a config.
 *
 * @param[in]  config         The config.
 * @param[in]  safe_checks    safe_checks option: 1 for "yes", 0 for "no".
 * @param[in]  optimize_test  optimize_test option: 1 for "yes", 0 for "no".
 * @param[in]  port_range     port_range option: 1 for "yes", 0 for "no".
 */
static void
setup_full_config_prefs (config_t config, int safe_checks,
                         int optimize_test, int port_range)
{
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'max_hosts', '20');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'max_checks', '4');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'cgi_path', '/cgi-bin:/scripts');",
       config);
  if (port_range)
    sql ("INSERT into config_preferences (config, type, name, value)"
         " VALUES (%i, 'SERVER_PREFS', 'port_range', '1-65535');",
         config);
  else
    sql ("INSERT into config_preferences (config, type, name, value)"
         " VALUES (%i, 'SERVER_PREFS', 'port_range', 'default');",
         config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'auto_enable_dependencies', 'yes');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'silent_dependencies', 'yes');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'host_expansion', 'ip');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'ping_hosts', 'no');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'reverse_lookup', 'no');",
       config);
  if (optimize_test)
    sql ("INSERT into config_preferences (config, type, name, value)"
         " VALUES (%i, 'SERVER_PREFS', 'optimize_test', 'yes');",
         config);
  else
    sql ("INSERT into config_preferences (config, type, name, value)"
         " VALUES (%i, 'SERVER_PREFS', 'optimize_test', 'no');",
         config);
  if (safe_checks)
    sql ("INSERT into config_preferences (config, type, name, value)"
         " VALUES (%i, 'SERVER_PREFS', 'safe_checks', 'yes');",
         config);
  else
    sql ("INSERT into config_preferences (config, type, name, value)"
         " VALUES (%i, 'SERVER_PREFS', 'safe_checks', 'no');",
         config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'use_mac_addr', 'no');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'unscanned_closed', 'no');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'save_knowledge_base', 'yes');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'only_test_hosts_whose_kb_we_dont_have', 'no');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'only_test_hosts_whose_kb_we_have', 'no');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'kb_restore', 'no');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'kb_dont_replay_scanners', 'no');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'kb_dont_replay_info_gathering', 'no');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'kb_dont_replay_attacks', 'no');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'kb_dont_replay_denials', 'no');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'kb_max_age', '864000');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'log_whole_attack', 'no');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'language', 'english');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'checks_read_timeout', '5');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'non_simult_ports', '139, 445');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'plugins_timeout', '320');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'slice_network_addresses', 'no');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'nasl_no_signature_check', 'yes');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'ping_hosts', 'no');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'reverse_lookup', 'no');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'use_mac_addr', 'no');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'SERVER_PREFS', 'unscanned_closed', 'no');",
       config);

  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'PLUGINS_PREFS',"
       " 'Ping Host[checkbox]:Mark unrechable Hosts as dead (not scanning)',"
       " 'yes');",
       config);
  sql ("INSERT into config_preferences (config, type, name, value)"
       " VALUES (%i, 'PLUGINS_PREFS',"
       " 'Login configurations[checkbox]:NTLMSSP',"
       " 'yes');",
       config);
}

/**
 * @brief Update the memory cache of NVTs.
 */
static void
update_nvti_cache ()
{
  iterator_t nvts;

  nvtis_free (nvti_cache);

  nvti_cache = nvtis_new ();

  init_nvt_iterator (&nvts, (nvt_t) 0, (config_t) 0, NULL, 1, NULL);
  while (next (&nvts))
    {
      nvti_t *nvti = nvti_new ();
      nvti_set_oid (nvti, nvt_iterator_oid (&nvts));
      nvti_set_name (nvti, nvt_iterator_name (&nvts));
      nvti_set_family (nvti, nvt_iterator_family (&nvts));
      nvti_set_cvss_base (nvti, nvt_iterator_cvss_base (&nvts));
      nvti_set_risk_factor (nvti, nvt_iterator_risk_factor (&nvts));
      nvti_set_cve (nvti, nvt_iterator_cve (&nvts));
      nvti_set_bid (nvti, nvt_iterator_bid (&nvts));
      nvtis_add (nvti_cache, nvti);
    }
  cleanup_iterator (&nvts);
}

/**
 * @brief Update the memory cache of NVTs, if this has been requested.
 */
void
manage_update_nvti_cache ()
{
  if (sql_int (0, 0,
               "SELECT value FROM meta WHERE name = 'update_nvti_cache';"))
    {
      update_nvti_cache ();
      sql ("UPDATE meta SET value = 0 WHERE name = 'update_nvti_cache';");
    }
}

/**
 * @brief Initialize the manage library.
 *
 * Ensure all tasks are in a clean initial state.
 *
 * Beware that calling this function while tasks are running may lead to
 * problems.
 *
 * @param[in]  log_config      Log configuration.
 * @param[in]  nvt_cache_mode  True when running in NVT caching mode.
 * @param[in]  database        Location of database.
 *
 * @return 0 success, -1 error, -2 database is wrong version, -3 database needs
 *         to be initialised from server.
 */
int
init_manage (GSList *log_config, int nvt_cache_mode, const gchar *database)
{
  char *database_version;

  g_log_set_handler (G_LOG_DOMAIN,
                     ALL_LOG_LEVELS,
                     (GLogFunc) openvas_log_func,
                     log_config);

  current_credentials.uuid = NULL;
  current_credentials.username = NULL;
  current_credentials.password = NULL;

  init_manage_process (0, database);

  /* Check that the version of the database is correct. */

  database_version = sql_string (0, 0,
                                 "SELECT value FROM meta"
                                 " WHERE name = 'database_version';");
  if (nvt_cache_mode)
    {
      if (database_version
          && strcmp (database_version,
                     G_STRINGIFY (OPENVASMD_DATABASE_VERSION)))
        {
          g_message ("%s: database version of database: %s\n",
                     __FUNCTION__,
                     database_version);
          g_message ("%s: database version supported by manager: %s\n",
                     __FUNCTION__,
                     G_STRINGIFY (OPENVASMD_DATABASE_VERSION));
          g_free (database_version);
          return -2;
        }
      g_free (database_version);

      /* If database_version was NULL then meta was missing, so assume
       * that the database is missing, which is OK. */
    }
  else
    {
      long long int count;

      if (database_version)
        {
          if (strcmp (database_version,
                      G_STRINGIFY (OPENVASMD_DATABASE_VERSION)))
            {
              g_message ("%s: database version of database: %s\n",
                         __FUNCTION__,
                         database_version);
              g_message ("%s: database version supported by manager: %s\n",
                         __FUNCTION__,
                         G_STRINGIFY (OPENVASMD_DATABASE_VERSION));
              g_free (database_version);
              return -2;
            }
          g_free (database_version);
        }
      else
        /* Assume database is missing. */
        return -3;

      /* Check that the database was initialised from the scanner.
       *
       * This can also fail after a migration, for example if the database
       * was created before NVT preferences were cached in the database.
       */

      if (sql_int64 (&count, 0, 0,
                     "SELECT count(*) FROM meta"
                     " WHERE name = 'nvts_md5sum'"
                     " OR name = 'nvt_preferences_enabled';")
          || count < 2)
        return -3;
    }

  /* Ensure the tables exist. */

  create_tables ();

  /* Ensure the version is set. */

  set_db_version (OPENVASMD_DATABASE_VERSION);

  /* Ensure the special "om" user exists. */

  if (sql_int (0, 0, "SELECT count(*) FROM users WHERE name = 'om';") == 0)
    sql ("INSERT into users (name, password) VALUES ('om', '');");

  /* Ensure the nvti cache update flag exists and is clear. */

  if (sql_int (0, 0,
               "SELECT count(*) FROM meta WHERE name = 'update_nvti_cache';"))
    sql ("UPDATE meta SET value = 0 WHERE name = 'update_nvti_cache';");
  else
    sql ("INSERT INTO meta (name, value) VALUES ('update_nvti_cache', 0);");

  /* Ensure every part of the predefined selector exists.
   *
   * This restores entries lost due to the error solved 2010-08-13 by r8805.  */

  if (sql_int (0, 0,
               "SELECT count(*) FROM nvt_selectors WHERE name ="
               " '" MANAGE_NVT_SELECTOR_UUID_ALL "'"
               " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_ALL) ";")
      == 0)
    {
      sql ("INSERT into nvt_selectors (name, exclude, type, family_or_nvt)"
           " VALUES ('" MANAGE_NVT_SELECTOR_UUID_ALL "', 0, "
           G_STRINGIFY (NVT_SELECTOR_TYPE_ALL) ", NULL);");
    }

  if (sql_int (0, 0,
               "SELECT count(*) FROM nvt_selectors WHERE name ="
               " '" MANAGE_NVT_SELECTOR_UUID_ALL "'"
               " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_FAMILY) ";")
      == 0)
    {
      sql ("INSERT into nvt_selectors"
           " (name, exclude, type, family_or_nvt, family)"
           " VALUES ('" MANAGE_NVT_SELECTOR_UUID_ALL "', 1, "
           G_STRINGIFY (NVT_SELECTOR_TYPE_FAMILY) ","
           " 'Port scanners', 'Port scanners');");
    }

  if (sql_int (0, 0,
               "SELECT count(*) FROM nvt_selectors WHERE name ="
               " '" MANAGE_NVT_SELECTOR_UUID_ALL "'"
               " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
               " AND family_or_nvt = '1.3.6.1.4.1.25623.1.0.14259';")
      == 0)
    {
      sql ("INSERT into nvt_selectors"
           " (name, exclude, type, family_or_nvt, family)"
           " VALUES ('" MANAGE_NVT_SELECTOR_UUID_ALL "', 0, "
           G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
           /* OID of the "Nmap (NASL wrapper)" NVT. */
           " '1.3.6.1.4.1.25623.1.0.14259', 'Port scanners');");
    }

  if (sql_int (0, 0,
               "SELECT count(*) FROM nvt_selectors WHERE name ="
               " '" MANAGE_NVT_SELECTOR_UUID_ALL "'"
               " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
               " AND family_or_nvt = '1.3.6.1.4.1.25623.1.0.100315';")
      == 0)
    {
      sql ("INSERT into nvt_selectors"
           " (name, exclude, type, family_or_nvt, family)"
           " VALUES ('" MANAGE_NVT_SELECTOR_UUID_ALL "', 0, "
           G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ","
           /* OID of the "Ping Host" NVT. */
           " '1.3.6.1.4.1.25623.1.0.100315', 'Port scanners');");
    }

  /* Ensure the predefined configs exist. */

  if (sql_int (0, 0,
               "SELECT count(*) FROM configs"
               " WHERE name = 'Full and fast';")
      == 0)
    {
      config_t config;

      sql ("INSERT into configs (id, uuid, owner, name, nvt_selector, comment,"
           " family_count, nvt_count, nvts_growing, families_growing)"
           " VALUES (" G_STRINGIFY (CONFIG_ID_FULL_AND_FAST) ","
           " '" CONFIG_UUID_FULL_AND_FAST "', NULL, 'Full and fast',"
           " '" MANAGE_NVT_SELECTOR_UUID_ALL "',"
           " 'All NVT''s; optimized by using previously collected information.',"
           " %i, %i, 1, 1);",
           family_nvt_count (NULL) - family_nvt_count ("Port scanners") + 1,
           family_count ());

      /* Setup preferences for the config. */
      config = sqlite3_last_insert_rowid (task_db);
      setup_full_config_prefs (config, 1, 1, 0);
    }

  if (sql_int (0, 0,
               "SELECT count(*) FROM configs"
               " WHERE name = 'Full and fast ultimate';")
      == 0)
    {
      config_t config;

      sql ("INSERT into configs (id, uuid, owner, name, nvt_selector, comment,"
           " family_count, nvt_count, nvts_growing, families_growing)"
           " VALUES (" G_STRINGIFY (CONFIG_ID_FULL_AND_FAST_ULTIMATE) ","
           " '" CONFIG_UUID_FULL_AND_FAST_ULTIMATE "', NULL,"
           " 'Full and fast ultimate', '" MANAGE_NVT_SELECTOR_UUID_ALL "',"
           " 'All NVT''s including those that can stop services/hosts;"
           " optimized by using previously collected information.',"
           " %i, %i, 1, 1);",
           family_nvt_count (NULL) - family_nvt_count ("Port scanners") + 1,
           family_count ());

      /* Setup preferences for the config. */
      config = sqlite3_last_insert_rowid (task_db);
      setup_full_config_prefs (config, 0, 1, 0);
    }

  if (sql_int (0, 0,
               "SELECT count(*) FROM configs"
               " WHERE name = 'Full and very deep';")
      == 0)
    {
      config_t config;

      sql ("INSERT into configs (id, uuid, owner, name, nvt_selector, comment,"
           " family_count, nvt_count, nvts_growing, families_growing)"
           " VALUES (" G_STRINGIFY (CONFIG_ID_FULL_AND_VERY_DEEP) ","
           " '" CONFIG_UUID_FULL_AND_VERY_DEEP "', NULL,"
           " 'Full and very deep', '" MANAGE_NVT_SELECTOR_UUID_ALL "',"
           " 'All NVT''s; don''t trust previously collected information; slow.',"
           " %i, %i, 1, 1);",
           family_nvt_count (NULL) - family_nvt_count ("Port scanners") + 1,
           family_count ());

      /* Setup preferences for the config. */
      config = sqlite3_last_insert_rowid (task_db);
      setup_full_config_prefs (config, 1, 0, 1);
    }

  if (sql_int (0, 0,
               "SELECT count(*) FROM configs"
               " WHERE name = 'Full and very deep ultimate';")
      == 0)
    {
      config_t config;

      sql ("INSERT into configs (id, uuid, owner, name, nvt_selector, comment,"
           " family_count, nvt_count, nvts_growing, families_growing)"
           " VALUES (" G_STRINGIFY (CONFIG_ID_FULL_AND_VERY_DEEP_ULTIMATE) ","
           " '" CONFIG_UUID_FULL_AND_VERY_DEEP_ULTIMATE "',"
           " NULL, 'Full and very deep ultimate',"
           " '" MANAGE_NVT_SELECTOR_UUID_ALL "',"
           " 'All NVT''s including those that can stop services/hosts;"
           " don''t trust previously collected information; slow.',"
           " %i, %i, 1, 1);",
           family_nvt_count (NULL) - family_nvt_count ("Port scanners") + 1,
           family_count ());

      /* Setup preferences for the config. */
      config = sqlite3_last_insert_rowid (task_db);
      setup_full_config_prefs (config, 0, 0, 1);
    }

  if (sql_int (0, 0,
               "SELECT count(*) FROM configs"
               " WHERE name = 'empty';")
      == 0)
    {
      config_t config;

      sql ("INSERT into configs (uuid, name, owner, nvt_selector, comment,"
           " family_count, nvt_count, nvts_growing, families_growing)"
           " VALUES ('" CONFIG_UUID_EMPTY "', 'empty', NULL, 'empty',"
           " 'Empty and static configuration template.',"
           " 0, 0, 0, 0);");

      /* Setup preferences for the config. */
      config = sqlite3_last_insert_rowid (task_db);
      setup_full_config_prefs (config, 1, 1, 0);
    }

  /* Ensure the predefined target exists. */

  if (sql_int (0, 0, "SELECT count(*) FROM targets WHERE name = 'Localhost';")
      == 0)
    sql ("INSERT into targets (uuid, owner, name, hosts)"
         " VALUES ('" TARGET_UUID_LOCALHOST "', NULL, 'Localhost',"
         " 'localhost');");

  /* Ensure the predefined example task and report exists. */

  if (sql_int (0, 0,
               "SELECT count(*) FROM tasks"
               " WHERE uuid = '" MANAGE_EXAMPLE_TASK_UUID "';")
      == 0)
    {
      sql ("INSERT into tasks (uuid, owner, name, hidden, comment,"
           " run_status, start_time, end_time, config, target, slave)"
           " VALUES ('" MANAGE_EXAMPLE_TASK_UUID "', NULL, 'Example task',"
           " 1, 'This is an example task for the help pages.', %u,"
           " 'Tue Aug 25 21:48:25 2009', 'Tue Aug 25 21:52:16 2009',"
           " (SELECT ROWID FROM configs WHERE name = 'Full and fast'),"
           " (SELECT ROWID FROM targets WHERE name = 'Localhost'),"
           " 0);",
           TASK_STATUS_DONE);
    }

  if (sql_int (0, 0,
               "SELECT count(*) FROM reports"
               " WHERE uuid = '343435d6-91b0-11de-9478-ffd71f4c6f30';")
      == 0)
    {
      task_t task;
      result_t result;
      report_t report;

      /* Setup a dummy user, so that find_task will work. */
      current_credentials.uuid = "";

      if (find_task (MANAGE_EXAMPLE_TASK_UUID, &task))
        g_warning ("%s: error while finding example task", __FUNCTION__);
      else if (task == 0)
        g_warning ("%s: failed to find example task", __FUNCTION__);
      else
        {
          sql ("INSERT into reports (uuid, owner, hidden, task, comment,"
               " start_time, end_time, scan_run_status, slave_progress,"
               " slave_task_uuid)"
               " VALUES ('343435d6-91b0-11de-9478-ffd71f4c6f30', NULL, 1, %llu,"
               " 'This is an example report for the help pages.',"
               " 'Tue Aug 25 21:48:25 2009', 'Tue Aug 25 21:52:16 2009',"
               " %u, 0, '');",
               task,
               TASK_STATUS_DONE);
          report = sqlite3_last_insert_rowid (task_db);
          sql ("INSERT into results (uuid, task, subnet, host, port, nvt, type,"
               " description)"
               " VALUES ('cb291ec0-1b0d-11df-8aa1-002264764cea', %llu, '',"
               " 'localhost', 'telnet (23/tcp)',"
               " '1.3.6.1.4.1.25623.1.0.10330', 'Security Note',"
               " 'A telnet server seems to be running on this port');",
               task);
          result = sqlite3_last_insert_rowid (task_db);
          sql ("INSERT into report_results (report, result) VALUES (%llu, %llu)",
               report, result);
          sql ("INSERT into report_hosts (report, host, start_time, end_time)"
               " VALUES (%llu, 'localhost', 'Tue Aug 25 21:48:26 2009',"
               " 'Tue Aug 25 21:52:15 2009')",
               report);
        }

      current_credentials.uuid = NULL;
    }

  /* Ensure the predefined report formats exist. */

  if (sql_int (0, 0, "SELECT count(*) FROM report_formats WHERE name = 'CPE';")
      == 0)
    {
      report_format_t report_format;
      sql ("INSERT into report_formats (uuid, owner, name, summary, description,"
           " extension, content_type, signature, trust, trust_time, flags)"
           " VALUES ('a0704abb-2120-489f-959f-251c9f4ffebd', NULL, 'CPE',"
           " 'Common Product Enumeration CSV table.',"
           " 'CPE stands for Common Product Enumeration.  It is a structured naming scheme for\n"
           "information technology systems, platforms, and packages.  In other words: CPE\n"
           "provides a unique identifier for virtually any software product that is known for\n"
           "a vulnerability.\n"
           "\n"
           "The CPE dictionary is maintained by MITRE and NIST.  MITRE also maintains CVE\n"
           "(Common Vulnerability Enumeration) and other relevant security standards.\n"
           "\n"
           "The report selects all CPE tables from the results and forms a single table\n"
           "as a comma separated values file.\n',"
           " 'csv', 'text/csv', '', %i, %i, 1);",
           TRUST_YES,
           time (NULL));
      report_format = sqlite3_last_insert_rowid (task_db);
      verify_report_format (report_format);
    }

  if (sql_int (0, 0, "SELECT count(*) FROM report_formats WHERE name = 'HTML';")
      == 0)
    {
      report_format_t report_format;
      sql ("INSERT into report_formats (uuid, owner, name, summary, description,"
           " extension, content_type, signature, trust, trust_time, flags)"
           " VALUES ('b993b6f5-f9fb-4e6e-9c94-dd46c00e058d', NULL, 'HTML',"
           " 'Single page HTML report.',"
           " 'A single HTML page listing results of a scan.  Style information is embedded in\n"
           "the HTML, so the page is suitable for viewing in a browser as is.\n',"
           " 'html', 'text/html', '', %i, %i, 1);",
           TRUST_YES,
           time (NULL));
      report_format = sqlite3_last_insert_rowid (task_db);
      verify_report_format (report_format);
    }

  if (sql_int (0, 0, "SELECT count(*) FROM report_formats WHERE name = 'ITG';")
      == 0)
    {
      report_format_t report_format;
      sql ("INSERT into report_formats (uuid, owner, name, summary, description,"
           " extension, content_type, signature, trust, trust_time, flags)"
           " VALUES ('929884c6-c2c4-41e7-befb-2f6aa163b458', NULL, 'ITG',"
           " 'German \"IT-Grundschutz-Kataloge\" report.',"
           " 'Tabular report on the German \"IT-Grundschutz-Kataloge\",\n"
           "as published and maintained by the German Federal Agency for IT-Security.\n',"
           " 'csv', 'text/csv', '', %i, %i, 1);",
           TRUST_YES,
           time (NULL));
      report_format = sqlite3_last_insert_rowid (task_db);
      verify_report_format (report_format);
    }

  if (sql_int (0, 0, "SELECT count(*) FROM report_formats WHERE name = 'LaTeX';")
      == 0)
    {
      report_format_t report_format;
      sql ("INSERT into report_formats (uuid, owner, name, summary, description,"
           " extension, content_type, signature, trust, trust_time, flags)"
           " VALUES ('9f1ab17b-aaaa-411a-8c57-12df446f5588', NULL, 'LaTeX',"
           " 'LaTeX source file.',"
           " 'Report as LaTeX source file for further processing.\n',"
           " 'tex', 'text/plain', '', %i, %i, 1);",
           TRUST_YES,
           time (NULL));
      report_format = sqlite3_last_insert_rowid (task_db);
      verify_report_format (report_format);
    }

  if (sql_int (0, 0, "SELECT count(*) FROM report_formats WHERE name = 'NBE';")
      == 0)
    {
      report_format_t report_format;
      sql ("INSERT into report_formats (uuid, owner, name, summary, description,"
           " extension, content_type, signature, trust, trust_time, flags)"
           " VALUES ('f5c2a364-47d2-4700-b21d-0a7693daddab', NULL, 'NBE',"
           " 'Legacy OpenVAS report.',"
           " 'The traditional OpenVAS Scanner text based format.',"
           " 'nbe', 'text/plain', '', %i, %i, 1);",
           TRUST_YES,
           time (NULL));
      report_format = sqlite3_last_insert_rowid (task_db);
      verify_report_format (report_format);
    }

  if (sql_int (0, 0, "SELECT count(*) FROM report_formats WHERE name = 'PDF';")
      == 0)
    {
      report_format_t report_format;
      sql ("INSERT into report_formats (uuid, owner, name, summary, description,"
           " extension, content_type, signature, trust, trust_time, flags)"
           " VALUES ('1a60a67e-97d0-4cbf-bc77-f71b08e7043d', NULL, 'PDF',"
           " 'Portable Document Format report.',"
           " 'Scan results in Portable Document Format (PDF).',"
           "'pdf', 'application/pdf', '', %i, %i, 1);",
           TRUST_YES,
           time (NULL));
      report_format = sqlite3_last_insert_rowid (task_db);
      verify_report_format (report_format);
    }

  if (sql_int (0, 0, "SELECT count(*) FROM report_formats WHERE name = 'TXT';")
      == 0)
    {
      report_format_t report_format;
      sql ("INSERT into report_formats (uuid, owner, name, summary, description,"
           " extension, content_type, signature, trust, trust_time, flags)"
           " VALUES ('19f6f1b3-7128-4433-888c-ccc764fe6ed5', NULL, 'TXT',"
           " 'Plain text report.',"
           " 'Plain text report, best viewed with fixed font size.',"
           " 'txt', 'text/plain', '', %i, %i, 1);",
           TRUST_YES,
           time (NULL));
      report_format = sqlite3_last_insert_rowid (task_db);
      verify_report_format (report_format);
    }

  if (sql_int (0, 0, "SELECT count(*) FROM report_formats WHERE name = 'XML';")
      == 0)
    {
      report_format_t report_format;
      sql ("INSERT into report_formats (uuid, owner, name, summary, description,"
           " extension, content_type, signature, trust, trust_time, flags)"
           " VALUES ('d5da9f67-8551-4e51-807b-b6a873d70e34', NULL, 'XML',"
           " 'Raw XML report.',"
           " 'Complete scan report in OpenVAS Manager XML format.',"
           " 'xml', 'text/xml', '', %i, %i, 1);",
           TRUST_YES,
           time (NULL));
      report_format = sqlite3_last_insert_rowid (task_db);
      verify_report_format (report_format);
    }

  if (nvt_cache_mode == 0)
    {
      iterator_t tasks;

      /* Set requested, paused and running tasks to stopped. */

      assert (current_credentials.uuid == NULL);
      init_task_iterator (&tasks, 0, 1, NULL);
      while (next (&tasks))
        {
          switch (task_iterator_run_status (&tasks))
            {
              case TASK_STATUS_DELETE_REQUESTED:
              case TASK_STATUS_PAUSE_REQUESTED:
              case TASK_STATUS_PAUSE_WAITING:
              case TASK_STATUS_PAUSED:
              case TASK_STATUS_REQUESTED:
              case TASK_STATUS_RESUME_REQUESTED:
              case TASK_STATUS_RESUME_WAITING:
              case TASK_STATUS_RUNNING:
              case TASK_STATUS_STOP_REQUESTED:
              case TASK_STATUS_STOP_WAITING:
                {
                  task_t index = task_iterator_task (&tasks);
                  /* Set the current user, for event checks. */
                  current_credentials.uuid = task_owner_uuid (index);
                  set_task_run_status (index, TASK_STATUS_STOPPED);
                  free (current_credentials.uuid);
                  break;
                }
              default:
                break;
            }
        }
      cleanup_iterator (&tasks);
      current_credentials.uuid = NULL;

      /* Set requested and running reports to stopped. */

      sql ("UPDATE reports SET scan_run_status = %u"
           " WHERE scan_run_status = %u"
           " OR scan_run_status = %u"
           " OR scan_run_status = %u"
           " OR scan_run_status = %u"
           " OR scan_run_status = %u"
           " OR scan_run_status = %u"
           " OR scan_run_status = %u"
           " OR scan_run_status = %u"
           " OR scan_run_status = %u"
           " OR scan_run_status = %u;",
           TASK_STATUS_STOPPED,
           TASK_STATUS_DELETE_REQUESTED,
           TASK_STATUS_PAUSE_REQUESTED,
           TASK_STATUS_PAUSE_WAITING,
           TASK_STATUS_PAUSED,
           TASK_STATUS_REQUESTED,
           TASK_STATUS_RESUME_REQUESTED,
           TASK_STATUS_RESUME_WAITING,
           TASK_STATUS_RUNNING,
           TASK_STATUS_STOP_REQUESTED,
           TASK_STATUS_STOP_WAITING);
    }

  /* Load the NVT cache into memory. */

  if (nvti_cache == NULL)
    update_nvti_cache ();

  sqlite3_close (task_db);
  task_db = NULL;
  task_db_name = g_strdup (database);
  return 0;
}

/**
 * @brief Cleanup the manage library.
 *
 * Optionally put any running task in the stopped state and close the database.
 *
 * @param[in]  cleanup  If TRUE perform all cleanup operations, else only
 *                      those required at the start of a forked process.
 */
void
cleanup_manage_process (gboolean cleanup)
{
  if (task_db)
    {
      if (cleanup && current_scanner_task)
        set_task_run_status (current_scanner_task, TASK_STATUS_STOPPED);
      sqlite3_close (task_db);
      task_db = NULL;
    }
}

/**
 * @brief Cleanup as immediately as possible.
 *
 * Put any running task in the error state and close the database.
 *
 * Intended for handlers for signals like SIGSEGV and SIGABRT.
 *
 * @param[in]  signal  Dummy argument for use as signal handler.
 */
void
manage_cleanup_process_error (/*@unused@*/ int signal)
{
  if (task_db)
    {
      if (current_scanner_task)
        set_task_run_status (current_scanner_task, TASK_STATUS_INTERNAL_ERROR);
      sqlite3_close (task_db);
      task_db = NULL;
    }
}

/**
 * @brief Authenticate credentials.
 *
 * The user "om" will never be authenticated with success.
 *
 * @param[in]  credentials  Credentials.
 *
 * @return 0 authentication success, 1 authentication failure, -1 error.
 */
int
authenticate (credentials_t* credentials)
{
  if (credentials->username && credentials->password)
    {
      int fail;

      if (strcmp (credentials->username, "om") == 0) return 1;

      if (authenticate_allow_all)
        {
          /* This flag is set for scheduled tasks only. Take the stored uuid
           * to be able to tell apart locally authenticated vs remotely
           * authenticated users (in order to fetch the correct rules). */
          credentials->uuid = get_scheduled_user_uuid ();
          if (*credentials->uuid)
            return 0;
          return -1;
        }

      fail = openvas_authenticate_uuid (credentials->username,
                                        credentials->password,
                                        &credentials->uuid);
      // Authentication succeeded.
      if (fail == 0)
        {
          gchar* quoted_name;

          /* Ensure the user exists in the database.  SELECT then INSERT
           * instead of using "INSERT OR REPLACE", so that the ROWID stays
           * the same. */

          if (sql_int (0, 0,
                       "SELECT count(*) FROM users WHERE uuid = '%s';",
                       credentials->uuid))
            return 0;

          quoted_name = sql_quote (credentials->username);
          sql ("INSERT INTO users (uuid, name) VALUES ('%s', '%s');",
               credentials->uuid,
               quoted_name);
          g_free (quoted_name);
          return 0;
        }
      return fail;
    }
  return 1;
}

/**
 * @brief Return the number of tasks associated with the current user.
 *
 * @return The number of tasks associated with the current user.
 */
unsigned int
task_count ()
{
  return (unsigned int) sql_int (0, 0,
                                 "SELECT count(*) FROM tasks WHERE owner ="
                                 " (SELECT ROWID FROM users"
                                 "  WHERE users.uuid = '%s');",
                                 current_credentials.uuid);
}

/**
 * @brief Return the identifier of a task.
 *
 * @param[in]  task  Task.
 *
 * @return ID of task.
 */
unsigned int
task_id (task_t task)
{
  /** @todo The cast is a hack for compatibility with the old, alternate,
   *        FS based storage mechanism. */
  return (unsigned int) task;
}

/**
 * @brief Return the UUID of a task.
 *
 * @param[in]   task  Task.
 * @param[out]  id    Pointer to a newly allocated string.
 *
 * @return 0.
 */
int
task_uuid (task_t task, char ** id)
{
  *id = sql_string (0, 0,
                    "SELECT uuid FROM tasks WHERE ROWID = %llu;",
                    task);
  return 0;
}

/**
 * @brief Return the name of the owner of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Newly allocated user name.
 */
char*
task_owner_name (task_t task)
{
  return sql_string (0, 0,
                     "SELECT name FROM users WHERE ROWID ="
                     " (SELECT owner FROM tasks WHERE ROWID = %llu);",
                     task);
}

/**
 * @brief Return the name of the owner of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Newly allocated user name.
 */
static char*
task_owner_uuid (task_t task)
{
  return sql_string (0, 0,
                     "SELECT uuid FROM users WHERE ROWID ="
                     " (SELECT owner FROM tasks WHERE ROWID = %llu);",
                     task);
}

/**
 * @brief Return the name of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Task name.
 */
char*
task_name (task_t task)
{
  return sql_string (0, 0,
                     "SELECT name FROM tasks WHERE ROWID = %llu;",
                     task);
}

/**
 * @brief Return the comment of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Comment of task.
 */
char*
task_comment (task_t task)
{
  return sql_string (0, 0,
                     "SELECT comment FROM tasks WHERE ROWID = %llu;",
                     task);
}

/**
 * @brief Return the config of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Config of task.
 */
config_t
task_config (task_t task)
{
  config_t config;
  switch (sql_int64 (&config, 0, 0,
                     "SELECT config FROM tasks WHERE ROWID = %llu;",
                     task))
    {
      case 0:
        return config;
      default:       /* Programming error. */
      case 1:        /* Too few rows in result of query. */
      case -1:       /* Error. */
        /* Every task should have a config. */
        assert (0);
        return 0;
        break;
    }
}

/**
 * @brief Return the UUID of the config of a task.
 *
 * @param[in]  task  Task.
 *
 * @return UUID of config of task.
 */
char*
task_config_uuid (task_t task)
{
  return sql_string (0, 0,
                     "SELECT uuid FROM configs WHERE ROWID ="
                     " (SELECT config FROM tasks WHERE ROWID = %llu);",
                     task);
}

/**
 * @brief Return the name of the config of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Name of config of task.
 */
char*
task_config_name (task_t task)
{
  return sql_string (0, 0,
                     "SELECT name FROM configs WHERE ROWID ="
                     " (SELECT config FROM tasks WHERE ROWID = %llu);",
                     task);
}

/**
 * @brief Set the config of a task.
 *
 * @param[in]  task    Task.
 * @param[in]  config  Config.
 */
void
set_task_config (task_t task, config_t config)
{
  sql ("UPDATE tasks SET config = %llu WHERE ROWID = %llu;", config, task);
}

/**
 * @brief Return the target of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Target of task.
 */
target_t
task_target (task_t task)
{
  target_t target = 0;
  switch (sql_int64 (&target, 0, 0,
                     "SELECT target FROM tasks WHERE ROWID = %llu;",
                     task))
    {
      case 0:
        return target;
        break;
      case 1:        /* Too few rows in result of query. */
      default:       /* Programming error. */
        assert (0);
      case -1:
        return 0;
        break;
    }
}

/**
 * @brief Set the target of a task.
 *
 * @param[in]  task    Task.
 * @param[in]  target  Target.
 */
void
set_task_target (task_t task, target_t target)
{
  sql ("UPDATE tasks SET target = %llu WHERE ROWID = %llu;", target, task);
}

/**
 * @brief Return the slave of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Slave of task.
 */
slave_t
task_slave (task_t task)
{
  slave_t slave = 0;
  switch (sql_int64 (&slave, 0, 0,
                     "SELECT slave FROM tasks WHERE ROWID = %llu;",
                     task))
    {
      case 0:
        return slave;
        break;
      case 1:        /* Too few rows in result of query. */
      default:       /* Programming error. */
        assert (0);
      case -1:
        return 0;
        break;
    }
}

/**
 * @brief Set the slave of a task.
 *
 * @param[in]  task   Task.
 * @param[in]  slave  Slave.
 */
void
set_task_slave (task_t task, slave_t slave)
{
  sql ("UPDATE tasks SET slave = %llu WHERE ROWID = %llu;", slave, task);
}

/**
 * @brief Return the description of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Description of task.
 */
char*
task_description (task_t task)
{
  return sql_string (0, 0,
                     "SELECT description FROM tasks WHERE ROWID = %llu;",
                     task);
}

/**
 * @brief Set the description of a task.
 *
 * @param[in]  task         Task.
 * @param[in]  description  Description.  Used directly, freed by free_task.
 * @param[in]  length       Length of description.
 */
void
set_task_description (task_t task, char* description, gsize length)
{
  gchar* quote = sql_nquote (description, strlen (description));
  sql ("UPDATE tasks SET description = '%s' WHERE ROWID = %llu;",
       quote,
       task);
  g_free (quote);
}

/**
 * @brief Return the run state of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Task run status.
 */
task_status_t
task_run_status (task_t task)
{
  return (unsigned int) sql_int (0, 0,
                                 "SELECT run_status FROM tasks WHERE ROWID = %llu;",
                                 task);
}

/**
 * @brief Set the run state of a task.
 *
 * @param[in]  task    Task.
 * @param[in]  status  New run status.
 */
void
set_task_run_status (task_t task, task_status_t status)
{
  char *uuid;
  char *name;

  if ((task == current_scanner_task) && current_report)
    sql ("UPDATE reports SET scan_run_status = %u WHERE ROWID = %llu;",
         status,
         current_report);
  sql ("UPDATE tasks SET run_status = %u WHERE ROWID = %llu;",
       status,
       task);

  task_uuid (task, &uuid);
  name = task_name (task);
  g_log ("event task", G_LOG_LEVEL_MESSAGE,
         "Status of task %s (%s) has changed to %s",
         name, uuid, run_status_name (status));
  free (uuid);
  free (name);

  event (task, EVENT_TASK_RUN_STATUS_CHANGED, (void*) status);
}

/**
 * @brief Atomically set the run state of a task to requested.
 *
 * @param[in]  task    Task.
 * @param[out] status  Old run status of task.
 *
 * @return 0 success, 1 task is active already.
 */
int
set_task_requested (task_t task, task_status_t *status)
{
  task_status_t run_status;

  sql ("BEGIN EXCLUSIVE;");

  run_status = task_run_status (task);
  if (run_status == TASK_STATUS_REQUESTED
      || run_status == TASK_STATUS_RUNNING
      || run_status == TASK_STATUS_PAUSE_REQUESTED
      || run_status == TASK_STATUS_PAUSE_WAITING
      || run_status == TASK_STATUS_PAUSED
      || run_status == TASK_STATUS_RESUME_REQUESTED
      || run_status == TASK_STATUS_RESUME_WAITING
      || run_status == TASK_STATUS_STOP_REQUESTED
      || run_status == TASK_STATUS_STOP_WAITING
      || run_status == TASK_STATUS_DELETE_REQUESTED)
    {
      sql ("END;");
      *status = run_status;
      return 1;
    }

  set_task_run_status (task, TASK_STATUS_REQUESTED);

  sql ("COMMIT;");

  *status = run_status;
  return 0;
}

/**
 * @brief Return the running report of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Current report of task if task is active, else (report_t) 0.
 */
report_t
task_running_report (task_t task)
{
  task_status_t run_status = task_run_status (task);
  if (run_status == TASK_STATUS_REQUESTED
      || run_status == TASK_STATUS_RUNNING)
    {
      return (unsigned int) sql_int (0, 0,
                                     "SELECT max(ROWID) FROM reports"
                                     " WHERE task = %llu AND end_time IS NULL"
                                     " AND scan_run_status = %u;",
                                     task,
                                     TASK_STATUS_RUNNING);
    }
  return (report_t) 0;
}

/**
 * @brief Return the current report of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Current report of task if task is active, else (report_t) 0.
 */
report_t
task_current_report (task_t task)
{
  task_status_t run_status = task_run_status (task);
  if (run_status == TASK_STATUS_REQUESTED
      || run_status == TASK_STATUS_RUNNING
      || run_status == TASK_STATUS_STOP_REQUESTED
      || run_status == TASK_STATUS_STOPPED
      || run_status == TASK_STATUS_PAUSE_REQUESTED
      || run_status == TASK_STATUS_PAUSED
      || run_status == TASK_STATUS_RESUME_REQUESTED)
    {
      return (unsigned int) sql_int (0, 0,
                                     "SELECT max(ROWID) FROM reports"
                                     " WHERE task = %llu"
                                     " AND (scan_run_status = %u"
                                     " OR scan_run_status = %u"
                                     " OR scan_run_status = %u"
                                     " OR scan_run_status = %u"
                                     " OR scan_run_status = %u"
                                     " OR scan_run_status = %u"
                                     " OR scan_run_status = %u);",
                                     task,
                                     TASK_STATUS_REQUESTED,
                                     TASK_STATUS_RUNNING,
                                     TASK_STATUS_STOP_REQUESTED,
                                     TASK_STATUS_STOPPED,
                                     TASK_STATUS_PAUSE_REQUESTED,
                                     TASK_STATUS_PAUSED,
                                     TASK_STATUS_RESUME_REQUESTED);
    }
  return (report_t) 0;
}

/**
 * @brief Return the most recent start time of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Task start time.
 */
char*
task_start_time (task_t task)
{
  return sql_string (0, 0,
                     "SELECT start_time FROM tasks WHERE ROWID = %llu;",
                     task);
}

/**
 * @brief Set the start time of a task.
 *
 * @param[in]  task  Task.
 * @param[in]  time  New time.  Freed before return.
 */
void
set_task_start_time (task_t task, char* time)
{
  sql ("UPDATE tasks SET start_time = '%.*s' WHERE ROWID = %llu;",
       strlen (time),
       time,
       task);
  free (time);
}

/**
 * @brief Return the most recent end time of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Task end time.
 */
char*
task_end_time (task_t task)
{
  return sql_string (0, 0,
                     "SELECT end_time FROM tasks WHERE ROWID = %llu;",
                     task);
}

/**
 * @brief Get the report from the most recently completed invocation of task.
 *
 * @param[in]  task    The task.
 * @param[out] report  Report return, 0 if succesfully failed to select report.
 *
 * @return 0 success, -1 error.
 */
static int
task_last_report (task_t task, report_t *report)
{
  switch (sql_int64 (report, 0, 0,
                     "SELECT ROWID FROM reports WHERE task = %llu"
                     " AND scan_run_status = %u"
                     " ORDER BY date DESC LIMIT 1;",
                     task,
                     TASK_STATUS_DONE))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *report = 0;
        return 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        return -1;
        break;
    }
  return 0;
}

/**
 * @brief Get the report from second most recently completed invocation of task.
 *
 * @param[in]  task    The task.
 * @param[out] report  Report return, 0 if succesfully failed to select report.
 *
 * @return 0 success, -1 error.
 */
static int
task_second_last_report (task_t task, report_t *report)
{
  switch (sql_int64 (report, 0, 1,
                     "SELECT ROWID FROM reports WHERE task = %llu"
                     " AND scan_run_status = %u"
                     " ORDER BY date DESC LIMIT 2;",
                     task,
                     TASK_STATUS_DONE))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *report = 0;
        return 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        return -1;
        break;
    }
  return 0;
}

/**
 * @brief Get the report from the most recently stopped invocation of task.
 *
 * @param[in]  task    The task.
 * @param[out] report  Report return, 0 if succesfully failed to select report.
 *
 * @return 0 success, -1 error.
 */
int
task_last_stopped_report (task_t task, report_t *report)
{
  switch (sql_int64 (report, 0, 0,
                     "SELECT ROWID FROM reports WHERE task = %llu"
                     " AND scan_run_status = %u"
                     " ORDER BY date DESC LIMIT 1;",
                     task,
                     TASK_STATUS_STOPPED))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *report = 0;
        return 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        return -1;
        break;
    }
  return 0;
}

/**
 * @brief Get the report ID from the very first completed invocation of task.
 *
 * @param[in]  task  The task.
 *
 * @return The UUID of the task as a newly allocated string.
 */
gchar*
task_first_report_id (task_t task)
{
  return sql_string (0, 0,
                     "SELECT uuid FROM reports WHERE task = %llu"
                     " AND scan_run_status = %u"
                     " ORDER BY date ASC LIMIT 1;",
                     task,
                     TASK_STATUS_DONE);
}

/**
 * @brief Get the report ID from the most recently completed invocation of task.
 *
 * @param[in]  task  The task.
 *
 * @return The UUID of the report as a newly allocated string.
 */
gchar*
task_last_report_id (task_t task)
{
  return sql_string (0, 0,
                     "SELECT uuid FROM reports WHERE task = %llu"
                     " AND scan_run_status = %u"
                     " ORDER BY date DESC LIMIT 1;",
                     task,
                     TASK_STATUS_DONE);
}

/**
 * @brief Get report ID from second most recently completed invocation of task.
 *
 * @param[in]  task  The task.
 *
 * @return The UUID of the report as a newly allocated string.
 */
gchar*
task_second_last_report_id (task_t task)
{
  return sql_string (0, 1,
                     "SELECT uuid FROM reports WHERE task = %llu"
                     " AND scan_run_status = %u"
                     " ORDER BY date DESC LIMIT 2;",
                     task,
                     TASK_STATUS_DONE);
}

/**
 * @brief Return the name of the escalator of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Name of escalator of task if any, else NULL.
 */
char*
task_escalator_name (task_t task)
{
  return sql_string (0, 0,
                     "SELECT name FROM escalators"
                     " WHERE ROWID ="
                     " (SELECT escalator FROM task_escalators"
                     "  WHERE task = %llu LIMIT 1);",
                     task);
}

/**
 * @brief Return the UUID of the escalator of a task.
 *
 * @param[in]  task  Task.
 *
 * @return UUID of escalator of task if any, else NULL.
 */
char*
task_escalator_uuid (task_t task)
{
  return sql_string (0, 0,
                     "SELECT uuid FROM escalators"
                     " WHERE ROWID ="
                     " (SELECT escalator FROM task_escalators"
                     "  WHERE task = %llu LIMIT 1);",
                     task);
}

/**
 * @brief Return the escalator of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Escalator of task if any, else NULL.
 */
escalator_t
task_escalator (task_t task)
{
  escalator_t escalator = 0;
  switch (sql_int64 (&escalator, 0, 0,
                     "SELECT escalator FROM tasks WHERE ROWID = %llu;",
                     task))
    {
      case 0:
        return escalator;
        break;
      case 1:        /* Too few rows in result of query. */
      default:       /* Programming error. */
        assert (0);
      case -1:
        return 0;
        break;
    }
}

/**
 * @brief Add an escalator to a task.
 *
 * @param[in]  task       Task.
 * @param[in]  escalator  Escalator.
 */
void
add_task_escalator (task_t task, escalator_t escalator)
{
  sql ("INSERT INTO task_escalators (task, escalator)"
       " VALUES (%llu, %llu);",
       task,
       escalator);
}

/**
 * @brief Add an escalator to a task, removing any existing ones.
 *
 * @param[in]  task       Task.
 * @param[in]  escalator  Escalator.
 */
void
set_task_escalator (task_t task, escalator_t escalator)
{
  sql ("DELETE FROM task_escalators where task = %llu;", task);
  sql ("INSERT INTO task_escalators (task, escalator)"
       " VALUES (%llu, %llu);",
       task,
       escalator);
}

/**
 * @brief Set the schedule of a task.
 *
 * @param[in]  task      Task.
 * @param[in]  schedule  Schedule.
 */
void
set_task_schedule (task_t task, schedule_t schedule)
{
  sql ("UPDATE tasks SET schedule = %llu, schedule_next_time = "
       " (SELECT schedules.first_time FROM schedules WHERE ROWID = %llu)"
       " WHERE ROWID = %llu;",
       schedule,
       schedule,
       task);
}

/**
 * @brief Return the threat level of a task, taking overrides into account.
 *
 * @param[in]  task  Task.
 *
 * @return Threat level of last report on task if there is one, as a static
 *         string, else NULL.
 */
const char*
task_threat_level (task_t task)
{
  char *type;
  gchar *ov, *new_type_sql;

  assert (current_credentials.uuid);

  ov = g_strdup_printf
        ("SELECT overrides.new_threat"
         " FROM overrides"
         " WHERE overrides.nvt = results.nvt"
         " AND ((overrides.owner IS NULL)"
         " OR (overrides.owner ="
         " (SELECT ROWID FROM users"
         "  WHERE users.uuid = '%s')))"
         " AND (overrides.task ="
         "      (SELECT reports.task FROM reports"
         "       WHERE report_results.report = reports.ROWID)"
         "      OR overrides.task = 0)"
         " AND (overrides.result = results.ROWID"
         "      OR overrides.result = 0)"
         " AND (overrides.hosts is NULL"
         "      OR overrides.hosts = \"\""
         "      OR hosts_contains (overrides.hosts, results.host))"
         " AND (overrides.port is NULL"
         "      OR overrides.port = \"\""
         "      OR overrides.port = results.port)"
         " AND (overrides.threat is NULL"
         "      OR overrides.threat = \"\""
         "      OR overrides.threat = results.type)"
         " ORDER BY overrides.result DESC, overrides.task DESC,"
         " overrides.port DESC, overrides.threat"
         " COLLATE collate_message_type ASC",
         current_credentials.uuid);

  new_type_sql = g_strdup_printf ("(CASE WHEN (%s) IS NULL"
                                  " THEN type ELSE (%s) END)",
                                  ov, ov);

  g_free (ov);

  type = sql_string (0, 0,
                     " SELECT %s AS new_type FROM results, report_results"
                     " WHERE report_results.report ="
                     " (SELECT ROWID FROM reports WHERE reports.task = %llu"
                     "  AND reports.scan_run_status = %u"
                     "  ORDER BY reports.date DESC LIMIT 1)"
                     " AND results.ROWID = report_results.result"
                     " ORDER BY new_type COLLATE collate_message_type DESC"
                     " LIMIT 1",
                     new_type_sql,
                     task,
                     TASK_STATUS_DONE);

  g_free (new_type_sql);

  if (type == NULL)
    return NULL;

  if (strcmp (type, "Security Hole") == 0)
    {
      free (type);
      return "High";
    }

  if (strcmp (type, "Security Warning") == 0)
    {
      free (type);
      return "Medium";
    }

  if (strcmp (type, "Security Note") == 0)
    {
      free (type);
      return "Low";
    }

  if (strcmp (type, "Log Message") == 0)
    {
      free (type);
      return "Log";
    }

  if (strcmp (type, "Debug Message") == 0)
    {
      free (type);
      return "Debug";
    }

  if (strcmp (type, "False Positive") == 0)
    {
      free (type);
      return "False Positive";
    }

  free (type);
  return NULL;
}

/**
 * @brief Return the previous threat level of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Threat level of the second last report on task if there is one, as a
 *         static string, else NULL.
 */
static const char*
task_previous_threat_level (task_t task)
{
  char *type;
  gchar *ov, *new_type_sql;

  assert (current_credentials.uuid);

  ov = g_strdup_printf
        ("SELECT overrides.new_threat"
         " FROM overrides"
         " WHERE overrides.nvt = results.nvt"
         " AND ((overrides.owner IS NULL)"
         " OR (overrides.owner ="
         " (SELECT ROWID FROM users"
         "  WHERE users.uuid = '%s')))"
         " AND (overrides.task ="
         "      (SELECT reports.task FROM reports"
         "       WHERE report_results.report = reports.ROWID)"
         "      OR overrides.task = 0)"
         " AND (overrides.result = results.ROWID"
         "      OR overrides.result = 0)"
         " AND (overrides.hosts is NULL"
         "      OR overrides.hosts = \"\""
         "      OR hosts_contains (overrides.hosts, results.host))"
         " AND (overrides.port is NULL"
         "      OR overrides.port = \"\""
         "      OR overrides.port = results.port)"
         " AND (overrides.threat is NULL"
         "      OR overrides.threat = \"\""
         "      OR overrides.threat = results.type)"
         " ORDER BY overrides.result DESC, overrides.task DESC,"
         " overrides.port DESC, overrides.threat"
         " COLLATE collate_message_type ASC",
         current_credentials.uuid);

  new_type_sql = g_strdup_printf ("(CASE WHEN (%s) IS NULL"
                                  " THEN type ELSE (%s) END)",
                                  ov, ov);

  g_free (ov);

  type = sql_string (0, 0,
                     " SELECT %s AS new_type FROM results, report_results"
                     " WHERE report_results.report ="
                     " (SELECT ROWID FROM reports WHERE reports.task = %llu"
                     "  AND reports.scan_run_status = %u"
                     "  ORDER BY reports.date DESC LIMIT 2 OFFSET 1)"
                     " AND results.ROWID = report_results.result"
                     " ORDER BY new_type COLLATE collate_message_type DESC"
                     " LIMIT 1",
                     new_type_sql,
                     task,
                     TASK_STATUS_DONE);

  g_free (new_type_sql);

  if (type == NULL)
    return NULL;

  if (strcmp (type, "Security Hole") == 0)
    {
      free (type);
      return "High";
    }

  if (strcmp (type, "Security Warning") == 0)
    {
      free (type);
      return "Medium";
    }

  if (strcmp (type, "Security Note") == 0)
    {
      free (type);
      return "Low";
    }

  if (strcmp (type, "Log Message") == 0)
    {
      free (type);
      return "Log";
    }

  if (strcmp (type, "Debug Message") == 0)
    {
      free (type);
      return "Debug";
    }

  if (strcmp (type, "False Positive") == 0)
    {
      free (type);
      return "False Positive";
    }

  free (type);
  return NULL;
}

/**
 * @brief Return the schedule of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Schedule.
 */
schedule_t
task_schedule (task_t task)
{
  schedule_t schedule = 0;
  switch (sql_int64 (&schedule, 0, 0,
                     "SELECT schedule FROM tasks WHERE ROWID = %llu;",
                     task))
    {
      case 0:
        return schedule;
        break;
      case 1:        /* Too few rows in result of query. */
      default:       /* Programming error. */
        assert (0);
      case -1:
        return 0;
        break;
    }
}

/**
 * @brief Get the next time a task with a schedule will run.
 *
 * @param[in]  task  Task.
 *
 * @return If the task has a schedule, the next time the task will run (0 if it
 *         has already run), otherwise 0.
 */
int
task_schedule_next_time (task_t task)
{
  return sql_int (0, 0,
                  "SELECT schedule_next_time FROM tasks"
                  " WHERE ROWID = %llu;",
                  task);
}

/**
 * @brief Set the next time a scheduled task will be due.
 *
 * @param[in]  task  Task.
 * @param[in]  time  New next time.
 */
void
set_task_schedule_next_time (task_t task, time_t time)
{
  sql ("UPDATE tasks SET schedule_next_time = %i WHERE ROWID = %llu;",
       time, task);
}

/**
 * @brief Generate rcfile in task from config and target.
 *
 * @param[in]  task  The task.
 *
 * @return 0 success, -1 error.
 */
int
make_task_rcfile (task_t task)
{
  config_t config;
  target_t target;
  char *config_name, *selector, *hosts, *rc;
  iterator_t prefs;
  GString *buffer;

  config = task_config (task);

  config_name = task_config_name (task);
  if (config_name == NULL) return -1;

  target = task_target (task);
  if (target == 0)
    {
      free (config_name);
      return -1;
    }

  selector = config_nvt_selector (config);
  if (selector == NULL)
    {
      free (config_name);
      return -1;
    }

  /* Header. */

  buffer = g_string_new ("# This file was automatically created"
                         " by openvasmd, the OpenVAS Manager daemon.\n");

  /* General preferences. */

  init_preference_iterator (&prefs, config, NULL);
  while (next (&prefs))
    g_string_append_printf (buffer,
                            "%s = %s\n",
                            preference_iterator_name (&prefs),
                            preference_iterator_value (&prefs));
  cleanup_iterator (&prefs);

  /* Targets for general preferences. */

  hosts = target_hosts (target);
  if (hosts)
    g_string_append_printf (buffer, "targets = %s\n\n", hosts);
  else
    {
      free (hosts);
      free (config_name);
      free (selector);
      g_string_free (buffer, TRUE);
      return -1;
    }
  free (hosts);

  /* Scanner set. */

  g_string_append (buffer, "begin(SCANNER_SET)\n");
  /** @todo How know if scanner? (?) */
  g_string_append (buffer, "end(SCANNER_SET)\n\n");

  /* Scanner preferences. */

  g_string_append (buffer, "begin(SERVER_PREFS)\n");
  init_preference_iterator (&prefs, config, "SERVER_PREFS");
  while (next (&prefs))
    g_string_append_printf (buffer,
                            " %s = %s\n",
                            preference_iterator_name (&prefs),
                            preference_iterator_value (&prefs));
  cleanup_iterator (&prefs);
  g_string_append (buffer, "end(SERVER_PREFS)\n\n");

  /* Client side user rules. */

  g_string_append (buffer, "begin(CLIENTSIDE_USERRULES)\n");
  g_string_append (buffer, "end(CLIENTSIDE_USERRULES)\n\n");

  /* Plugin preferences. */

  g_string_append (buffer, "begin(PLUGINS_PREFS)\n");
  init_preference_iterator (&prefs, config, "PLUGINS_PREFS");
  while (next (&prefs))
    g_string_append_printf (buffer,
                            " %s = %s\n",
                            preference_iterator_name (&prefs),
                            preference_iterator_value (&prefs));
  cleanup_iterator (&prefs);
  g_string_append (buffer, "end(PLUGINS_PREFS)\n\n");

  /* Plugin set. */

  g_string_append (buffer, "begin(PLUGIN_SET)\n");
  {
    /* This block is a modified copy of nvt_selector_plugins (from
     * manage.c). */
    /** @todo This may be better as "config_families_growing (config)". */
    if (nvt_selector_nvts_growing (selector))
      {
        /** @todo Do other cases. (?) */
        if ((sql_int (0, 0,
                      "SELECT COUNT(*) FROM nvt_selectors WHERE name = '%s';",
                      selector)
             == 1)
            && (sql_int (0, 0,
                         "SELECT COUNT(*) FROM nvt_selectors"
                         " WHERE name = '%s'"
                         " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_ALL)
                         ";",
                         selector)
                == 1))
          {
            iterator_t nvts;

            init_nvt_iterator (&nvts, (nvt_t) 0, (config_t) 0, NULL, 1, NULL);
            while (next (&nvts))
              g_string_append_printf (buffer,
                                      " %s = yes\n",
                                      nvt_iterator_oid (&nvts));
            cleanup_iterator (&nvts);
          }
      }
    else
      {
        iterator_t nvts;

        init_nvt_selector_iterator (&nvts, selector, (config_t) 0, 2);
        while (next (&nvts))
          g_string_append_printf (buffer,
                                  " %s = %s\n",
                                  nvt_selector_iterator_nvt (&nvts),
                                  nvt_selector_iterator_include (&nvts)
                                  ? "yes" : "no");
        cleanup_iterator (&nvts);
      }
  }
  g_string_append (buffer, "end(PLUGIN_SET)\n\n");

  /* Scanner info. */

  g_string_append (buffer, "begin(SERVER_INFO)\n");
  g_string_append (buffer, "end(SERVER_INFO)\n");

  free (config_name);
  free (selector);

  rc = g_string_free (buffer, FALSE);

  set_task_description (task, rc, strlen (rc));
  free (rc);

  return 0;
}


/* Results. */

/**
 * @brief Find a result given a UUID.
 *
 * @param[in]   uuid    UUID of result.
 * @param[out]  result  Result return, 0 if succesfully failed to find result.
 *
 * @return FALSE on success (including if failed to find result), TRUE on error.
 */
gboolean
find_result (const char* uuid, result_t* result)
{
  if (user_owns_result (uuid) == 0)
    {
      *result = 0;
      return FALSE;
    }
  switch (sql_int64 (result, 0, 0,
                     "SELECT ROWID FROM results WHERE uuid = '%s';",
                     uuid))
    {
      case 0:
        break;
      case 1:        /* Too few rows in outcome of query. */
        *result = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        return TRUE;
        break;
    }

  return FALSE;
}

/**
 * @brief Make a result.
 *
 * @param[in]  task         The task associated with the result.
 * @param[in]  subnet       Subnet.
 * @param[in]  host         Host.
 * @param[in]  port         The port the result refers to.
 * @param[in]  nvt          The OID of the NVT that produced the result.
 * @param[in]  type         Type of result.  "Security Hole", etc.
 * @param[in]  description  Description of the result.
 *
 * @return A result descriptor for the new result.
 */
result_t
make_result (task_t task, const char* subnet, const char* host,
             const char* port, const char* nvt, const char* type,
             const char* description)
{
  result_t result;
  gchar *quoted_descr = sql_quote (description);
  sql ("INSERT into results"
       " (task, subnet, host, port, nvt, type, description, uuid)"
       " VALUES"
       " (%llu, '%s', '%s', '%s', '%s', '%s', '%s', make_uuid ());",
       task, subnet, host, port, nvt, type, quoted_descr);
  g_free (quoted_descr);
  result = sqlite3_last_insert_rowid (task_db);
  return result;
}

/**
 * @brief Return the UUID of a result.
 *
 * @param[in]   result  Result.
 * @param[out]  id      Pointer to a newly allocated string.
 *
 * @return 0.
 */
int
result_uuid (result_t result, char ** id)
{
  *id = sql_string (0, 0,
                    "SELECT uuid FROM results WHERE ROWID = %llu;",
                    result);
  return 0;
}


/* Reports. */

/**
 * @brief Make a report.
 *
 * @param[in]  task    The task associated with the report.
 * @param[in]  uuid    The UUID of the report.
 * @param[in]  status  The run status of the scan associated with the report.
 *
 * @return A report descriptor for the new report.
 */
report_t
make_report (task_t task, const char* uuid, task_status_t status)
{
  report_t report;

  assert (current_credentials.uuid);

  sql ("INSERT into reports (uuid, owner, hidden, task, date, nbefile, comment,"
       " scan_run_status, slave_progress, slave_task_uuid)"
       " VALUES ('%s',"
       " (SELECT ROWID FROM users WHERE users.uuid = '%s'),"
       " 0, %llu, %i, '', '', %u, 0, '');",
       uuid, current_credentials.uuid, task, time (NULL), status);
  report = sqlite3_last_insert_rowid (task_db);
  return report;
}

/**
 * @brief Create the current report for a task.
 *
 * @param[in]   task       The task.
 * @param[out]  report_id  Report ID.
 * @param[in]   status     Run status of scan associated with report.
 *
 * @return 0 success, -1 current_report is already set, -2 failed to generate ID.
 */
int
create_report (task_t task, char **report_id, task_status_t status)
{
  char *id;

  assert (current_report == (report_t) 0);

  if (current_report) return -1;

  if (report_id == NULL) report_id = &id;

  /* Generate report UUID. */

  *report_id = openvas_uuid_make ();
  if (*report_id == NULL) return -2;

  /* Create the report. */

  current_report = make_report (task, *report_id, status);

  return 0;
}

/**
 * @brief Return the UUID of a report.
 *
 * @param[in]  report  Report.
 *
 * @return Report UUID.
 */
char*
report_uuid (report_t report)
{
  return sql_string (0, 0,
                     "SELECT uuid FROM reports WHERE ROWID = %llu;",
                     report);
}

/**
 * @brief Return the task of a report.
 *
 * @param[in]   report  A report.
 * @param[out]  task    Task return, 0 if succesfully failed to find task.
 *
 * @return FALSE on success (including if failed to find report), TRUE on error.
 */
gboolean
report_task (report_t report, task_t *task)
{
  switch (sql_int64 (task, 0, 0,
                     "SELECT task FROM reports WHERE ROWID = %llu;",
                     report))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *task = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        return TRUE;
        break;
    }
  return FALSE;
}

/**
 * @brief Add a result to a report.
 *
 * @param[in]  report  The report.
 * @param[in]  result  The result.
 */
void
report_add_result (report_t report, result_t result)
{
  sql ("INSERT into report_results (report, result)"
       " VALUES (%llu, %llu);",
       report, result);
}

/**
 * @brief Initialise a report iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  task      Task whose reports the iterator loops over.  0 for all.
 *                       Overridden by \arg report.
 * @param[in]  report    Single report to iterate over over.  0 for all.
 */
void
init_report_iterator (iterator_t* iterator, task_t task, report_t report)
{
  if (report)
    init_iterator (iterator,
                   "SELECT ROWID, uuid FROM reports WHERE ROWID = %llu;",
                   report);
  else if (task)
    init_iterator (iterator,
                   "SELECT ROWID, uuid FROM reports WHERE task = %llu;",
                   task);
  else
    init_iterator (iterator,
                   "SELECT ROWID, uuid FROM reports;");
}

#if 0
/**
 * @brief Get the NAME from a host iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The NAME of the host.  Caller must use only before calling
 *         cleanup_iterator.
 */
#endif

/**
 * @brief Generate accessor for an SQL iterator.
 *
 * @param[in]  name  Name of accessor.
 * @param[in]  col   Column number to access.
 */
#define DEF_ACCESS(name, col) \
const char* \
name (iterator_t* iterator) \
{ \
  const char *ret; \
  if (iterator->done) return NULL; \
  ret = (const char*) sqlite3_column_text (iterator->stmt, col); \
  return ret; \
}

/**
 * @brief Get the UUID from a report iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return UUID, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (report_iterator_uuid, 1);

#undef DEF_ACCESS

/**
 * @brief Read the next report from an iterator.
 *
 * @param[in]   iterator  Task iterator.
 * @param[out]  report    Report.
 *
 * @return TRUE if there was a next task, else FALSE.
 */
gboolean
next_report (iterator_t* iterator, report_t* report)
{
  int ret;

  if (iterator->done) return FALSE;

  while ((ret = sqlite3_step (iterator->stmt)) == SQLITE_BUSY);
  if (ret == SQLITE_DONE)
    {
      iterator->done = TRUE;
      return FALSE;
    }
  if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
    {
      if (ret == SQLITE_ERROR) ret = sqlite3_reset (iterator->stmt);
      g_warning ("%s: sqlite3_step failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      abort ();
    }
  *report = sqlite3_column_int64 (iterator->stmt, 0);
  return TRUE;
}

/**
 * @brief Return SQL WHERE for restricting a SELECT to levels.
 *
 * @param[in]  levels  String describing threat levels (message types)
 *                     to include in report (for example, "hmlgd" for
 *                     High, Medium, Low, loG and Debug).  All levels if
 *                     NULL.
 *
 * @return WHERE clause for levels if one is required, else NULL.
 */
static GString *
where_levels (const char* levels)
{
  int count;
  GString *levels_sql;

  /* Generate SQL for constraints on message type, according to levels. */

  if (levels == NULL || strlen (levels) == 0)
    return NULL;

  levels_sql = NULL;
  count = 0;

  /* High. */
  if (strchr (levels, 'h'))
    {
      count = 1;
      levels_sql = g_string_new (" AND (new_type = 'Security Hole'");
    }

  /* Medium. */
  if (strchr (levels, 'm'))
    {
      if (count == 0)
        levels_sql = g_string_new (" AND (new_type = 'Security Warning'");
      else
        levels_sql = g_string_append (levels_sql,
                                      " OR new_type = 'Security Warning'");
      count++;
    }

  /* Low. */
  if (strchr (levels, 'l'))
    {
      if (count == 0)
        levels_sql = g_string_new (" AND (new_type = 'Security Note'");
      else
        levels_sql = g_string_append (levels_sql,
                                      " OR new_type = 'Security Note'");
      count++;
    }

  /* loG. */
  if (strchr (levels, 'g'))
    {
      if (count == 0)
        levels_sql = g_string_new (" AND (new_type = 'Log Message'");
      else
        levels_sql = g_string_append (levels_sql,
                                      " OR new_type = 'Log Message'");
      count++;
    }

  /* Debug. */
  if (strchr (levels, 'd'))
    {
      if (count == 0)
        levels_sql = g_string_new (" AND (new_type = 'Debug Message'");
      else
        levels_sql = g_string_append (levels_sql,
                                      " OR new_type = 'Debug Message'");
      count++;
    }

  /* False Positive. */
  if (strchr (levels, 'f'))
    {
      if (count == 0)
        levels_sql = g_string_new (" AND (new_type = 'False Positive')");
      else
        levels_sql = g_string_append (levels_sql,
                                      " OR new_type = 'False Positive')");
      count++;
    }
  else if (count)
    levels_sql = g_string_append (levels_sql, ")");

  if (count == 6)
    {
      /* All levels. */
      g_string_free (levels_sql, TRUE);
      levels_sql = NULL;
    }

  return levels_sql;
}

/**
 * @brief Return SQL WHERE for restricting a SELECT to levels by type column.
 *
 * @param[in]  levels  String describing threat levels (message types)
 *                     to include in report (for example, "hmlgd" for
 *                     High, Medium, Low, loG and Debug).  All levels if
 *                     NULL.
 *
 * @return WHERE clause for levels if one is required, else NULL.
 */
static GString *
where_levels_type (const char* levels)
{
  int count;
  GString *levels_sql;

  /* Generate SQL for constraints on message type, according to levels. */

  if (levels == NULL || strlen (levels) == 0)
    return NULL;

  levels_sql = NULL;
  count = 0;

  /* High. */
  if (strchr (levels, 'h'))
    {
      count = 1;
      levels_sql = g_string_new (" AND (type = 'Security Hole'");
    }

  /* Medium. */
  if (strchr (levels, 'm'))
    {
      if (count == 0)
        levels_sql = g_string_new (" AND (type = 'Security Warning'");
      else
        levels_sql = g_string_append (levels_sql,
                                      " OR type = 'Security Warning'");
      count++;
    }

  /* Low. */
  if (strchr (levels, 'l'))
    {
      if (count == 0)
        levels_sql = g_string_new (" AND (type = 'Security Note'");
      else
        levels_sql = g_string_append (levels_sql,
                                      " OR type = 'Security Note'");
      count++;
    }

  /* loG. */
  if (strchr (levels, 'g'))
    {
      if (count == 0)
        levels_sql = g_string_new (" AND (type = 'Log Message'");
      else
        levels_sql = g_string_append (levels_sql,
                                      " OR type = 'Log Message'");
      count++;
    }

  /* Debug. */
  if (strchr (levels, 'd'))
    {
      if (count == 0)
        levels_sql = g_string_new (" AND (type = 'Debug Message')");
      else
        levels_sql = g_string_append (levels_sql,
                                      " OR type = 'Debug Message')");
      count++;
    }
  else if (count)
    levels_sql = g_string_append (levels_sql, ")");

  if (count == 5)
    {
      /* All levels. */
      g_string_free (levels_sql, TRUE);
      levels_sql = NULL;
    }

  return levels_sql;
}

/**
 * @brief Return SQL WHERE for restricting a SELECT to a minimum CVSS base.
 *
 * @param[in]  min_cvss_base  Minimum value for CVSS.
 *
 * @return WHERE clause if one is required, else NULL.
 */
static GString *
where_cvss_base (const char* min_cvss_base)
{
  if (min_cvss_base)
    {
      GString *cvss_sql;
      gchar *quoted_min_cvss_base;

      if (strlen (min_cvss_base) == 0)
        return NULL;

      quoted_min_cvss_base = sql_quote (min_cvss_base);
      cvss_sql = g_string_new ("");
      g_string_append_printf (cvss_sql,
                              " AND CAST ((SELECT cvss_base FROM nvts WHERE nvts.oid = results.nvt) AS REAL)"
                              " >= CAST ('%s' AS REAL)",
                              quoted_min_cvss_base);
      g_free (quoted_min_cvss_base);

      return cvss_sql;
    }
  return NULL;
}

/**
 * @brief Return SQL WHERE for restricting a SELECT to a search phrase.
 *
 * @param[in]  search_phrase  Phrase that results must include.  All results if
 *                            NULL or "".
 *
 * @return WHERE clause for search phrase if one is required, else NULL.
 */
static GString *
where_search_phrase (const char* search_phrase)
{
  if (search_phrase)
    {
      GString *phrase_sql;
      gchar *quoted_search_phrase;

      if (strlen (search_phrase) == 0)
        return NULL;

      quoted_search_phrase = sql_quote (search_phrase);
      phrase_sql = g_string_new ("");
      g_string_append_printf (phrase_sql,
                              " AND (port LIKE '%%%%%s%%%%'"
                              " OR nvt LIKE '%%%%%s%%%%'"
                              " OR description LIKE '%%%%%s%%%%')",
                              quoted_search_phrase,
                              quoted_search_phrase,
                              quoted_search_phrase);
      g_free (quoted_search_phrase);

      return phrase_sql;
    }
  return NULL;
}

/**
 * @brief Initialise a result iterator.
 *
 * The results are ordered by host, then port and type (severity) according
 * to sort_field.
 *
 * @param[in]  iterator       Iterator.
 * @param[in]  report         Report whose results the iterator loops over,
 *                            or 0 to use result.
 * @param[in]  result         Single result to iterate over.  0 for all.
 *                            Overridden by report.
 * @param[in]  host           Host whose results the iterator loops over.  All
 *                            results if NULL.  Only considered if report given.
 * @param[in]  first_result   The result to start from.  The results are 0
 *                            indexed.
 * @param[in]  max_results    The maximum number of results returned.
 * @param[in]  ascending      Whether to sort ascending or descending.
 * @param[in]  sort_field     Field to sort on, or NULL for "type".
 * @param[in]  levels         String describing threat levels (message types)
 *                            to include in report (for example, "hmlgdf" for
 *                            High, Medium, Low, loG, Debug and False positive).
 *                            All levels if NULL.
 * @param[in]  search_phrase  Phrase that results must include.  All results if
 *                            NULL or "".
 * @param[in]  min_cvss_base  Minimum value for CVSS.  All results if NULL.
 * @param[in]  override       Whether to override the threat.
 */
void
init_result_iterator (iterator_t* iterator, report_t report, result_t result,
                      const char* host, int first_result, int max_results,
                      int ascending, const char* sort_field, const char* levels,
                      const char* search_phrase, const char* min_cvss_base,
                      int override)
{
  GString *levels_sql, *phrase_sql, *cvss_sql;
  gchar* sql;

  assert ((report && result) == 0);

  /* Allocate the query. */

  if (report)
    {
      gchar *new_type_sql;

      if (sort_field == NULL) sort_field = "type";
      if (levels == NULL) levels = "hmlgdf";

      levels_sql = where_levels (levels);
      phrase_sql = where_search_phrase (search_phrase);
      cvss_sql = where_cvss_base (min_cvss_base);
      if (override)
        {
          gchar *ov;

          assert (current_credentials.uuid);

          ov = g_strdup_printf
                ("SELECT overrides.new_threat"
                 " FROM overrides"
                 " WHERE overrides.nvt = results.nvt"
                 " AND ((overrides.owner IS NULL)"
                 " OR (overrides.owner ="
                 " (SELECT ROWID FROM users"
                 "  WHERE users.uuid = '%s')))"
                 " AND (overrides.task ="
                 "      (SELECT reports.task FROM reports"
                 "       WHERE report_results.report = reports.ROWID)"
                 "      OR overrides.task = 0)"
                 " AND (overrides.result = results.ROWID"
                 "      OR overrides.result = 0)"
                 " AND (overrides.hosts is NULL"
                 "      OR overrides.hosts = \"\""
                 "      OR hosts_contains (overrides.hosts, results.host))"
                 " AND (overrides.port is NULL"
                 "      OR overrides.port = \"\""
                 "      OR overrides.port = results.port)"
                 " AND (overrides.threat is NULL"
                 "      OR overrides.threat = \"\""
                 "      OR overrides.threat = results.type)"
                 " ORDER BY overrides.result DESC, overrides.task DESC,"
                 " overrides.port DESC, overrides.threat"
                 " COLLATE collate_message_type ASC",
                 current_credentials.uuid);

          new_type_sql = g_strdup_printf ("(CASE WHEN (%s) IS NULL"
                                          " THEN type ELSE (%s) END)",
                                          ov, ov);

          g_free (ov);
        }
      else
        new_type_sql = g_strdup ("type");

      if (host)
        sql = g_strdup_printf ("SELECT results.ROWID, subnet, host, port,"
                               " nvt, type, %s AS new_type, results.description"
                               " FROM results, report_results"
                               " WHERE report_results.report = %llu"
                               "%s"
                               " AND report_results.result = results.ROWID"
                               " AND results.host = '%s'"
                               "%s"
                               "%s"
                               "%s"
                               " LIMIT %i OFFSET %i;",
                               new_type_sql,
                               report,
                               levels_sql ? levels_sql->str : "",
                               host,
                               phrase_sql ? phrase_sql->str : "",
                               cvss_sql ? cvss_sql->str : "",
                               ascending
                                ? ((strcmp (sort_field, "port") == 0)
                                    ? " ORDER BY"
                                      " port,"
                                      " new_type"
                                      " COLLATE collate_message_type DESC"
                                    : " ORDER BY"
                                      " new_type COLLATE collate_message_type,"
                                      " port")
                                : ((strcmp (sort_field, "port") == 0)
                                    ? " ORDER BY"
                                      " port DESC,"
                                      " new_type"
                                      " COLLATE collate_message_type DESC"
                                    : " ORDER BY"
                                      " new_type"
                                      " COLLATE collate_message_type DESC,"
                                      " port"),
                               max_results,
                               first_result);
      else
        sql = g_strdup_printf ("SELECT results.ROWID, subnet, host, port,"
                               " nvt, type, %s AS new_type, results.description"
                               " FROM results, report_results"
                               " WHERE report_results.report = %llu"
                               "%s"
                               "%s"
                               "%s"
                               " AND report_results.result = results.ROWID"
                               "%s"
                               " LIMIT %i OFFSET %i;",
                               new_type_sql,
                               report,
                               levels_sql ? levels_sql->str : "",
                               phrase_sql ? phrase_sql->str : "",
                               cvss_sql ? cvss_sql->str : "",
                               ascending
                                ? ((strcmp (sort_field, "ROWID") == 0)
                                    ? " ORDER BY results.ROWID"
                                    : ((strcmp (sort_field, "port") == 0)
                                        ? " ORDER BY host COLLATE collate_ip,"
                                          " port,"
                                          " new_type"
                                          " COLLATE collate_message_type DESC"
                                        : " ORDER BY host COLLATE collate_ip,"
                                          " new_type COLLATE collate_message_type,"
                                          " port"))
                                : ((strcmp (sort_field, "ROWID") == 0)
                                    ? " ORDER BY results.ROWID DESC"
                                    : ((strcmp (sort_field, "port") == 0)
                                        ? " ORDER BY host COLLATE collate_ip,"
                                          " port DESC,"
                                          " new_type"
                                          " COLLATE collate_message_type DESC"
                                        : " ORDER BY host COLLATE collate_ip,"
                                          " new_type"
                                          " COLLATE collate_message_type DESC,"
                                          " port")),
                               max_results,
                               first_result);

      if (levels_sql) g_string_free (levels_sql, TRUE);
      if (phrase_sql) g_string_free (phrase_sql, TRUE);
      if (cvss_sql) g_string_free (cvss_sql, TRUE);
      g_free (new_type_sql);
    }
  else if (result)
    sql = g_strdup_printf ("SELECT ROWID, subnet, host, port, nvt,"
                           " type, type, description"
                           " FROM results"
                           " WHERE ROWID = %llu;",
                           result);
  else
    sql = g_strdup_printf ("SELECT results.ROWID, subnet, host, port, nvt,"
                           " type, type, description"
                           " FROM results, report_results, reports"
                           " WHERE results.ROWID = report_results.result"
                           " AND report_results.report = reports.ROWID"
                           " AND reports.owner ="
                           " (SELECT ROWID FROM users WHERE uuid = '%s');",
                           current_credentials.uuid);

  init_iterator (iterator, sql);
  g_free (sql);
}

/**
 * @brief Get the result from a result iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The result.
 */
result_t
result_iterator_result (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return (result_t) sqlite3_column_int64 (iterator->stmt, 0);
}

#if 0
/**
 * @brief Get the subnet from a result iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The subnet of the result as a newly allocated string, or NULL on
 *         error.
 */
char*
result_iterator_subnet (iterator_t* iterator)
{
  const char *ret;
  if (iterator->done) return NULL;
  ret = (const char*) sqlite3_column_text (iterator->stmt, 1);
  return ret ? g_strdup (ret) : NULL;
}
#endif

#define DEF_ACCESS(name, col) \
const char* \
result_iterator_ ## name (iterator_t* iterator) \
{ \
  const char *ret; \
  if (iterator->done) return NULL; \
  ret = (const char*) sqlite3_column_text (iterator->stmt, col); \
  return ret; \
}

/**
 * @brief Get the subnet from a result iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The subnet of the result.  Caller must only use before calling
 *         cleanup_iterator.
 */
DEF_ACCESS (subnet, 1);

/**
 * @brief Get the host from a result iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The host of the result.  Caller must only use before calling
 *         cleanup_iterator.
 */
DEF_ACCESS (host, 2);

/**
 * @brief Get the port from a result iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The port of the result.  Caller must only use before calling
 *         cleanup_iterator.
 */
DEF_ACCESS (port, 3);

/**
 * @brief Get the NVT OID from a result iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The NVT OID of the result.  Caller must only use before calling
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_oid, 4);

/**
 * @brief Get the NVT name from a result iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The name of the NVT that produced the result, or NULL on error.
 */
const char*
result_iterator_nvt_name (iterator_t *iterator)
{
  nvti_t *nvti;
  if (iterator->done) return NULL;
  nvti = nvtis_lookup (nvti_cache, result_iterator_nvt_oid (iterator));
  if (nvti)
    return nvti_name (nvti);
  return NULL;
}

/**
 * @brief Get the NVT CVSS base value from a result iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The CVSS base of the NVT that produced the result, or NULL on error.
 */
const char*
result_iterator_nvt_cvss_base (iterator_t *iterator)
{
  nvti_t *nvti;
  if (iterator->done) return NULL;
  nvti = nvtis_lookup (nvti_cache, result_iterator_nvt_oid (iterator));
  if (nvti)
    return nvti_cvss_base (nvti);
  return NULL;
}

/**
 * @brief Get the NVT risk factor from a result iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The risk factor of the NVT that produced the result, or NULL on error.
 */
const char*
result_iterator_nvt_risk_factor (iterator_t *iterator)
{
  nvti_t *nvti;
  if (iterator->done) return NULL;
  nvti = nvtis_lookup (nvti_cache, result_iterator_nvt_oid (iterator));
  if (nvti)
    return nvti_risk_factor (nvti);
  return NULL;
}

/**
 * @brief Get the NVT CVE from a result iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The CVE of the NVT that produced the result, or NULL on error.
 */
const char*
result_iterator_nvt_cve (iterator_t *iterator)
{
  nvti_t *nvti;
  if (iterator->done) return NULL;
  nvti = nvtis_lookup (nvti_cache, result_iterator_nvt_oid (iterator));
  if (nvti)
    return nvti_cve (nvti);
  return NULL;
}

/**
 * @brief Get the NVT BID from a result iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The BID of the NVT that produced the result, or NULL on error.
 */
const char*
result_iterator_nvt_bid (iterator_t *iterator)
{
  nvti_t *nvti;
  if (iterator->done) return NULL;
  nvti = nvtis_lookup (nvti_cache, result_iterator_nvt_oid (iterator));
  if (nvti)
    return nvti_bid (nvti);
  return NULL;
}

/**
 * @brief Get the original type from a result iterator.
 *
 * This is the column 'type'.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The origianl type of the result.  Caller must only use before calling
 *         cleanup_iterator.
 */
DEF_ACCESS (original_type, 5);

/**
 * @brief Get the original type from a result iterator.
 *
 * This is the column 'new_type', the overridden type.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The origianl type of the result.  Caller must only use before calling
 *         cleanup_iterator.
 */
DEF_ACCESS (type, 6);

/**
 * @brief Get the descr from a result iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The descr of the result.  Caller must only use before calling
 *         cleanup_iterator.
 */
DEF_ACCESS (descr, 7);

#undef DEF_ACCESS

/**
 * @brief Initialise a host iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  report    Report whose hosts the iterator loops over.
 *                       All hosts if NULL.
 * @param[in]  host      Single host to iterate over.  All hosts if NULL.
 */
void
init_host_iterator (iterator_t* iterator, report_t report, const char *host)
{
  gchar* sql;

  assert (report);

  sql = g_strdup_printf ("SELECT host, start_time, end_time, attack_state,"
                         " current_port, max_port"
                         " FROM report_hosts WHERE report = %llu"
                         "%s%s%s"
                         " ORDER BY host COLLATE collate_ip;",
                         report,
                         host ? " AND host = '" : "",
                         host ? host : "",
                         host ? "'" : "");
  init_iterator (iterator, sql);
  g_free (sql);
}

#define DEF_ACCESS(name, col) \
const char* \
name (iterator_t* iterator) \
{ \
  const char *ret; \
  if (iterator->done) return NULL; \
  ret = (const char*) sqlite3_column_text (iterator->stmt, col); \
  return ret; \
}

/**
 * @brief Get the host from a host iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The host of the host.  Caller must use only before calling
 *         cleanup_iterator.
 */
DEF_ACCESS (host_iterator_host, 0);

/**
 * @brief Get the start time from a host iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The start time of the host.  Caller must use only before calling
 *         cleanup_iterator.
 */
DEF_ACCESS (host_iterator_start_time, 1);

/**
 * @brief Get the end time from a host iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The end time of the host.  Caller must use only before calling
 *         cleanup_iterator.
 */
DEF_ACCESS (host_iterator_end_time, 2);

/**
 * @brief Get the attack state from a host iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The attack state of the host.  Caller must use only before calling
 *         cleanup_iterator.
 */
DEF_ACCESS (host_iterator_attack_state, 3);

/**
 * @brief Get the current port from a host iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Current port.
 */
int
host_iterator_current_port (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (int) sqlite3_column_int (iterator->stmt, 4);
  return ret;
}

/**
 * @brief Get the max port from a host iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Current port.
 */
int
host_iterator_max_port (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (int) sqlite3_column_int (iterator->stmt, 5);
  return ret;
}

/**
 * @brief Return whether a host has results on a report.
 *
 * @param[in]  report  Report.
 * @param[in]  host    Host.
 *
 * @return 1 if host has results, else 0.
 */
int
manage_report_host_has_results (report_t report, const char *host)
{
  char *quoted_host = sql_quote ((gchar*) host);
  int ret = sql_int (0, 0,
                     "SELECT COUNT(*) > 0 FROM results, report_results"
                     " WHERE report_results.report = %llu"
                     " AND report_results.result = results.ROWID"
                     " AND results.host = '%s';",
                     report,
                     quoted_host);
  g_free (quoted_host);
  return ret ? 1 : 0;
}

/**
 * @brief Set the end time of a task.
 *
 * @param[in]  task  Task.
 * @param[in]  time  New time.  Freed before return.  If NULL, clear end time.
 */
void
set_task_end_time (task_t task, char* time)
{
  if (time)
    {
      sql ("UPDATE tasks SET end_time = '%.*s' WHERE ROWID = %llu;",
           strlen (time),
           time,
           task);
      free (time);
    }
  else
    sql ("UPDATE tasks SET end_time = NULL WHERE ROWID = %llu;",
         task);
}

/**
 * @brief Get the start time of a scan.
 *
 * @param[in]  report  The report associated with the scan.
 *
 * @return Start time of scan, in a newly allocated string.
 */
char*
scan_start_time (report_t report)
{
  char *time = sql_string (0, 0,
                           "SELECT start_time FROM reports WHERE ROWID = %llu;",
                           report);
  return time ? time : g_strdup ("");
}

/**
 * @brief Set the start time of a scan.
 *
 * @param[in]  report     The report associated with the scan.
 * @param[in]  timestamp  Start time.
 */
void
set_scan_start_time (report_t report, const char* timestamp)
{
  sql ("UPDATE reports SET start_time = '%s' WHERE ROWID = %llu;",
       timestamp, report);
}

/**
 * @brief Get the end time of a scan.
 *
 * @param[in]  report  The report associated with the scan.
 *
 * @return End time of scan, in a newly allocated string.
 */
char*
scan_end_time (report_t report)
{
  char *time = sql_string (0, 0,
                           "SELECT end_time FROM reports WHERE ROWID = %llu;",
                           report);
  return time ? time : g_strdup ("");
}

/**
 * @brief Set the end time of a scan.
 *
 * @param[in]  report     The report associated with the scan.
 * @param[in]  timestamp  End time.  If NULL, clear end time.
 */
void
set_scan_end_time (report_t report, const char* timestamp)
{
  if (timestamp)
    sql ("UPDATE reports SET end_time = '%s' WHERE ROWID = %llu;",
         timestamp, report);
  else
    sql ("UPDATE reports SET end_time = NULL WHERE ROWID = %llu;",
         report);
}

/**
 * @brief Set the end time of a scanned host.
 *
 * @param[in]  report     Report associated with the scan.
 * @param[in]  host       Host.
 * @param[in]  timestamp  End time.
 */
void
set_scan_host_end_time (report_t report, const char* host,
                        const char* timestamp)
{
  if (sql_int (0, 0,
               "SELECT COUNT(*) FROM report_hosts"
               " WHERE report = %llu AND host = '%s';",
               report, host))
    sql ("UPDATE report_hosts SET end_time = '%s'"
         " WHERE report = %llu AND host = '%s';",
         timestamp, report, host);
  else
    sql ("INSERT into report_hosts (report, host, end_time)"
         " VALUES (%llu, '%s', '%s');",
         report, host, timestamp);
}

/**
 * @brief Set the start time of a scanned host.
 *
 * @param[in]  report     Report associated with the scan.
 * @param[in]  host       Host.
 * @param[in]  timestamp  Start time.
 */
void
set_scan_host_start_time (report_t report, const char* host,
                          const char* timestamp)
{
  if (sql_int (0, 0,
               "SELECT COUNT(*) FROM report_hosts"
               " WHERE report = %llu AND host = '%s';",
               report, host))
    sql ("UPDATE report_hosts SET start_time = '%s'"
         " WHERE report = %llu AND host = '%s';",
         timestamp, report, host);
  else
    sql ("INSERT into report_hosts (report, host, start_time)"
         " VALUES (%llu, '%s', '%s');",
         report, host, timestamp);
}

/**
 * @brief Get the timestamp of a report.
 *
 * @todo Lacks permission check.  Caller contexts all have permission
 *       checks before calling this so it's safe.  Rework callers so
 *       they pass report_t instead of UUID string.
 *
 * @param[in]   report_id    UUID of report.
 * @param[out]  timestamp    Timestamp on success.  Caller must free.
 *
 * @return 0 on success, -1 on error.
 */
int
report_timestamp (const char* report_id, gchar** timestamp)
{
  const char* stamp;
  time_t time = sql_int (0, 0,
                         "SELECT date FROM reports where uuid = '%s';",
                         report_id);
  stamp = ctime (&time);
  if (stamp == NULL) return -1;
  /* Allocate a copy, clearing the newline from the end of the timestamp. */
  *timestamp = g_strndup (stamp, strlen (stamp) - 1);
  return 0;
}

/**
 * @brief Return the run status of the scan associated with a report.
 *
 * @param[in]   report  Report.
 * @param[out]  status  Scan run status.
 *
 * @return 0 on success, -1 on error.
 */
int
report_scan_run_status (report_t report, int* status)
{
  *status = sql_int (0, 0,
                     "SELECT scan_run_status FROM reports"
                     " WHERE reports.ROWID = %llu;",
                     report);
  return 0;
}

/**
 * @brief Return the run status of the scan associated with a report.
 *
 * @param[in]   report  Report.
 * @param[out]  status  Scan run status.
 *
 * @return 0 on success, -1 on error.
 */
int
set_report_scan_run_status (report_t report, task_status_t status)
{
  sql ("UPDATE reports SET scan_run_status = %u WHERE ROWID = %llu;",
       status,
       report);
  return 0;
}

/**
 * @brief Get the number of results in the scan associated with a report.
 *
 * @param[in]   report         Report.
 * @param[in]   levels         String describing threat levels (message types)
 *                             to include in count (for example, "hmlgd" for
 *                             High, Medium, Low, loG and Debug).  All levels if
 *                             NULL.
 * @param[in]   search_phrase  Phrase that results must include.  All results if
 *                             NULL or "".
 * @param[in]   min_cvss_base  Minimum CVSS base of included results.  All
 *                             results if NULL.
 * @param[in]   override       Whether to override threats.
 * @param[out]  count          Total number of results in the scan.
 *
 * @return 0 on success, -1 on error.
 */
int
report_scan_result_count (report_t report, const char* levels,
                          const char* search_phrase, const char* min_cvss_base,
                          int override, int* count)
{
  GString *levels_sql, *phrase_sql, *cvss_sql;
  gchar *new_type_sql = NULL;

  phrase_sql = where_search_phrase (search_phrase);
  cvss_sql = where_cvss_base (min_cvss_base);

  if (override)
    {
      gchar *ov;

      assert (current_credentials.uuid);

      levels_sql = where_levels (levels);

      ov = g_strdup_printf
            ("SELECT overrides.new_threat"
             " FROM overrides"
             " WHERE overrides.nvt = results.nvt"
             " AND ((overrides.owner IS NULL)"
             " OR (overrides.owner ="
             " (SELECT ROWID FROM users"
             "  WHERE users.uuid = '%s')))"
             " AND (overrides.task ="
             "      (SELECT reports.task FROM reports"
             "       WHERE report_results.report = reports.ROWID)"
             "      OR overrides.task = 0)"
             " AND (overrides.result = results.ROWID"
             "      OR overrides.result = 0)"
             " AND (overrides.hosts is NULL"
             "      OR overrides.hosts = \"\""
             "      OR hosts_contains (overrides.hosts, results.host))"
             " AND (overrides.port is NULL"
             "      OR overrides.port = \"\""
             "      OR overrides.port = results.port)"
             " AND (overrides.threat is NULL"
             "      OR overrides.threat = \"\""
             "      OR overrides.threat = results.type)"
             " ORDER BY overrides.result DESC, overrides.task DESC,"
             " overrides.port DESC, overrides.threat"
             " COLLATE collate_message_type ASC",
             current_credentials.uuid);

      new_type_sql = g_strdup_printf (", (CASE WHEN (%s) IS NULL"
                                      " THEN type ELSE (%s) END)"
                                      " AS new_type",
                                      ov, ov);

      g_free (ov);
    }
  else
    levels_sql = where_levels_type (levels);

  *count = sql_int (0, 0,
                    "SELECT count(results.ROWID)%s"
                    " FROM results, report_results"
                    " WHERE results.ROWID = report_results.result"
                    "%s%s%s"
                    " AND report_results.report = %llu;",
                    new_type_sql ? new_type_sql : "",
                    levels_sql ? levels_sql->str : "",
                    phrase_sql ? phrase_sql->str : "",
                    cvss_sql ? cvss_sql->str : "",
                    report);

  if (levels_sql) g_string_free (levels_sql, TRUE);
  if (phrase_sql) g_string_free (phrase_sql, TRUE);
  if (cvss_sql) g_string_free (cvss_sql, TRUE);
  g_free (new_type_sql);

  return 0;
}

/**
 * @brief Get the message count for a report for a specific message type.
 *
 * @param[in]  report     Report.
 * @param[in]  type       Message type.
 * @param[in]  override   Whether to override the threat.
 * @param[in]  host       Host to which to limit the count.  NULL to allow all.
 *
 * @return Message count.
 */
int
report_count (report_t report, const char *type, int override, const char *host)
{
  if (override
      && sql_int (0, 0,
                  "SELECT count(*)"
                  " FROM overrides"
                  " WHERE (overrides.owner IS NULL)"
                  " OR (overrides.owner ="
                  " (SELECT ROWID FROM users"
                  "  WHERE users.uuid = '%s'))",
                  current_credentials.uuid))
    {
      int count;
      iterator_t results;
      task_t task;

      sqlite3_stmt *stmt, *full_stmt;
      gchar *select;
      int ret;

      /* Prepare quick inner statement. */

      select = g_strdup_printf ("SELECT 1 FROM overrides"
                                " WHERE (overrides.nvt = $nvt)"
                                " AND ((overrides.owner IS NULL) OR (overrides.owner ="
                                " (SELECT ROWID FROM users WHERE users.uuid = '%s')))",
                                current_credentials.uuid);
      while (1)
        {
          const char* tail;
          ret = sqlite3_prepare (task_db, select, -1, &stmt, &tail);
          if (ret == SQLITE_BUSY) continue;
          g_free (select);
          if (ret == SQLITE_OK)
            {
              if (stmt == NULL)
                {
                  g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s\n",
                             __FUNCTION__,
                             sqlite3_errmsg (task_db));
                  abort ();
                }
              break;
            }
          g_warning ("%s: sqlite3_prepare failed: %s\n",
                     __FUNCTION__,
                     sqlite3_errmsg (task_db));
          /** @todo ROLLBACK if in transaction. */
          abort ();
        }

      /* Prepare full inner statement. */

      report_task (report, &task);

      select = g_strdup_printf
                ("SELECT overrides.new_threat"
                 " FROM overrides"
                 " WHERE overrides.nvt = $nvt" // 1
                 " AND ((overrides.owner IS NULL)"
                 " OR (overrides.owner ="
                 " (SELECT users.ROWID FROM users"
                 "  WHERE users.uuid = '%s')))"
                 " AND (overrides.task = 0"
                 "      OR overrides.task = %llu)"
                 " AND (overrides.result = 0"
                 "      OR overrides.result = $result)" // 2
                 " AND (overrides.hosts is NULL"
                 "      OR overrides.hosts = \"\""
                 "      OR hosts_contains (overrides.hosts, $host))" // 3
                 " AND (overrides.port is NULL"
                 "      OR overrides.port = \"\""
                 "      OR overrides.port = $port)" // 4
                 " AND (overrides.threat is NULL"
                 "      OR overrides.threat = \"\""
                 "      OR overrides.threat = $type)" // 5
                 " ORDER BY overrides.result DESC, overrides.task DESC,"
                 " overrides.port DESC, overrides.threat"
                 " COLLATE collate_message_type ASC;",
                 current_credentials.uuid,
                 task);

      while (1)
        {
          const char* tail;
          ret = sqlite3_prepare (task_db, select, -1, &full_stmt, &tail);
          if (ret == SQLITE_BUSY) continue;
          g_free (select);
          if (ret == SQLITE_OK)
            {
              if (full_stmt == NULL)
                {
                  g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s\n",
                             __FUNCTION__,
                             sqlite3_errmsg (task_db));
                  abort ();
                }
              break;
            }
          g_warning ("%s: sqlite3_prepare failed: %s\n",
                     __FUNCTION__,
                     sqlite3_errmsg (task_db));
          /** @todo ROLLBACK if in transaction. */
          abort ();
        }

      /* Loop through all results. */

      count = 0;
      init_iterator (&results,
                     "SELECT results.ROWID, results.nvt, results.type,"
                     " results.host, results.port"
                     " FROM results, report_results"
                     " WHERE report_results.report = %llu"
                     " AND results.ROWID = report_results.result",
                     report);
      while (next (&results))
        {
          const char *nvt, *new_type;

          nvt = (const char*) sqlite3_column_text (results.stmt, 1);

          /* Bind the current result values into the quick statement. */

          while (1)
            {
              ret = sqlite3_bind_text (stmt, 1, nvt, -1, SQLITE_TRANSIENT);
              if (ret == SQLITE_BUSY) continue;
              if (ret == SQLITE_OK) break;
              g_warning ("%s: sqlite3_prepare failed: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              abort ();
            }

          /* Run the quick inner statement to check for overrides. */

          while (1)
            {
              ret = sqlite3_step (stmt);
              if (ret == SQLITE_BUSY) continue;
              if (ret == SQLITE_DONE) break;
              if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
                {
                  if (ret == SQLITE_ERROR) ret = sqlite3_reset (stmt);
                  g_warning ("%s: sqlite3_step failed: %s\n",
                             __FUNCTION__,
                             sqlite3_errmsg (task_db));
                  abort ();
                }
              break;
            }

          /* Check the result. */

          if (ret == SQLITE_DONE)
            {
              new_type = (const char*) sqlite3_column_text (results.stmt, 2);
              if (new_type && (strcmp (new_type, type) == 0))
                count++;
            }
          else
            {
              /* There is an override on this NVT, get the new threat value. */

              /* Bind the current result values into the full statement. */

              while (1)
                {
                  ret = sqlite3_bind_text (full_stmt, 1, nvt, -1, SQLITE_TRANSIENT);
                  if (ret == SQLITE_BUSY) continue;
                  if (ret == SQLITE_OK) break;
                  g_warning ("%s: sqlite3_prepare failed: %s\n",
                             __FUNCTION__,
                             sqlite3_errmsg (task_db));
                  abort ();
                }

              while (1)
                {
                  result_t result;
                  result = (result_t) sqlite3_column_int64 (results.stmt, 0);
                  ret = sqlite3_bind_int64 (full_stmt, 2, result);
                  if (ret == SQLITE_BUSY) continue;
                  if (ret == SQLITE_OK) break;
                  g_warning ("%s: sqlite3_prepare failed: %s\n",
                             __FUNCTION__,
                             sqlite3_errmsg (task_db));
                  abort ();
                }

              while (1)
                {
                  const char *host;
                  host = (const char*) sqlite3_column_text (results.stmt, 3);
                  ret = sqlite3_bind_text (full_stmt, 3, host, -1,
                                           SQLITE_TRANSIENT);
                  if (ret == SQLITE_BUSY) continue;
                  if (ret == SQLITE_OK) break;
                  g_warning ("%s: sqlite3_prepare failed: %s\n",
                             __FUNCTION__,
                             sqlite3_errmsg (task_db));
                  abort ();
                }

              while (1)
                {
                  const char *port;
                  port = (const char*) sqlite3_column_text (results.stmt, 4);
                  ret = sqlite3_bind_text (full_stmt, 4, port, -1,
                                           SQLITE_TRANSIENT);
                  if (ret == SQLITE_BUSY) continue;
                  if (ret == SQLITE_OK) break;
                  g_warning ("%s: sqlite3_prepare failed: %s\n",
                             __FUNCTION__,
                             sqlite3_errmsg (task_db));
                  abort ();
                }

              while (1)
                {
                  const char *type;
                  type = (const char*) sqlite3_column_text (results.stmt, 2);
                  ret = sqlite3_bind_text (full_stmt, 5, type, -1,
                                           SQLITE_TRANSIENT);
                  if (ret == SQLITE_BUSY) continue;
                  if (ret == SQLITE_OK) break;
                  g_warning ("%s: sqlite3_prepare failed: %s\n",
                             __FUNCTION__,
                             sqlite3_errmsg (task_db));
                  abort ();
                }

              /* Run the full inner statement. */

              while (1)
                {
                  ret = sqlite3_step (full_stmt);
                  if (ret == SQLITE_BUSY) continue;
                  if (ret == SQLITE_DONE) break;
                  if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
                    {
                      if (ret == SQLITE_ERROR) ret = sqlite3_reset (full_stmt);
                      g_warning ("%s: sqlite3_step failed: %s\n",
                                 __FUNCTION__,
                                 sqlite3_errmsg (task_db));
                      abort ();
                    }
                  break;
                }

              /* Check the result. */

              if (ret == SQLITE_DONE)
                new_type = (const char*) sqlite3_column_text (results.stmt, 2);
              else
                new_type = (const char*) sqlite3_column_text (full_stmt, 0);

              if (new_type && (strcmp (new_type, type) == 0))
                count++;

              /* Reset the full inner statement. */

              while (1)
                {
                  ret = sqlite3_reset (full_stmt);
                  if (ret == SQLITE_BUSY) continue;
                  if (ret == SQLITE_DONE || ret == SQLITE_OK) break;
                  if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
                    {
                      g_warning ("%s: sqlite3_reset failed: %s\n",
                                 __FUNCTION__,
                                 sqlite3_errmsg (task_db));
                      abort ();
                    }
                }
            }

          /* Reset the quick inner statement. */

          while (1)
            {
              ret = sqlite3_reset (stmt);
              if (ret == SQLITE_BUSY) continue;
              if (ret == SQLITE_DONE || ret == SQLITE_OK) break;
              if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
                {
                  g_warning ("%s: sqlite3_reset failed: %s\n",
                             __FUNCTION__,
                             sqlite3_errmsg (task_db));
                  abort ();
                }
            }
        }
      cleanup_iterator (&results);
      sqlite3_finalize (stmt);
      return count;
    }
  else if (host)
    {
      gchar* quoted_host = sql_quote (host);
      int count = sql_int (0, 0,
                           "SELECT count(*) FROM results, report_results"
                           " WHERE results.host = '%s' AND results.type = '%s'"
                           " AND results.ROWID = report_results.result"
                           " AND report_results.report = %llu;",
                           quoted_host,
                           type,
                           report);
      g_free (quoted_host);
      return count;
    }
  else
    return sql_int (0, 0,
                    "SELECT count(*) FROM results, report_results"
                    " WHERE report_results.report = %llu"
                    " AND report_results.result = results.ROWID"
                    " AND results.type = '%s';",
                    report,
                    type);
}

/**
 * @brief Get the message counts for a report given the UUID.
 *
 * @todo Lacks permission check.  Caller contexts all have permission
 *       checks before calling this so it's safe.  Rework callers to
 *       use report_counts_id instead.
 *
 * @param[in]   report_id    ID of report.
 * @param[out]  debugs       Number of debug messages.
 * @param[out]  holes        Number of hole messages.
 * @param[out]  infos        Number of info messages.
 * @param[out]  logs         Number of log messages.
 * @param[out]  warnings     Number of warning messages.
 * @param[out]  false_positives  Number of false positives.
 * @param[in]   override     Whether to override the threat.
 *
 * @return 0 on success, -1 on error.
 */
int
report_counts (const char* report_id, int* debugs, int* holes, int* infos,
               int* logs, int* warnings, int* false_positives, int override)
{
  report_t report;
  if (find_report (report_id, &report)) return -1;
  return report_counts_id (report, debugs, holes, infos, logs, warnings,
                           false_positives, override, NULL);
}

/**
 * @brief Get the message counts for a report.
 *
 * @param[in]   report    Report.
 * @param[out]  debugs    Number of debug messages.
 * @param[out]  holes     Number of hole messages.
 * @param[out]  infos     Number of info messages.
 * @param[out]  logs      Number of log messages.
 * @param[out]  warnings  Number of warning messages.
 * @param[out]  false_positives  Number of false positive messages.
 * @param[in]   override  Whether to override the threat.
 * @param[in]   host      Host to which to limit the count.  NULL to allow all.
 *
 * @return 0 on success, -1 on error.
 */
int
report_counts_id (report_t report, int* debugs, int* holes, int* infos,
                  int* logs, int* warnings, int* false_positives, int override,
                  const char *host)
{
  /* This adds time and is out of scope of OMP threat levels, so skip it */
  if (debugs)
    *debugs = 0;

  if (holes && infos && logs && warnings && false_positives)
    {
      if (override
          && sql_int (0, 0,
                      "SELECT count(*)"
                      " FROM overrides"
                      " WHERE (overrides.owner IS NULL)"
                      " OR (overrides.owner ="
                      " (SELECT ROWID FROM users"
                      "  WHERE users.uuid = '%s'))",
                      current_credentials.uuid))
        {
          iterator_t results;
          task_t task;

          sqlite3_stmt *stmt, *full_stmt;
          gchar *select;
          int ret;

          /* Prepare quick inner statement. */

          select = g_strdup_printf ("SELECT 1 FROM overrides"
                                    " WHERE (overrides.nvt = $nvt)"
                                    " AND ((overrides.owner IS NULL) OR (overrides.owner ="
                                    " (SELECT ROWID FROM users WHERE users.uuid = '%s')))",
                                    current_credentials.uuid);
          while (1)
            {
              const char* tail;
              ret = sqlite3_prepare (task_db, select, -1, &stmt, &tail);
              if (ret == SQLITE_BUSY) continue;
              g_free (select);
              if (ret == SQLITE_OK)
                {
                  if (stmt == NULL)
                    {
                      g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s\n",
                                 __FUNCTION__,
                                 sqlite3_errmsg (task_db));
                      abort ();
                    }
                  break;
                }
              g_warning ("%s: sqlite3_prepare failed: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              /** @todo ROLLBACK if in transaction. */
              abort ();
            }

          /* Prepare full inner statement. */

          report_task (report, &task);

          select = g_strdup_printf
                    ("SELECT overrides.new_threat"
                     " FROM overrides"
                     " WHERE overrides.nvt = $nvt" // 1
                     " AND ((overrides.owner IS NULL)"
                     " OR (overrides.owner ="
                     " (SELECT users.ROWID FROM users"
                     "  WHERE users.uuid = '%s')))"
                     " AND (overrides.task = 0"
                     "      OR overrides.task = %llu)"
                     " AND (overrides.result = 0"
                     "      OR overrides.result = $result)" // 2
                     " AND (overrides.hosts is NULL"
                     "      OR overrides.hosts = \"\""
                     "      OR hosts_contains (overrides.hosts, $host))" // 3
                     " AND (overrides.port is NULL"
                     "      OR overrides.port = \"\""
                     "      OR overrides.port = $port)" // 4
                     " AND (overrides.threat is NULL"
                     "      OR overrides.threat = \"\""
                     "      OR overrides.threat = $type)" // 5
                     " ORDER BY overrides.result DESC, overrides.task DESC,"
                     " overrides.port DESC, overrides.threat"
                     " COLLATE collate_message_type ASC;",
                     current_credentials.uuid,
                     task);

          while (1)
            {
              const char* tail;
              ret = sqlite3_prepare (task_db, select, -1, &full_stmt, &tail);
              if (ret == SQLITE_BUSY) continue;
              g_free (select);
              if (ret == SQLITE_OK)
                {
                  if (full_stmt == NULL)
                    {
                      g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s\n",
                                 __FUNCTION__,
                                 sqlite3_errmsg (task_db));
                      abort ();
                    }
                  break;
                }
              g_warning ("%s: sqlite3_prepare failed: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              /** @todo ROLLBACK if in transaction. */
              abort ();
            }

          /* Loop through all results. */

          *holes = *infos = *logs = *warnings = *false_positives = 0;
          init_iterator (&results,
                         "SELECT results.ROWID, results.nvt, results.type,"
                         " results.host, results.port"
                         " FROM results, report_results"
                         " WHERE report_results.report = %llu"
                         " AND results.ROWID = report_results.result",
                         report);
          while (next (&results))
            {
              const char *nvt, *new_type;

              nvt = (const char*) sqlite3_column_text (results.stmt, 1);

              /* Bind the current result values into the quick statement. */

              while (1)
                {
                  ret = sqlite3_bind_text (stmt, 1, nvt, -1, SQLITE_TRANSIENT);
                  if (ret == SQLITE_BUSY) continue;
                  if (ret == SQLITE_OK) break;
                  g_warning ("%s: sqlite3_prepare failed: %s\n",
                             __FUNCTION__,
                             sqlite3_errmsg (task_db));
                  abort ();
                }

              /* Run the quick inner statement to check for overrides. */

              while (1)
                {
                  ret = sqlite3_step (stmt);
                  if (ret == SQLITE_BUSY) continue;
                  if (ret == SQLITE_DONE) break;
                  if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
                    {
                      if (ret == SQLITE_ERROR) ret = sqlite3_reset (stmt);
                      g_warning ("%s: sqlite3_step failed: %s\n",
                                 __FUNCTION__,
                                 sqlite3_errmsg (task_db));
                      abort ();
                    }
                  break;
                }

              /* Check the result. */

              if (ret == SQLITE_DONE)
                {
                  new_type = (const char*) sqlite3_column_text (results.stmt, 2);
                  if (new_type)
                    {
                      if (strcmp (new_type, "Security Hole") == 0)
                        (*holes)++;
                      else if (strcmp (new_type, "Security Warning") == 0)
                        (*warnings)++;
                      else if (strcmp (new_type, "Security Note") == 0)
                        (*infos)++;
                      else if (strcmp (new_type, "Log Message") == 0)
                        (*logs)++;
                      else if (strcmp (new_type, "False Positive") == 0)
                        (*false_positives)++;
                    }
                }
              else
                {
                  /* There is an override on this NVT, get the new threat value. */

                  /* Bind the current result values into the full statement. */

                  while (1)
                    {
                      ret = sqlite3_bind_text (full_stmt, 1, nvt, -1, SQLITE_TRANSIENT);
                      if (ret == SQLITE_BUSY) continue;
                      if (ret == SQLITE_OK) break;
                      g_warning ("%s: sqlite3_prepare failed: %s\n",
                                 __FUNCTION__,
                                 sqlite3_errmsg (task_db));
                      abort ();
                    }

                  while (1)
                    {
                      result_t result;
                      result = (result_t) sqlite3_column_int64 (results.stmt, 0);
                      ret = sqlite3_bind_int64 (full_stmt, 2, result);
                      if (ret == SQLITE_BUSY) continue;
                      if (ret == SQLITE_OK) break;
                      g_warning ("%s: sqlite3_prepare failed: %s\n",
                                 __FUNCTION__,
                                 sqlite3_errmsg (task_db));
                      abort ();
                    }

                  while (1)
                    {
                      const char *host;
                      host = (const char*) sqlite3_column_text (results.stmt, 3);
                      ret = sqlite3_bind_text (full_stmt, 3, host, -1,
                                               SQLITE_TRANSIENT);
                      if (ret == SQLITE_BUSY) continue;
                      if (ret == SQLITE_OK) break;
                      g_warning ("%s: sqlite3_prepare failed: %s\n",
                                 __FUNCTION__,
                                 sqlite3_errmsg (task_db));
                      abort ();
                    }

                  while (1)
                    {
                      const char *port;
                      port = (const char*) sqlite3_column_text (results.stmt, 4);
                      ret = sqlite3_bind_text (full_stmt, 4, port, -1,
                                               SQLITE_TRANSIENT);
                      if (ret == SQLITE_BUSY) continue;
                      if (ret == SQLITE_OK) break;
                      g_warning ("%s: sqlite3_prepare failed: %s\n",
                                 __FUNCTION__,
                                 sqlite3_errmsg (task_db));
                      abort ();
                    }

                  while (1)
                    {
                      const char *type;
                      type = (const char*) sqlite3_column_text (results.stmt, 2);
                      ret = sqlite3_bind_text (full_stmt, 5, type, -1,
                                               SQLITE_TRANSIENT);
                      if (ret == SQLITE_BUSY) continue;
                      if (ret == SQLITE_OK) break;
                      g_warning ("%s: sqlite3_prepare failed: %s\n",
                                 __FUNCTION__,
                                 sqlite3_errmsg (task_db));
                      abort ();
                    }

                  /* Run the full inner statement. */

                  while (1)
                    {
                      ret = sqlite3_step (full_stmt);
                      if (ret == SQLITE_BUSY) continue;
                      if (ret == SQLITE_DONE) break;
                      if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
                        {
                          if (ret == SQLITE_ERROR) ret = sqlite3_reset (full_stmt);
                          g_warning ("%s: sqlite3_step failed: %s\n",
                                     __FUNCTION__,
                                     sqlite3_errmsg (task_db));
                          abort ();
                        }
                      break;
                    }

                  /* Check the result. */

                  if (ret == SQLITE_DONE)
                    new_type = (const char*) sqlite3_column_text (results.stmt, 2);
                  else
                    new_type = (const char*) sqlite3_column_text (full_stmt, 0);

                  if (new_type)
                    {
                      if (strcmp (new_type, "Security Hole") == 0)
                        (*holes)++;
                      else if (strcmp (new_type, "Security Warning") == 0)
                        (*warnings)++;
                      else if (strcmp (new_type, "Security Note") == 0)
                        (*infos)++;
                      else if (strcmp (new_type, "Log Message") == 0)
                        (*logs)++;
                      else if (strcmp (new_type, "False Positive") == 0)
                        (*false_positives)++;
                    }

                  /* Reset the full inner statement. */

                  while (1)
                    {
                      ret = sqlite3_reset (full_stmt);
                      if (ret == SQLITE_BUSY) continue;
                      if (ret == SQLITE_DONE || ret == SQLITE_OK) break;
                      if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
                        {
                          g_warning ("%s: sqlite3_reset failed: %s\n",
                                     __FUNCTION__,
                                     sqlite3_errmsg (task_db));
                          abort ();
                        }
                    }
                }

              /* Reset the quick inner statement. */

              while (1)
                {
                  ret = sqlite3_reset (stmt);
                  if (ret == SQLITE_BUSY) continue;
                  if (ret == SQLITE_DONE || ret == SQLITE_OK) break;
                  if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
                    {
                      g_warning ("%s: sqlite3_reset failed: %s\n",
                                 __FUNCTION__,
                                 sqlite3_errmsg (task_db));
                      abort ();
                    }
                }
            }
          cleanup_iterator (&results);
          sqlite3_finalize (stmt);

          return 0;
        }
    }

  if (false_positives)
    *false_positives = report_count (report, "False Positive", override, host);
  if (holes) *holes = report_count (report, "Security Hole", override, host);
  if (infos) *infos = report_count (report, "Security Note", override, host);
  if (logs) *logs = report_count (report, "Log Message", override, host);
  if (warnings)
    *warnings = report_count (report, "Security Warning", override, host);

  return 0;
}

/**
 * @brief Delete a report.
 *
 * It's up to the caller to provide the transaction.
 *
 * @param[in]  report  Report.
 *
 * @return 0 success, 1 report is hidden, 2 report is in use, -1 error.
 */
int
delete_report (report_t report)
{
  task_t task;
  char *slave_task_uuid;

  if (sql_int (0, 0, "SELECT hidden FROM reports WHERE ROWID = %llu;", report))
    return 1;

  if (sql_int (0, 0,
               "SELECT count(*) FROM reports WHERE ROWID = %llu"
               " AND (scan_run_status = %u OR scan_run_status = %u"
               " OR scan_run_status = %u OR scan_run_status = %u"
               " OR scan_run_status = %u OR scan_run_status = %u"
               " OR scan_run_status = %u OR scan_run_status = %u"
               " OR scan_run_status = %u OR scan_run_status = %u);",
               report,
               TASK_STATUS_RUNNING,
               TASK_STATUS_PAUSE_REQUESTED,
               TASK_STATUS_PAUSE_WAITING,
               TASK_STATUS_PAUSED,
               TASK_STATUS_RESUME_REQUESTED,
               TASK_STATUS_RESUME_WAITING,
               TASK_STATUS_REQUESTED,
               TASK_STATUS_DELETE_REQUESTED,
               TASK_STATUS_STOP_REQUESTED,
               TASK_STATUS_STOP_WAITING))
    return 2;

  if (report_task (report, &task))
    return -1;

  /* Remove any associated slave task. */

  slave_task_uuid = report_slave_task_uuid (report);
  if (slave_task_uuid)
    {
      slave_t slave;

      /** @todo Store slave on report, in case task's slave changes. */
      slave = task_slave (task);
      if (slave == 0)
        {
          free (slave_task_uuid);
          return -1;
        }

      delete_slave_task (slave, slave_task_uuid);
    }

  /* Remove the report data. */

  sql ("DELETE FROM report_hosts WHERE report = %llu;", report);
  sql ("DELETE FROM report_results WHERE report = %llu;", report);
  sql ("DELETE FROM reports WHERE ROWID = %llu;", report);

  /* Update the task state. */

  switch (sql_int64 (&report, 0, 0,
                     "SELECT max (ROWID) FROM reports WHERE task = %llu",
                     task))
    {
      case 0:
        if (report)
          {
            int status;
            if (report_scan_run_status (report, &status))
              return -1;
            sql ("UPDATE tasks SET run_status = %u WHERE ROWID = %llu;",
                 status,
                 task);
          }
        break;
      case 1:        /* Too few rows in result of query. */
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        return -1;
        break;
    }

  return 0;
}

/**
 * @brief Delete a report.
 *
 * @param[in]  report  Report.
 *
 * @return 0 success, 1 report is hidden, 2 report is in use, -1 error.
 */
int
manage_delete_report (report_t report)
{
  int ret;

  sql ("BEGIN EXCLUSIVE;");

  ret = delete_report (report);
  if (ret)
    {
      sql ("ROLLBACK;");
      return ret;
    }

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Return the slave progress of a report.
 *
 * @param[in]  report  Report.
 *
 * @return Number of reports.
 */
int
report_slave_progress (report_t report)
{
  return sql_int (0, 0,
                  "SELECT slave_progress FROM reports WHERE ROWID = %llu;",
                  report);
}

/**
 * @brief Set slave progress of a report.
 *
 * @param[in]  report    The report.
 * @param[in]  progress  The new progress value.
 *
 * @return 0 success.
 */
int
set_report_slave_progress (report_t report, int progress)
{
  sql ("UPDATE reports SET slave_progress = %i WHERE ROWID = %llu;",
       progress,
       report);
  return 0;
}

/**
 * @brief Return the UUID of the task on the slave.
 *
 * @param[in]  report    The report.
 *
 * @return UUID of the slave task if any, else NULL.
 */
char*
report_slave_task_uuid (report_t report)
{
  char *uuid;

  uuid = sql_string (0, 0,
                     "SELECT slave_task_uuid FROM reports WHERE ROWID = %llu;",
                     report);
  if (uuid && strlen (uuid))
    return uuid;
  free (uuid);
  return NULL;
}

/**
 * @brief Set the UUID of the slave task, on the local task.
 *
 * @param[in]  report    The report.
 * @param[in]  uuid  UUID.
 */
void
set_report_slave_task_uuid (report_t report, const char *uuid)
{
  gchar *quoted_uuid = sql_quote (uuid);
  sql ("UPDATE reports SET slave_task_uuid = '%s' WHERE ROWID = %llu;",
       quoted_uuid,
       report);
  g_free (quoted_uuid);
}

/**
 * @brief Set a report parameter.
 *
 * @param[in]  report     The report.
 * @param[in]  parameter  The name of the parameter (in any case): COMMENT.
 * @param[in]  value      The value of the parameter.
 *
 * @return 0 success, -2 parameter name error,
 *         -3 failed to write parameter to disk,
 *         -4 username missing from current_credentials.
 */
int
set_report_parameter (report_t report, const char* parameter, const char* value)
{
  tracef ("   set_report_parameter %llu %s\n", report, parameter);
  if (strcasecmp ("COMMENT", parameter) == 0)
    {
      gchar* quote = sql_nquote (value, strlen (value));
      sql ("UPDATE reports SET comment = '%s' WHERE ROWID = %llu;",
           value,
           report);
      g_free (quote);
    }
  else
    return -2;
  return 0;
}

/**
 * @brief Prepare a partial report for restarting the scan from the beginning.
 *
 * @param[in]  report  The report.
 */
void
trim_report (report_t report)
{
  /* Remove results for all hosts. */

  sql ("DELETE FROM report_results WHERE report = %llu AND result IN"
       " (SELECT results.ROWID FROM report_results, results, report_hosts"
       "  WHERE report_results.report = %llu"
       "  AND report_results.result = results.ROWID"
       "  AND report_hosts.report = %llu"
       "  AND results.host = report_hosts.host);",
       report,
       report,
       report);

  sql ("DELETE FROM results WHERE ROWID IN"
       " (SELECT results.ROWID FROM report_results, results, report_hosts"
       "  WHERE report_results.report = %llu"
       "  AND report_results.result = results.ROWID"
       "  AND report_hosts.report = %llu"
       "  AND results.host = report_hosts.host);",
       report,
       report);

  /* Remove all hosts. */

  sql ("DELETE FROM report_hosts"
       " WHERE report = %llu;",
       report);
}

/**
 * @brief Prepare a partial report for resumption of the scan.
 *
 * @param[in]  report  The report.
 */
void
trim_partial_report (report_t report)
{
  /* Remove results for partial hosts. */

  sql ("DELETE FROM report_results WHERE report = %llu AND result IN"
       " (SELECT results.ROWID FROM report_results, results, report_hosts"
       "  WHERE report_results.report = %llu"
       "  AND report_results.result = results.ROWID"
       "  AND report_hosts.report = %llu"
       "  AND results.host = report_hosts.host"
       "  AND (report_hosts.end_time is NULL OR report_hosts.end_time = ''));",
       report,
       report,
       report);

  sql ("DELETE FROM results WHERE ROWID IN"
       " (SELECT results.ROWID FROM report_results, results, report_hosts"
       "  WHERE report_results.report = %llu"
       "  AND report_results.result = results.ROWID"
       "  AND report_hosts.report = %llu"
       "  AND results.host = report_hosts.host"
       "  AND (report_hosts.end_time is NULL OR report_hosts.end_time = ''));",
       report,
       report);

  /* Remove partial hosts. */

  sql ("DELETE FROM report_hosts"
       " WHERE report = %llu"
       " AND (end_time is NULL OR end_time = '');",
       report);
}

/**
 * @brief Compares two textual threat level representations, sorting
 * @brief descending.
 *
 * @param[in]  arg_one  First threat level.
 * @param[in]  arg_two  Second threat level.
 *
 * @return 1, 0 or -1 if first given threat is less than, equal to or greater
 *         than second.
 */
static gint
compare_message_types_desc (gconstpointer arg_one, gconstpointer arg_two)
{
  gchar *one_type, *two_type;
  gchar *one = *((gchar**) arg_one);
  gchar *two = *((gchar**) arg_two);
  gint host;

  one += strlen (one) + 1;
  two += strlen (two) + 1;
  one_type = one;
  two_type = two;

  one += strlen (one) + 1;
  two += strlen (two) + 1;
  host = strcmp (one, two);
  if (host == 0)
    {
      gint type;
      type = collate_message_type (NULL,
                                   strlen (two_type), two_type,
                                   strlen (one_type), one_type);
      if (type == 0)
        {
          one = *((gchar**) arg_one);
          two = *((gchar**) arg_two);
          return strcmp (one, two);
        }

      return type;
    }
  return host;
}

/**
 * @brief Compares two textual threat level representations, sorting ascending.
 *
 * @param[in]  arg_one  First threat level.
 * @param[in]  arg_two  Second threat level.
 *
 * @return -1, 0 or 1 if first given threat is less than, equal to or greater
 *         than second.
 */
static gint
compare_message_types_asc (gconstpointer arg_one, gconstpointer arg_two)
{
  gchar *one_type, *two_type;
  gchar *one = *((gchar**) arg_one);
  gchar *two = *((gchar**) arg_two);
  gint host;

  one += strlen (one) + 1;
  two += strlen (two) + 1;
  one_type = one;
  two_type = two;

  one += strlen (one) + 1;
  two += strlen (two) + 1;
  host = strcmp (one, two);
  if (host == 0)
    {
      gint type;
      type = collate_message_type (NULL,
                                   strlen (one_type), one_type,
                                   strlen (two_type), two_type);
      if (type == 0)
        {
          one = *((gchar**) arg_one);
          two = *((gchar**) arg_two);
          return strcmp (two, one);
        }

      return type;
    }
  return host;
}

/**
 * @brief Compares two buffered results, sorting by port then threat.
 *
 * @param[in]  arg_one  First result.
 * @param[in]  arg_two  Second result.
 *
 * @return -1, 0 or 1 if first given result is less than, equal to or greater
 *         than second.
 */
static gint
compare_port_threat (gconstpointer arg_one, gconstpointer arg_two)
{
  int host;
  gchar *one = *((gchar**) arg_one);
  gchar *two = *((gchar**) arg_two);
  gchar *one_threat = one + strlen (one) + 1;
  gchar *two_threat = two + strlen (two) + 1;

  host = strcmp (one_threat + strlen (one_threat) + 1,
                 two_threat + strlen (two_threat) + 1);
  if (host == 0)
    {
      int port = strcmp (one, two);
      if (port == 0)
        return collate_message_type (NULL,
                                     strlen (two_threat), two_threat,
                                     strlen (one_threat), one_threat);
      return port;
    }
  return host;
}

/**
 * @brief Write to a file or exit.
 *
 * @param[in]   stream    Stream to write to.
 * @param[in]   format    Format specification.
 * @param[in]   args      Arguments.
 */
#define PRINT(stream, format, args...)                                       \
  do                                                                         \
    {                                                                        \
      if (fprintf (stream, format , ## args) < 0)                            \
        return -1;                                                           \
    }                                                                        \
  while (0)

/** @todo Defined in omp.c! */
void buffer_results_xml (GString *, iterator_t *, task_t, int, int, int, int);

#if 0
void
dump (GArray *ports)
{
  int index;
  for (index = 0; index < ports->len; index++)
    {
      char *port = g_array_index (ports, char*, index);
      char *threat = port + strlen (port) + 1;
      tracef ("  == %s %s %s", threat + strlen (threat) + 1, port, threat);
    }
}
#endif

/**
 * @brief Print the XML for a report to a file.
 *
 * @param[in]  report      The report.
 * @param[in]  task        Task associated with report.
 * @param[in]  xml_file    File name.
 * @param[in]  sort_order  Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for "type".
 * @param[in]  result_hosts_only  Whether to show only hosts with results.
 * @param[in]  min_cvss_base      Minimum CVSS base of included results.  All
 *                                results if NULL.
 * @param[in]  report_format  Format of report that will be created from XML.
 * @param[in]  levels         String describing threat levels (message types)
 *                            to include in count (for example, "hmlgd" for
 *                            High, Medium, Low, loG and Debug).  All levels if
 *                            NULL.
 * @param[in]  apply_overrides    Whether to apply overrides.
 * @param[in]  search_phrase      Phrase that results must include.  All results
 *                                if NULL or "".
 * @param[in]  notes              Whether to include notes.
 * @param[in]  notes_details      If notes, Whether to include details.
 * @param[in]  overrides          Whether to include overrides.
 * @param[in]  overrides_details  If overrides, Whether to include details.
 * @param[in]  first_result       The result to start from.  The results are 0
 *                                indexed.
 * @param[in]  max_results        The maximum number of results returned.
 *
 * @return 0 on success, -1 error.
 */
static int
print_report_xml (report_t report, task_t task, gchar* xml_file,
                  int sort_order, const char* sort_field, int result_hosts_only,
                  const char *min_cvss_base, report_format_t report_format,
                  const char *levels, int apply_overrides,
                  const char *search_phrase, int notes, int notes_details,
                  int overrides, int overrides_details, int first_result,
                  int max_results)
{
  FILE *out;
  char *uuid, *tsk_uuid = NULL, *start_time, *end_time;
  int result_count, filtered_result_count, run_status;
  array_t *result_hosts;
  iterator_t results, params;

  out = fopen (xml_file, "w");

  if (out == NULL)
    {
      g_warning ("%s: fopen failed: %s\n",
                 __FUNCTION__,
                 strerror (errno));
      return -1;
    }

  levels = levels ? levels : "hmlgd";

  if (task && task_uuid (task, &tsk_uuid))
    {
      fclose (out);
      return -1;
    }

  uuid = report_uuid (report);
  PRINT (out, "<report id=\"%s\">", uuid);
  free (uuid);

  PRINT (out, "<report_format>");
  init_report_format_param_iterator (&params, report_format, 1, NULL);
  while (next (&params))
    PRINT (out,
           "<param><name>%s</name><value>%s</value></param>",
           report_format_param_iterator_name (&params),
           report_format_param_iterator_value (&params));
  cleanup_iterator (&params);
  PRINT (out, "</report_format>");

  report_scan_result_count (report, NULL, NULL, NULL,
                            apply_overrides,
                            &result_count);
  report_scan_result_count (report,
                            levels,
                            search_phrase,
                            min_cvss_base,
                            apply_overrides,
                            &filtered_result_count);
  report_scan_run_status (report, &run_status);
  PRINT
   (out,
    "<sort><field>%s<order>%s</order></field></sort>"
    "<filters>"
    "%s"
    "<phrase>%s</phrase>"
    "<notes>%i</notes>"
    "<overrides>%i</overrides>"
    "<apply_overrides>%i</apply_overrides>"
    "<result_hosts_only>%i</result_hosts_only>"
    "<min_cvss_base>%s</min_cvss_base>",
    sort_field ? sort_field : "type",
    sort_order ? "ascending" : "descending",
    levels,
    search_phrase ? search_phrase : "",
    notes ? 1 : 0,
    overrides ? 1 : 0,
    apply_overrides ? 1 : 0,
    result_hosts_only ? 1 : 0,
    min_cvss_base ? min_cvss_base : "");

  if (strchr (levels, 'h'))
    PRINT (out, "<filter>High</filter>");
  if (strchr (levels, 'm'))
    PRINT (out, "<filter>Medium</filter>");
  if (strchr (levels, 'l'))
    PRINT (out, "<filter>Low</filter>");
  if (strchr (levels, 'g'))
    PRINT (out, "<filter>Log</filter>");
  if (strchr (levels, 'd'))
    PRINT (out, "<filter>Debug</filter>");
  if (strchr (levels, 'f'))
    PRINT (out, "<filter>False Positive</filter>");

  PRINT
   (out,
    "</filters>"
    "<scan_run_status>%s</scan_run_status>",
    run_status_name (run_status
                      ? run_status
                      : TASK_STATUS_INTERNAL_ERROR));

  if (task && tsk_uuid)
    {
      char* tsk_name = task_name (task);
      PRINT (out,
             "<task id=\"%s\">"
             "<name>%s</name>"
             "</task>",
             tsk_uuid,
             tsk_name ? tsk_name : "");
      free (tsk_name);
      free (tsk_uuid);
    }

  start_time = scan_start_time (report);
  PRINT (out,
         "<scan_start>%s</scan_start>",
         start_time);
  free (start_time);

  /* Port summary. */

  {
    gchar *last_port, *last_host;
    GArray *ports = g_array_new (TRUE, FALSE, sizeof (gchar*));

    init_result_iterator
     (&results, report, 0, NULL,
      first_result,
      max_results,
      /* Sort by the requested field in the requested order, in case there is
       * a first_result and/or max_results (these are applied after the
       * sorting). */
      sort_order,
      sort_field,
      levels,
      search_phrase,
      min_cvss_base,
      apply_overrides);

    /* Buffer the results, removing duplicates. */

    last_port = NULL;
    last_host = NULL;
    while (next (&results))
      {
        const char *port = result_iterator_port (&results);
        const char *host = result_iterator_host (&results);

        if (last_port == NULL || strcmp (port, last_port)
            || strcmp (host, last_host))
          {
            const char *type;
            gchar *item;
            int port_len, type_len;

            g_free (last_port);
            last_port = g_strdup (port);
            g_free (last_host);
            last_host = g_strdup (host);

            type = result_iterator_type (&results);
            port_len = strlen (port);
            type_len = strlen (type);
            item = g_malloc (port_len
                              + type_len
                              + strlen (host)
                              + 3);
            g_array_append_val (ports, item);
            strcpy (item, port);
            strcpy (item + port_len + 1, type);
            strcpy (item + port_len + type_len + 2, host);
          }

      }
    g_free (last_port);
    g_free (last_host);

    /* Handle sorting by threat and ROWID. */

    if (sort_field == NULL || strcmp (sort_field, "port"))
      {
        int index, length;

        /** @todo Sort by ROWID if was requested. */

        /* Sort by port then threat. */

        g_array_sort (ports, compare_port_threat);

        /* Remove duplicates. */

        last_port = NULL;
        last_host = NULL;
        for (index = 0, length = ports->len; index < length; index++)
          {
            char *port = g_array_index (ports, char*, index);
            char *host = port + strlen (port) + 1;
            host += strlen (host) + 1;
            if (last_port
                && (strcmp (port, last_port) == 0)
                && (strcmp (host, last_host) == 0))
              {
                g_array_remove_index (ports, index);
                length = ports->len;
                index--;
              }
            else
              {
                last_port = port;
                last_host = host;
              }
          }

        /* Sort by threat. */

        if (sort_order)
          g_array_sort (ports, compare_message_types_asc);
        else
          g_array_sort (ports, compare_message_types_desc);
      }

    /* Write to file from the buffer. */

    PRINT (out,
             "<ports"
             " start=\"%i\""
             " max=\"%i\">",
             /* Add 1 for 1 indexing. */
             first_result + 1,
             max_results);
    {
      gchar *item;
      int index = 0;

      while ((item = g_array_index (ports, gchar*, index++)))
        {
          int port_len = strlen (item);
          int type_len = strlen (item + port_len + 1);
          PRINT (out,
                   "<port>"
                   "<host>%s</host>"
                   "%s"
                   "<threat>%s</threat>"
                   "</port>",
                   item + port_len + type_len + 2,
                   item,
                   manage_result_type_threat (item + port_len + 1));
          g_free (item);
        }
      g_array_free (ports, TRUE);
    }
    PRINT (out, "</ports>");
    cleanup_iterator (&results);
  }

  /* Result counts. */

  {
    int debugs, holes, infos, logs, warnings, false_positives;

    report_counts_id (report, &debugs, &holes, &infos, &logs,
                      &warnings, &false_positives,
                      apply_overrides, NULL);

    PRINT (out,
             "<result_count>"
             "%i"
             "<filtered>%i</filtered>"
             "<debug>%i</debug>"
             "<hole>%i</hole>"
             "<info>%i</info>"
             "<log>%i</log>"
             "<warning>%i</warning>"
             "<false_positive>%i</false_positive>"
             "</result_count>",
             result_count,
             filtered_result_count,
             debugs,
             holes,
             infos,
             logs,
             warnings,
             false_positives);
  }

  /* Results. */

  init_result_iterator (&results, report, 0, NULL,
                        first_result,
                        max_results,
                        sort_order,
                        sort_field,
                        levels,
                        search_phrase,
                        min_cvss_base,
                        apply_overrides);

  PRINT (out,
           "<results"
           " start=\"%i\""
           " max=\"%i\">",
           /* Add 1 for 1 indexing. */
           first_result + 1,
           max_results);
  if (result_hosts_only)
    result_hosts = make_array ();
  else
    /* Quiet erroneous compiler warning. */
    result_hosts = NULL;
  while (next (&results))
    {
      GString *buffer = g_string_new ("");
      buffer_results_xml (buffer,
                          &results,
                          task,
                          notes,
                          notes_details,
                          overrides,
                          overrides_details);
      PRINT (out, "%s", buffer->str);
      g_string_free (buffer, TRUE);
      if (result_hosts_only)
        array_add_new_string (result_hosts,
                              result_iterator_host (&results));
    }
  PRINT (out, "</results>");
  cleanup_iterator (&results);

  if (result_hosts_only)
    {
      gchar *host;
      int index = 0;
      array_terminate (result_hosts);
      while ((host = g_ptr_array_index (result_hosts, index++)))
        {
          iterator_t hosts;
          init_host_iterator (&hosts, report, host);
          if (next (&hosts))
            {
              PRINT (out,
                       "<host_start>"
                       "<host>%s</host>%s"
                       "</host_start>",
                       host,
                       host_iterator_start_time (&hosts));
              PRINT (out,
                       "<host_end>"
                       "<host>%s</host>%s"
                       "</host_end>",
                       host,
                       host_iterator_end_time (&hosts)
                         ? host_iterator_end_time (&hosts)
                         : "");
            }
          cleanup_iterator (&hosts);
        }
      array_free (result_hosts);
    }
  else
    {
      iterator_t hosts;
      init_host_iterator (&hosts, report, NULL);
      while (next (&hosts))
        PRINT (out,
                 "<host_start><host>%s</host>%s</host_start>",
                 host_iterator_host (&hosts),
                 host_iterator_start_time (&hosts));
      cleanup_iterator (&hosts);

      init_host_iterator (&hosts, report, NULL);
      while (next (&hosts))
        PRINT (out,
                 "<host_end><host>%s</host>%s</host_end>",
                 host_iterator_host (&hosts),
                 host_iterator_end_time (&hosts)
                  ? host_iterator_end_time (&hosts)
                  : "");
      cleanup_iterator (&hosts);
    }
  end_time = scan_end_time (report);
  PRINT (out,
           "<scan_end>%s</scan_end>",
           end_time);
  free (end_time);

  PRINT (out, "</report>");

  if (fclose (out))
    {
      g_warning ("%s: fclose failed: %s\n",
                 __FUNCTION__,
                 strerror (errno));
      return -1;
    }

  return 0;
}

/**
 * @brief Generate a report.
 *
 * @param[in]  report             Report.
 * @param[in]  report_format      Report format.
 * @param[in]  sort_order         Whether to sort ascending or descending.
 * @param[in]  sort_field         Field to sort on, or NULL for "type".
 * @param[in]  result_hosts_only  Whether to show only hosts with results.
 * @param[in]  min_cvss_base      Minimum CVSS base of included results.  All
 *                                results if NULL.
 * @param[in]  levels         String describing threat levels (message types)
 *                            to include in count (for example, "hmlgd" for
 *                            High, Medium, Low, loG and Debug).  All levels if
 *                            NULL.
 * @param[in]  apply_overrides    Whether to apply overrides.
 * @param[in]  search_phrase      Phrase that results must include.  All results
 *                                if NULL or "".
 * @param[in]  notes              Whether to include notes.
 * @param[in]  notes_details      If notes, Whether to include details.
 * @param[in]  overrides          Whether to include overrides.
 * @param[in]  overrides_details  If overrides, Whether to include details.
 * @param[in]  first_result       The result to start from.  The results are 0
 *                                indexed.
 * @param[in]  max_results        The maximum number of results returned.
 * @param[out] output_length      NULL or location for length of return.
 * @param[out] extension          NULL or location for report format extension.
 * @param[out] content_type       NULL or location for report format content
 *                                type.
 *
 * @return Contents of report on success, NULL on error.
 */
gchar *
manage_report (report_t report, report_format_t report_format, int sort_order,
               const char* sort_field, int result_hosts_only,
               const char *min_cvss_base, const char *levels,
               int apply_overrides, const char *search_phrase, int notes,
               int notes_details, int overrides, int overrides_details,
               int first_result, int max_results, gsize *output_length,
               gchar **extension, gchar **content_type)
{
  task_t task;
  gchar *xml_file;
  char xml_dir[] = "/tmp/openvasmd_XXXXXX";

  /* Print the report as XML to a file. */

  if (report_task (report, &task))
    return NULL;

  if (mkdtemp (xml_dir) == NULL)
    {
      g_warning ("%s: mkdtemp failed\n", __FUNCTION__);
      return NULL;
    }

  xml_file = g_strdup_printf ("%s/report.xml", xml_dir);
  if (print_report_xml (report, task, xml_file, sort_order, sort_field,
                        result_hosts_only, min_cvss_base, report_format,
                        levels, apply_overrides, search_phrase, notes,
                        notes_details, overrides, overrides_details,
                        first_result, max_results))
    {
      g_free (xml_file);
      return NULL;
    }

  /* Pass the file to the report format generate script, sending the output
   * to a file. */

  {
    iterator_t formats;
    const char *uuid_format;
    char *uuid_report;
    gchar *script, *script_dir;

    /* Setup file names. */

    uuid_report = report_uuid (report);
    init_report_format_iterator (&formats, report_format, 1, NULL);
    if (next (&formats) == FALSE)
      {
        g_free (xml_file);
        cleanup_iterator (&formats);
        return NULL;
      }

    /* Set convenience return parameters. */
    assert (report_format_iterator_extension (&formats));
    assert (report_format_iterator_content_type (&formats));
    if (extension)
      *extension = g_strdup (report_format_iterator_extension (&formats));
    if (content_type)
      *content_type = g_strdup (report_format_iterator_content_type (&formats));

    uuid_format = report_format_iterator_uuid (&formats);
    if (report_format_global (report_format))
      script_dir = g_build_filename (OPENVAS_SYSCONF_DIR,
                                     "openvasmd",
                                     "global_report_formats",
                                     uuid_format,
                                     NULL);
    else
      {
        assert (current_credentials.uuid);
        script_dir = g_build_filename (OPENVAS_SYSCONF_DIR,
                                       "openvasmd",
                                       "report_formats",
                                       current_credentials.uuid,
                                       uuid_format,
                                       NULL);
      }

    cleanup_iterator (&formats);

    script = g_build_filename (script_dir, "generate", NULL);

    if (!g_file_test (script, G_FILE_TEST_EXISTS))
      {
        g_free (script);
        g_free (script_dir);
        if (extension) g_free (*extension);
        if (content_type) g_free (*content_type);
        g_free (xml_file);
        return NULL;
      }

    {
      gchar *output_file, *command;
      char *previous_dir;
      int ret;

      /* Change into the script directory. */

      /** @todo NULL arg is glibc extension. */
      previous_dir = getcwd (NULL, 0);
      if (previous_dir == NULL)
        {
          g_warning ("%s: Failed to getcwd: %s\n",
                     __FUNCTION__,
                     strerror (errno));
          g_free (previous_dir);
          g_free (script);
          g_free (script_dir);
          g_free (xml_file);
          if (extension) g_free (*extension);
          if (content_type) g_free (*content_type);
          return NULL;
        }

      if (chdir (script_dir))
        {
          g_warning ("%s: Failed to chdir: %s\n",
                     __FUNCTION__,
                     strerror (errno));
          g_free (previous_dir);
          g_free (script);
          g_free (script_dir);
          g_free (xml_file);
          if (extension) g_free (*extension);
          if (content_type) g_free (*content_type);
          return NULL;
        }
      g_free (script_dir);

      output_file = g_strdup_printf ("%s/report.out", xml_dir);

      /* Call the script. */

      command = g_strdup_printf ("/bin/sh %s %s > %s"
                                 " 2> /dev/null",
                                 script,
                                 xml_file,
                                 output_file);
      g_free (script);

      g_debug ("   command: %s\n", command);

      /* RATS: ignore, command is defined above. */
      if (ret = system (command),
          /** @todo ret is always -1. */
          0 && ((ret) == -1
                || WEXITSTATUS (ret)))
        {
          g_warning ("%s: system failed with ret %i, %i, %s\n",
                     __FUNCTION__,
                     ret,
                     WEXITSTATUS (ret),
                     command);
          if (chdir (previous_dir))
            g_warning ("%s: and chdir failed\n",
                       __FUNCTION__);
          g_free (previous_dir);
          g_free (command);
          g_free (output_file);
          if (extension) g_free (*extension);
          if (content_type) g_free (*content_type);
          return NULL;
        }

      {
        GError *get_error;
        gchar *output;
        gsize output_len;

        g_free (command);

        /* Change back to the previous directory. */

        if (chdir (previous_dir))
          {
            g_warning ("%s: Failed to chdir back: %s\n",
                       __FUNCTION__,
                       strerror (errno));
            g_free (previous_dir);
            g_free (xml_file);
            if (extension) g_free (*extension);
            if (content_type) g_free (*content_type);
            return NULL;
          }
        g_free (previous_dir);

        /* Read the script output from file. */

        get_error = NULL;
        g_file_get_contents (output_file,
                             &output,
                             &output_len,
                             &get_error);
        g_free (output_file);
        if (get_error)
          {
            g_warning ("%s: Failed to get output: %s\n",
                       __FUNCTION__,
                       get_error->message);
            g_error_free (get_error);
            if (extension) g_free (*extension);
            if (content_type) g_free (*content_type);
            return NULL;
          }

        /* Remove the directory. */

        file_utils_rmdir_rf (xml_dir);

        /* Return the output. */

        if (output_length) *output_length = output_len;

        return output;
      }
    }
  }
}

/**
 * @brief Size of base64 chunk in manage_send_report.
 */
#define MANAGE_SEND_REPORT_CHUNK64_SIZE 262144

/**
 * @brief Size of file chunk in manage_send_report.
 */
#define MANAGE_SEND_REPORT_CHUNK_SIZE (MANAGE_SEND_REPORT_CHUNK64_SIZE * 3 / 4)

/**
 * @brief Generate a report.
 *
 * @param[in]  report             Report.
 * @param[in]  report_format      Report format.
 * @param[in]  sort_order         Whether to sort ascending or descending.
 * @param[in]  sort_field         Field to sort on, or NULL for "type".
 * @param[in]  result_hosts_only  Whether to show only hosts with results.
 * @param[in]  min_cvss_base      Minimum CVSS base of included results.  All
 *                                results if NULL.
 * @param[in]  levels         String describing threat levels (message types)
 *                            to include in count (for example, "hmlgd" for
 *                            High, Medium, Low, loG and Debug).  All levels if
 *                            NULL.
 * @param[in]  apply_overrides    Whether to apply overrides.
 * @param[in]  search_phrase      Phrase that results must include.  All results
 *                                if NULL or "".
 * @param[in]  notes              Whether to include notes.
 * @param[in]  notes_details      If notes, Whether to include details.
 * @param[in]  overrides          Whether to include overrides.
 * @param[in]  overrides_details  If overrides, Whether to include details.
 * @param[in]  first_result       The result to start from.  The results are 0
 *                                indexed.
 * @param[in]  max_results        The maximum number of results returned.
 * @param[in]  base64             Whether to base64 encode the report.
 * @param[in]  send               Function to write to client.
 * @param[in]  send_data_1        Second argument to \p send.
 * @param[in]  send_data_2        Third argument to \p send.
 *
 * @return 0 success, -1 error.
 */
int
manage_send_report (report_t report, report_format_t report_format,
                    int sort_order, const char* sort_field,
                    int result_hosts_only, const char *min_cvss_base,
                    const char *levels, int apply_overrides,
                    const char *search_phrase, int notes, int notes_details,
                    int overrides, int overrides_details, int first_result,
                    int max_results, int base64,
                    gboolean (*send) (const char *, int (*) (void*), void*),
                    int (*send_data_1) (void*), void *send_data_2)
{
  task_t task;
  gchar *xml_file;
  char xml_dir[] = "/tmp/openvasmd_XXXXXX";

  /* Print the report as XML to a file. */

  if (report_task (report, &task))
    return -1;

  if (mkdtemp (xml_dir) == NULL)
    {
      g_warning ("%s: mkdtemp failed\n", __FUNCTION__);
      return -1;
    }

  xml_file = g_strdup_printf ("%s/report.xml", xml_dir);
  if (print_report_xml (report, task, xml_file, sort_order, sort_field,
                        result_hosts_only, min_cvss_base, report_format,
                        levels, apply_overrides, search_phrase, notes,
                        notes_details, overrides, overrides_details,
                        first_result, max_results))
    {
      g_free (xml_file);
      return -1;
    }

  /* Pass the file to the report format generate script, sending the output
   * to a file. */

  {
    iterator_t formats;
    const char *uuid_format;
    char *uuid_report;
    gchar *script, *script_dir;

    /* Setup file names. */

    uuid_report = report_uuid (report);
    init_report_format_iterator (&formats, report_format, 1, NULL);
    if (next (&formats) == FALSE)
      {
        g_free (xml_file);
        cleanup_iterator (&formats);
        return -1;
      }

    uuid_format = report_format_iterator_uuid (&formats);
    if (report_format_global (report_format))
      script_dir = g_build_filename (OPENVAS_SYSCONF_DIR,
                                     "openvasmd",
                                     "global_report_formats",
                                     uuid_format,
                                     NULL);
    else
      {
        assert (current_credentials.uuid);
        script_dir = g_build_filename (OPENVAS_SYSCONF_DIR,
                                       "openvasmd",
                                       "report_formats",
                                       current_credentials.uuid,
                                       uuid_format,
                                       NULL);
      }

    cleanup_iterator (&formats);

    script = g_build_filename (script_dir, "generate", NULL);

    if (!g_file_test (script, G_FILE_TEST_EXISTS))
      {
        g_free (script);
        g_free (script_dir);
        g_free (xml_file);
        return -1;
      }

    {
      gchar *output_file, *command;
      char *previous_dir;
      int ret;

      /* Change into the script directory. */

      /** @todo NULL arg is glibc extension. */
      previous_dir = getcwd (NULL, 0);
      if (previous_dir == NULL)
        {
          g_warning ("%s: Failed to getcwd: %s\n",
                     __FUNCTION__,
                     strerror (errno));
          g_free (previous_dir);
          g_free (script);
          g_free (script_dir);
          g_free (xml_file);
          return -1;
        }

      if (chdir (script_dir))
        {
          g_warning ("%s: Failed to chdir: %s\n",
                     __FUNCTION__,
                     strerror (errno));
          g_free (previous_dir);
          g_free (script);
          g_free (script_dir);
          g_free (xml_file);
          return -1;
        }
      g_free (script_dir);

      output_file = g_strdup_printf ("%s/report.out", xml_dir);

      /* Call the script. */

      command = g_strdup_printf ("/bin/sh %s %s > %s"
                                 " 2> /dev/null",
                                 script,
                                 xml_file,
                                 output_file);
      g_free (script);
      g_free (xml_file);

      g_debug ("   command: %s\n", command);

      /* RATS: ignore, command is defined above. */
      if (ret = system (command),
          /** @todo ret is always -1. */
          0 && ((ret) == -1
                || WEXITSTATUS (ret)))
        {
          g_warning ("%s: system failed with ret %i, %i, %s\n",
                     __FUNCTION__,
                     ret,
                     WEXITSTATUS (ret),
                     command);
          if (chdir (previous_dir))
            g_warning ("%s: and chdir failed\n",
                       __FUNCTION__);
          g_free (previous_dir);
          g_free (command);
          g_free (output_file);
          return -1;
        }

      {
        char chunk[MANAGE_SEND_REPORT_CHUNK_SIZE + 1];
        FILE *stream;

        g_free (command);

        /* Change back to the previous directory. */

        if (chdir (previous_dir))
          {
            g_warning ("%s: Failed to chdir back: %s\n",
                       __FUNCTION__,
                       strerror (errno));
            g_free (previous_dir);
            g_free (output_file);
            return -1;
          }
        g_free (previous_dir);

        /* Read the script output from file in chunks, sending to client. */

        stream = fopen (output_file, "r");
        g_free (output_file);
        if (stream == NULL)
          {
            g_warning ("%s: %s\n",
                       __FUNCTION__,
                       strerror (errno));
            return -1;
          }

        while (1)
          {
            int left;
            char *dest;

            /* Read a chunk. */

            left = MANAGE_SEND_REPORT_CHUNK_SIZE;
            dest = chunk;
            while (1)
              {
                int ret = fread (dest, 1, left, stream);
                if (ferror (stream))
                  {
                    fclose (stream);
                    g_warning ("%s: error after fread\n", __FUNCTION__);
                    return -1;
                  }
                left -= ret;
                if (left == 0)
                  break;
                if (feof (stream))
                  break;
                dest += ret;
              }

            /* Send the chunk. */

            if (left < MANAGE_SEND_REPORT_CHUNK_SIZE)
              {
                if (base64)
                  {
                    gchar *chunk64;
                    chunk64 = g_base64_encode ((guchar*) chunk,
                                               MANAGE_SEND_REPORT_CHUNK_SIZE
                                                - left);
                    if (send (chunk64, send_data_1, send_data_2))
                      {
                        g_free (chunk64);
                        fclose (stream);
                        g_warning ("%s: send error\n", __FUNCTION__);
                        return -1;
                      }
                    g_free (chunk64);
                  }
                else
                  {
                    chunk[MANAGE_SEND_REPORT_CHUNK_SIZE - left] = '\0';
                    if (send (chunk, send_data_1, send_data_2))
                      {
                        fclose (stream);
                        g_warning ("%s: send error\n", __FUNCTION__);
                        return -1;
                      }
                  }
              }

            /* Check if there's more. */

            if (feof (stream))
              break;
          }

        fclose (stream);

        /* Remove the directory. */

        file_utils_rmdir_rf (xml_dir);

        /* Return the output. */

        return 0;
      }
    }
  }
}


/* More task stuff. */

/** @todo Should be on tasks page above. */

/**
 * @brief Return the number of reports associated with a task.
 *
 * @param[in]  task  Task.
 *
 * @return Number of reports.
 */
unsigned int
task_report_count (task_t task)
{
  return (unsigned int) sql_int (0, 0,
                                 "SELECT count(*) FROM reports WHERE task = %llu;",
                                 task);
}

/**
 * @brief Return the number of finished reports associated with a task.
 *
 * @param[in]  task  Task.
 *
 * @return Number of reports.
 */
unsigned int
task_finished_report_count (task_t task)
{
  return (unsigned int) sql_int (0, 0,
                                 "SELECT count(*) FROM reports"
                                 " WHERE task = %llu"
                                 " AND scan_run_status = %u;",
                                 task,
                                 TASK_STATUS_DONE);
}

/**
 * @brief Return the trend of a task.
 *
 * @param[in]  task      Task.
 * @param[in]  override  Whether to override the threat.
 *
 * @return "up", "down", "more", "less", "same" or if too few reports "".
 */
const char *
task_trend (task_t task, int override)
{
  report_t last_report, second_last_report;
  int holes_a, warns_a, infos_a, logs_a, threat_a, false_positives_a;
  int holes_b, warns_b, infos_b, logs_b, threat_b, false_positives_b;

  /* Ensure there are enough reports. */

  if (task_finished_report_count (task) <= 1)
    return "";

  /* Skip running tasks. */

  if (task_run_status (task) == TASK_STATUS_RUNNING)
    return "";

  /* Get details of last report. */

  task_last_report (task, &last_report);
  if (last_report == 0)
    return "";

  /* Count the logs and false positives too, as report_counts_id is faster
   * with all five. */
  if (report_counts_id (last_report, NULL, &holes_a, &infos_a, &logs_a, &warns_a,
                        &false_positives_a, override, NULL))
    /** @todo Either fail better or abort at SQL level. */
    abort ();

  if (holes_a > 0)
    threat_a = 4;
  else if (warns_a > 0)
    threat_a = 3;
  else if (infos_a > 0)
    threat_a = 2;
  else
    threat_a = 1;

  /* Get details of second last report. */

  task_second_last_report (task, &second_last_report);
  if (second_last_report == 0)
    return "";

  /* Count the logs and false positives too, as report_counts_id is faster
   * with all five. */
  if (report_counts_id (second_last_report, NULL, &holes_b, &infos_b, &logs_b,
                        &warns_b, &false_positives_b, override, NULL))
    /** @todo Either fail better or abort at SQL level. */
    abort ();

  if (holes_b > 0)
    threat_b = 4;
  else if (warns_b > 0)
    threat_b = 3;
  else if (infos_b > 0)
    threat_b = 2;
  else
    threat_b = 1;

  /* Check if the threat level changed. */

  if (threat_a > threat_b)
    return "up";

  if (threat_a < threat_b)
    return "down";

  /* Check if the threat count changed in the highest level. */

  if (holes_a)
    {
      if (holes_a > holes_b)
        return "more";
      if (holes_a < holes_b)
        return "less";
      return "same";
    }

  if (warns_a)
    {
      if (warns_a > warns_b)
        return "more";
      if (warns_a < warns_b)
        return "less";
      return "same";
    }

  if (infos_a)
    {
      if (infos_a > infos_b)
        return "more";
      if (infos_a < infos_b)
        return "less";
      return "same";
    }

  return "same";
}

/**
 * @brief Set the attack state of a scan (given by a report).
 *
 * @param[in]  report  Report.
 * @param[in]  host    Host to which the state refers.
 * @param[in]  state   New state.
 */
void
set_scan_attack_state (report_t report, const char* host, const char* state)
{
  sql ("UPDATE report_hosts SET attack_state = '%s'"
       " WHERE host = '%s' AND report = %llu;",
       state,
       host,
       report);
}

/**
 * @brief Return the total number of debug messages of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Number of debug messages.
 */
int
task_debugs_size (task_t task)
{
  return sql_int (0, 0,
                  "SELECT count(*) FROM results"
                  " WHERE task = %llu AND results.type = 'Debug Message';",
                  task);
}

/**
 * @brief Return the total number of false positive results in a task.
 *
 * @param[in]  task  Task.
 *
 * @return Number of false positive results.
 */
int
task_false_positive_size (task_t task)
{
  return sql_int (0, 0,
                  "SELECT count(*) FROM results"
                  " WHERE task = %llu AND results.type = 'False Positive';",
                  task);
}

/**
 * @brief Return the total number of hole messages of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Number of hole messages.
 */
int
task_holes_size (task_t task)
{
  return sql_int (0, 0,
                  "SELECT count(*) FROM results"
                  " WHERE task = %llu AND results.type = 'Security Hole';",
                  task);
}

/**
 * @brief Return the total number of info messages of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Number of info messages.
 */
int
task_infos_size (task_t task)
{
  return sql_int (0, 0,
                  "SELECT count(*) FROM results"
                  " WHERE task = %llu AND results.type = 'Security Note';",
                  task);
}

/**
 * @brief Return the total number of log messages of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Number of log messages.
 */
int
task_logs_size (task_t task)
{
  return sql_int (0, 0,
                  "SELECT count(*) FROM results"
                  " WHERE task = %llu AND results.type = 'Log Message';",
                  task);
}

/**
 * @brief Return the total number of note messages of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Number of note messages.
 */
int
task_warnings_size (task_t task)
{
  return sql_int (0, 0,
                  "SELECT count(*) FROM results"
                  " WHERE task = %llu AND results.type = 'Security Warning';",
                  task);
}

/**
 * @brief Dummy function.
 */
void
free_tasks ()
{
  /* Empty. */
}

/**
 * @brief Make a task.
 *
 * The char* parameters name and comment are used directly and freed
 * when the task is freed.
 *
 * @param[in]  name     The name of the task.
 * @param[in]  time     The period of the task, in seconds.
 * @param[in]  comment  A comment associated the task.
 *
 * @return A pointer to the new task.
 */
task_t
make_task (char* name, unsigned int time, char* comment)
{
  task_t task;
  char* uuid = openvas_uuid_make ();
  gchar *quoted_name, *quoted_comment;
  if (uuid == NULL) abort ();
  quoted_name = name ? sql_quote ((gchar*) name) : NULL;
  quoted_comment = comment ? sql_quote ((gchar*) comment) : NULL;
  sql ("INSERT into tasks"
       " (owner, uuid, name, hidden, time, comment, schedule,"
       "  schedule_next_time, slave)"
       " VALUES ((SELECT ROWID FROM users WHERE users.uuid = '%s'),"
       "         '%s', '%s', 0, %u, '%s', 0, 0, 0);",
       current_credentials.uuid,
       uuid,
       quoted_name ? quoted_name : "",
       time,
       quoted_comment ? quoted_comment : "");
  task = sqlite3_last_insert_rowid (task_db);
  set_task_run_status (task, TASK_STATUS_NEW);
  free (uuid);
  free (name);
  free (comment);
  g_free (quoted_name);
  g_free (quoted_comment);
  return task;
}

#ifdef S_SPLINT_S
typedef /*@only@*/ struct dirent * only_dirent_pointer;
#endif

/**
 * @brief Dummy function.
 *
 * @return 0.
 */
int
load_tasks ()
{
  return 0;
}

/**
 * @brief Dummy function.
 *
 * @return 0.
 */
int
save_tasks ()
{
  return 0;
}

/**
 * @brief Set a task parameter.
 *
 * The "value" parameter is used directly and freed either immediately or
 * when the task is freed.
 *
 * @param[in]  task       A pointer to a task.
 * @param[in]  parameter  The name of the parameter (in any case): RCFILE,
 *                        NAME or COMMENT.
 * @param[in]  value      The value of the parameter, in base64 if parameter
 *                        is "RCFILE".
 *
 * @return 0 on success, -2 if parameter name error, -3 value error (NULL).
 */
int
set_task_parameter (task_t task, const char* parameter, /*@only@*/ char* value)
{
  /** @todo Free value consistently. */

  tracef ("   set_task_parameter %u %s\n",
          task_id (task),
          parameter ? parameter : "(null)");
  if (value == NULL) return -3;
  if (parameter == NULL)
    {
      free (value);
      return -2;
    }
  if (strcasecmp ("RCFILE", parameter) == 0)
    {
      gsize rc_len;
      guchar *rc;
      gchar *quoted_rc;

      rc = g_base64_decode (value, &rc_len);

      sql ("BEGIN IMMEDIATE;");

      /* Remove all files from the task. */

      sql ("DELETE FROM task_files WHERE task = %llu;", task);

      /* Update task description (rcfile). */

      quoted_rc = sql_quote ((gchar*) rc);
      sql ("UPDATE tasks SET description = '%s' WHERE ROWID = %llu;",
           quoted_rc,
           task);
      g_free (quoted_rc);

      /* Update task config. */

      {
        config_t config;
        target_t target;
        char *config_name, *config_uuid;
        char *quoted_config_name, *quoted_selector;

        config_uuid = task_config_uuid (task);
        if (config_uuid == NULL)
          {
            g_free (rc);
            sql ("ROLLBACK");
            return -1;
          }

        target = task_target (task);
        if (target == 0)
          {
            free (config_uuid);
            g_free (rc);
            sql ("ROLLBACK");
            return -1;
          }

        if (find_config (config_uuid, &config))
          {
            free (config_uuid);
            g_free (rc);
            sql ("ROLLBACK");
            return -1;
          }
        else if (config == 0)
          {
            free (config_uuid);
            g_free (rc);
            sql ("ROLLBACK");
            return -1;
          }
        else
          {
            char *hosts, *selector;

            free (config_uuid);

            config_name = task_config_name (task);
            if (config_name == NULL)
              {
                g_free (rc);
                sql ("ROLLBACK");
                return -1;
              }

            selector = config_nvt_selector (config);
            if (selector == NULL)
              {
                free (config_name);
                g_free (rc);
                sql ("ROLLBACK");
                return -1;
              }
            quoted_selector = sql_quote (selector);
            free (selector);

            /* Flush config preferences. */

            sql ("DELETE FROM config_preferences WHERE config = %llu;",
                 config);

            /* Flush selector NVTs. */

            sql ("DELETE FROM nvt_selectors WHERE name = '%s';",
                 quoted_selector);

            /* Replace targets. */

            hosts = rc_preference ((gchar*) rc, "targets");
            if (hosts == NULL)
              {
                free (config_name);
                free (quoted_selector);
                g_free (rc);
                sql ("ROLLBACK");
                return -1;
              }
            set_target_hosts (target, hosts);
            free (hosts);

            /* Fill config from RC. */

            quoted_config_name = sql_quote (config_name);
            free (config_name);
            /* This modifies rc. */
            if (insert_rc_into_config (config, quoted_config_name,
                                       quoted_selector, (gchar*) rc))
              {
                free (quoted_selector);
                g_free (rc);
                sql ("ROLLBACK");
                return -1;
              }
            free (quoted_selector);
            g_free (rc);
          }

        sql ("COMMIT");
      }
    }
  else if (strcasecmp ("NAME", parameter) == 0)
    {
      gchar* quote = sql_nquote (value, strlen (value));
      sql ("UPDATE tasks SET name = '%s' WHERE ROWID = %llu;",
           value,
           task);
      g_free (quote);
    }
  else if (strcasecmp ("COMMENT", parameter) == 0)
    {
      gchar* quote = sql_nquote (value, strlen (value));
      sql ("UPDATE tasks SET comment = '%s' WHERE ROWID = %llu;",
           value,
           task);
      g_free (quote);
    }
  else
    {
      free (value);
      return -2;
    }
  return 0;
}

/**
 * @brief Request deletion of a task.
 *
 * Stop the task beforehand with \ref stop_task, if it is running.
 *
 * @param[in]  task_pointer  A pointer to the task.
 *
 * @return 0 if deleted, 1 if delete requested, 2 if task is hidden,
 *         -1 if error.
 */
int
request_delete_task (task_t* task_pointer)
{
  task_t task = *task_pointer;

  tracef ("   request delete task %u\n", task_id (task));

  if (sql_int (0, 0,
               "SELECT hidden from tasks WHERE ROWID = %llu;",
               *task_pointer))
    return 2;

  if (current_credentials.uuid == NULL) return -1;

  switch (stop_task (task))
    {
      case 0:    /* Stopped. */
        /** @todo Check delete-task return. */
        delete_task (task);
        return 0;
      case 1:    /* Stop requested. */
        set_task_run_status (task, TASK_STATUS_DELETE_REQUESTED);
        return 1;
      default:   /* Programming error. */
        assert (0);
      case -1:   /* Error. */
        return -1;
        break;
    }

  return 0;
}

/**
 * @brief Complete deletion of a task.
 *
 * @param[in]  task  A pointer to the task.
 *
 * @return 0 on success, 1 if task is hidden, -1 on error.
 */
int
delete_task (task_t task)
{
  char* tsk_uuid;

  tracef ("   delete task %u\n", task_id (task));

  sql ("BEGIN EXCLUSIVE;");

  if (sql_int (0, 0, "SELECT hidden from tasks WHERE ROWID = %llu;", task))
    {
      sql ("ROLLBACK;");
      return -1;
    }

  /** @todo Many other places just assert this. */
  if (current_credentials.uuid == NULL)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  if (task_uuid (task, &tsk_uuid)
      || delete_reports (task))
    {
      sql ("ROLLBACK;");
      return -1;
    }

  sql ("DELETE FROM results WHERE task = %llu;", task);
  sql ("DELETE FROM tasks WHERE ROWID = %llu;", task);
  sql ("DELETE FROM task_escalators WHERE task = %llu;", task);
  sql ("DELETE FROM task_files WHERE task = %llu;", task);

  sql ("COMMIT;");
  return 0;
}

/**
 * @brief Append text to the comment associated with a task.
 *
 * @param[in]  task    A pointer to the task.
 * @param[in]  text    The text to append.
 * @param[in]  length  Length of the text.
 */
void
append_to_task_comment (task_t task, const char* text, /*@unused@*/ int length)
{
  append_to_task_string (task, "comment", text);
}

/**
 * @brief Append text to the name associated with a task.
 *
 * @param[in]  task    A pointer to the task.
 * @param[in]  text    The text to append.
 * @param[in]  length  Length of the text.
 */
void
append_to_task_name (task_t task, const char* text, /*@unused@*/ int length)
{
  append_to_task_string (task, "name", text);
}

/**
 * @brief Add a line to a task description.
 *
 * @param[in]  task         A pointer to the task.
 * @param[in]  line         The line.
 * @param[in]  line_length  The length of the line.
 */
void
add_task_description_line (task_t task, const char* line,
                           /*@unused@*/ size_t line_length)
{
  append_to_task_string (task, "description", line);
}

/**
 * @brief Set the ports for a particular host in a scan.
 *
 * @param[in]  report   Report associated with scan.
 * @param[in]  host     Host.
 * @param[in]  current  New value for port currently being scanned.
 * @param[in]  max      New value for last port to be scanned.
 */
void
set_scan_ports (report_t report, const char* host, unsigned int current,
                unsigned int max)
{
  sql ("UPDATE report_hosts SET current_port = %i, max_port = %i"
       " WHERE host = '%s' AND report = %llu;",
       current, max, host, report);
}

/**
 * @brief Add an open port as a result to a task.
 *
 * @param[in]  task  The task.
 * @param[in]  host  The host the port is on.
 * @param[in]  port  The port string.
 */
void
append_task_open_port (task_t task, const char *host, const char *port)
{
  result_t result;
  result = make_result (task, host, host, port, "0", "Log Message",
                        "Open port.");
  if (current_report) report_add_result (current_report, result);
}

/**
 * @brief Find a task given an identifier.
 *
 * @param[in]   uuid  A task identifier.
 * @param[out]  task  Task return, 0 if succesfully failed to find task.
 *
 * @return FALSE on success (including if failed to find task), TRUE on error.
 */
gboolean
find_task (const char* uuid, task_t* task)
{
  if (user_owns_uuid ("task", uuid) == 0)
    {
      *task = 0;
      return FALSE;
    }
  switch (sql_int64 (task, 0, 0,
                     "SELECT ROWID FROM tasks WHERE uuid = '%s';",
                     uuid))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *task = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        return TRUE;
        break;
    }

  return FALSE;
}

/**
 * @brief Find a report given an identifier.
 *
 * @param[in]   uuid    A report identifier.
 * @param[out]  report  Report return, 0 if succesfully failed to find report.
 *
 * @return FALSE on success (including if failed to find report), TRUE on error.
 */
gboolean
find_report (const char* uuid, report_t* report)
{
  if (user_owns_uuid ("report", uuid) == 0)
    {
      *report = 0;
      return FALSE;
    }
  switch (sql_int64 (report, 0, 0,
                     "SELECT ROWID FROM reports WHERE uuid = '%s';",
                     uuid))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *report = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        return TRUE;
        break;
    }

  return FALSE;
}

/**
 * @brief Reset all running information for a task.
 *
 * @param[in]  task  Task.
 */
void
reset_task (task_t task)
{
  sql ("UPDATE tasks SET"
       " start_time = '',"
       " end_time = ''"
       " WHERE ROWID = %llu;",
       task);
}

/**
 * @brief Add a file to a task, or update the file on the task.
 *
 * @param[in]  task     Task.
 * @param[in]  name     Name of file.
 * @param[in]  content  Content for file in base64 encoding.
 */
void
manage_task_update_file (task_t task, const char *name,
                         const void *content)
{
  gchar* quoted_name = sql_quote (name);
  gchar* quoted_content = sql_quote (content);

  /** @todo Probably better to save ASCII instead of base64. */

  if (sql_int (0, 0,
               "SELECT count(*) FROM task_files"
               " WHERE task = %llu AND name = '%s';",
               task,
               quoted_name))
    {
      /* Update the existing file. */

      sql ("UPDATE task_files SET content = '%s'"
           " WHERE task = %llu AND name = '%s';",
           quoted_content,
           task,
           quoted_name);
    }
  else
    {
      /* Insert the file. */

      sql ("INSERT INTO task_files (task, name, content)"
           " VALUES (%llu, '%s', '%s');",
           task,
           quoted_name,
           quoted_content);
    }

  g_free (quoted_name);
  g_free (quoted_content);
}

/**
 * @brief Remove a file on a task.
 *
 * @param[in]  task     Task.
 * @param[in]  name     Name of file.
 *
 * @return 0 success, -1 error.
 */
int
manage_task_remove_file (task_t task, const char *name)
{
  if (sql_int (0, 0,
               "SELECT count(*) FROM task_files"
               " WHERE task = %llu AND name = '%s';",
               task))
    {
      gchar* quoted_name = sql_quote (name);
      sql ("DELETE FROM task_files WHERE task = %llu AND name = '%s';",
           task,
           quoted_name);
      g_free (quoted_name);
      return 0;
    }
  return -1;
}


/**
 * @brief Initialise a task file iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  task      Task.
 * @param[in]  file      File name, NULL for all files.
 */
void
init_task_file_iterator (iterator_t* iterator, task_t task, const char* file)
{
  gchar* sql;
  if (file)
    {
      gchar *quoted_file = sql_nquote (file, strlen (file));
      sql = g_strdup_printf ("SELECT name, content, length(content)"
                             " FROM task_files"
                             " WHERE task = %llu"
                             " AND name = '%s';",
                             task, quoted_file);
      g_free (quoted_file);
    }
  else
    sql = g_strdup_printf ("SELECT name, content, length(content)"
                           " FROM task_files"
                           " WHERE task = %llu;",
                           task);
  init_iterator (iterator, sql);
  g_free (sql);
}

/**
 * @brief Get the name of the file from a task file iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name of the file or NULL if iteration is complete.
 */
DEF_ACCESS (task_file_iterator_name, 0);

/**
 * @brief Get the content of the file from a task file iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Content of the file or NULL if iteration is complete.
 */
DEF_ACCESS (task_file_iterator_content, 1);

/**
 * @brief Get the length from a task file iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Length.
 */
int
task_file_iterator_length (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (int) sqlite3_column_int (iterator->stmt, 2);
  return ret;
}


/* Targets. */

/**
 * @brief Find a target given a UUID.
 *
 * @param[in]   uuid    UUID of target.
 * @param[out]  target  Target return, 0 if succesfully failed to find target.
 *
 * @return FALSE on success (including if failed to find target), TRUE on error.
 */
gboolean
find_target (const char* uuid, target_t* target)
{
  gchar *quoted_uuid = sql_quote (uuid);
  if (user_owns_uuid ("target", quoted_uuid) == 0)
    {
      g_free (quoted_uuid);
      *target = 0;
      return FALSE;
    }
  switch (sql_int64 (target, 0, 0,
                     "SELECT ROWID FROM targets WHERE uuid = '%s';",
                     quoted_uuid))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *target = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        g_free (quoted_uuid);
        return TRUE;
        break;
    }

  g_free (quoted_uuid);
  return FALSE;
}

/**
 * @brief Make a copy of a target.
 *
 * @param[in]  target  Target to copy.
 * @param[in]  name    Name for new target.
 *
 * @return Address of matching character, else NULL.
 */
static target_t
duplicate_target (target_t target, const char *name)
{
  char *quoted_name = sql_quote (name);
  sql ("INSERT INTO targets"
       " (uuid, owner, name, hosts, comment, lsc_credential,"
       "  smb_lsc_credential)"
       " SELECT make_uuid (), owner, uniquify ('target', '%s', owner), hosts,"
       "        comment, lsc_credential, smb_lsc_credential"
       " FROM targets WHERE ROWID = %llu;",
       quoted_name,
       target);
  g_free (quoted_name);
  return sqlite3_last_insert_rowid (task_db);
}

/**
 * @brief Search backwards in a string for a character.
 *
 * Start at the character before \p point.
 *
 * @param[in]  start  Start of string.
 * @param[in]  point  Current position.
 * @param[in]  ch     Character.
 *
 * @return Address of matching character, else NULL.
 */
static char *
strbchr (char *start, char *point, char ch)
{
  while (1)
    {
      if (point == start)
        return NULL;
      point--;
      if (*point == ch)
        return point;
    }
}

/**
 * @brief Return number of hosts described by a hosts string.
 *
 * @param[in]  hosts  String describing hosts.
 *
 * @return Number of hosts, or -1 on error.
 */
int
manage_max_hosts (const char *hosts)
{
  long count = 0;
  gchar** split = g_strsplit (hosts, ",", 0);
  gchar** point = split;

  /** @todo Check for errors in "hosts". */

  while (*point)
    {
      gchar *slash, *hyphen;
      slash = strchr (*point, '/');
      hyphen = strchr (*point, '-');
      if (slash)
        {
          if (hyphen)
            /* Range and netmask. */
            return -1;

          slash++;
          if (*slash)
            {
              long int mask;
              struct in_addr addr;

              if (strchr (*point, ':'))
                /* IPv6.  Scanner current only supports single addresses. */
                count++;
              else
                {
                  /* IPv4. */

                  /* Convert text after slash to a bit netmask. */

                  if (strchr (slash, '.')
                      && (atoi (slash) > 32)
                      && inet_aton (slash, &addr))
                    {
                      in_addr_t haddr;

                      /* 192.168.200.0/255.255.255.252 */

                      haddr = ntohl (addr.s_addr);
                      mask = 32;
                      while ((haddr & 1) == 0)
                        {
                          mask--;
                          haddr = haddr >> 1;
                        }
                      if (mask < 8 || mask > 32) return -1;
                    }
                  else
                    {
                      /* 192.168.200.0/30 */

                      errno = 0;
                      mask = strtol (slash, NULL, 10);
                      if (errno == ERANGE || mask < 8 || mask > 32) return -1;
                    }

                  /* Calculate number of hosts. */

                  count += 1L << (32 - mask);
                  /* Leave out the network and broadcast addresses. */
                  if (mask < 31) count--;
                }
            }
          else
            /* Just a trailing /. */
            count++;
        }
      else if (hyphen)
        {
          hyphen++;
          if (*hyphen)
            {
              int dot_count, total_dot_count;
              const gchar* dot;

              /* An address specifying a range. */

              if (strchr (hyphen, '-'))
                /* Multiple ranges. */
                return -1;

              dot_count = 0;
              dot = hyphen;
              while ((dot = strchr (dot, '.')))
                dot++, dot_count++;

              dot_count = 0;
              dot = hyphen;
              while ((dot = strchr (dot, '.')))
                dot++, dot_count++;

              total_dot_count = 0;
              dot = *point;
              while ((dot = strchr (dot, '.')))
                dot++, total_dot_count++;

              if (total_dot_count == 6)
                {
                  int one, two, subcount;
                  char *pos_one, *pos_two;

                  /* 192.168.1.102-192.168.1.104 */

                  pos_one = *point;
                  pos_two = hyphen;
                  subcount = 0;

                  /* First. */

                  one = atoi (pos_one);
                  two = atoi (pos_two);

                  if (one > two)
                    return -1;
                  if (one < two)
                    subcount += (two - one + 1) * 256 * 256 * 255;

                  /* Second. */

                  pos_one = strchr (pos_one, '.');
                  pos_one++;

                  pos_two = strchr (pos_two, '.');
                  pos_two++;

                  one = atoi (pos_one);
                  two = atoi (pos_two);

                  if (one > two)
                    return -1;
                  if (one < two)
                    subcount += (two - one + 1) * 256 * 255;

                  /* Third. */

                  pos_one = strchr (pos_one, '.');
                  pos_one++;

                  pos_two = strchr (pos_two, '.');
                  pos_two++;

                  one = atoi (pos_one);
                  two = atoi (pos_two);

                  if (one > two)
                    return -1;
                  if (one < two)
                    subcount += (two - one + 1) * 255;

                  /* Fourth. */

                  pos_one = strchr (pos_one, '.');
                  pos_one++;

                  pos_two = strchr (pos_two, '.');
                  pos_two++;
                  if (*pos_two == '\0')
                    /* Trailing dot. */
                    return -1;

                  one = atoi (pos_one);
                  two = atoi (pos_two);

                  if (one > two)
                    return -1;
                  if (one < two)
                    subcount += (two - one + 1);

                  count += subcount;
                }
              else if (total_dot_count <= 3)
                {
                  int start, end;

                  /* 192.168.1.102-104 */

                  end = atoi (hyphen);
                  dot = strbchr (*point, hyphen, '.');
                  dot = dot ? (dot + 1) : *point;
                  start = atoi (dot);

                  if (end < start)
                    {
                      int tem = end;
                      end = start;
                      start = tem;
                    }

                  if (end - start > 255)
                    return -1;

                  if (start == end)
                    count++;
                  else
                    count += (end - start + 1);
                }
              else
                {
                  /* 192.168-169.1.102-104 */
                  return -1;
                }
            }
          else
            /* Just a trailing -. */
            count++;
        }
      else
        count++;
      point += 1;
    }
  return count;
}

/**
 * @brief Create a target.
 *
 * The \param hosts and \param target_locator parameters are mutually
 * exclusive, if target_locator is not NULL, always try to import from source.
 *
 * @param[in]   name            Name of target.
 * @param[in]   hosts           Host list of target.
 * @param[in]   comment         Comment on target.
 * @param[in]   port_range      Port range of target.
 * @param[in]   ssh_lsc_credential  SSH LSC credential.
 * @param[in]   smb_lsc_credential  SMB LSC credential.
 * @param[in]   target_locator  Name of target_locator to import target(s)
 *                              from.
 * @param[in]   username        Username to authenticate with against source.
 * @param[in]   password        Password for user \p username.
 * @param[out]  target          Created target.
 *
 * @return 0 success, 1 target exists already, 2 error in host specification,
 *         3 too many hosts, -1 if import from target locator failed or response
 *         was empty.
 */
int
create_target (const char* name, const char* hosts, const char* comment,
               const char* port_range, lsc_credential_t ssh_lsc_credential,
               lsc_credential_t smb_lsc_credential, const char* target_locator,
               const char* username, const char* password, target_t* target)
{
  gchar *quoted_name = sql_nquote (name, strlen (name));
  gchar *quoted_hosts, *quoted_comment, *quoted_port_range;

  sql ("BEGIN IMMEDIATE;");

  assert (current_credentials.uuid);

  /** @todo Validate properly ("-100,200-1024,3000-4000,60000-"). */
  assert (port_range);

  /* Check whether a target with the same name exists already. */
  if (sql_int (0, 0,
               "SELECT COUNT(*) FROM targets"
               " WHERE name = '%s'"
               " AND ((owner IS NULL) OR (owner ="
               " (SELECT users.ROWID FROM users WHERE users.uuid = '%s')));",
               quoted_name,
               current_credentials.uuid))
    {
      g_free (quoted_name);
      sql ("ROLLBACK;");
      return 1;
    }

  /* Import targets from target locator. */
  if (target_locator != NULL)
    {
      int max;
      GSList* hosts_list = resource_request_resource (target_locator,
                                                      RESOURCE_TYPE_TARGET,
                                                      username ? username : "",
                                                      password ? password : "");

      if (hosts_list == NULL)
        {
          g_free (quoted_name);
          sql ("ROLLBACK;");
          return -1;
        }

      gchar* import_hosts = openvas_string_flatten_string_list (hosts_list,
                                                                ", ");

      openvas_string_list_free (hosts_list);
      max = manage_max_hosts (import_hosts);
      if (max == -1)
        {
          g_free (import_hosts);
          g_free (quoted_name);
          sql ("ROLLBACK;");
          return 2;
        }
      if (max > MANAGE_MAX_HOSTS)
        {
          g_free (import_hosts);
          g_free (quoted_name);
          sql ("ROLLBACK;");
          return 3;
        }
      quoted_hosts = sql_nquote (import_hosts, strlen (import_hosts));
      g_free (import_hosts);
    }
  else
    {
      int max;

      /* User provided hosts. */

      max = manage_max_hosts (hosts);
      if (max == -1)
        {
          g_free (quoted_name);
          sql ("ROLLBACK;");
          return 2;
        }
      if (max > MANAGE_MAX_HOSTS)
        {
          g_free (quoted_name);
          sql ("ROLLBACK;");
          return 3;
        }

      quoted_hosts = sql_nquote (hosts, strlen (hosts));
    }

  quoted_port_range = port_range
                       ? sql_quote (port_range)
                       : g_strdup ("default");

  if (comment)
    {
      quoted_comment = sql_nquote (comment, strlen (comment));
      sql ("INSERT INTO targets"
           " (uuid, name, owner, hosts, comment, lsc_credential,"
           "  smb_lsc_credential, port_range)"
           " VALUES (make_uuid (), '%s',"
           " (SELECT ROWID FROM users WHERE users.uuid = '%s'),"
           " '%s', '%s', %llu, %llu, '%s');",
           quoted_name, current_credentials.uuid, quoted_hosts, quoted_comment,
           ssh_lsc_credential, smb_lsc_credential, quoted_port_range);
      g_free (quoted_comment);
    }
  else
    sql ("INSERT INTO targets"
         " (uuid, name, owner, hosts, comment, lsc_credential,"
         "  smb_lsc_credential, port_range)"
         " VALUES (make_uuid (), '%s',"
         " (SELECT ROWID FROM users WHERE users.uuid = '%s'),"
         " '%s', '', %llu, %llu, '%s');",
         quoted_name, current_credentials.uuid, quoted_hosts,
         ssh_lsc_credential, smb_lsc_credential, quoted_port_range);

  if (target)
    *target = sqlite3_last_insert_rowid (task_db);

  g_free (quoted_name);
  g_free (quoted_hosts);
  g_free (quoted_port_range);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Delete a target.
 *
 * @param[in]  target  Target.
 *
 * @return 0 success, 1 fail because a task refers to the target, -1 error.
 */
int
delete_target (target_t target)
{
  sql ("BEGIN IMMEDIATE;");
  if (sql_int (0, 0,
               "SELECT count(*) FROM tasks WHERE target = %llu;",
               target))
    {
      sql ("ROLLBACK;");
      return 1;
    }
  sql ("DELETE FROM targets WHERE ROWID = %llu;", target);
  sql ("COMMIT;");
  return 0;
}

/**
 * @brief Initialise a target iterator.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  target      Target to limit iteration to.  0 for all.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for "ROWID".
 */
void
init_target_iterator (iterator_t* iterator, target_t target,
                      int ascending, const char* sort_field)
{
  assert (current_credentials.uuid);

  if (target)
    init_iterator (iterator,
                   "SELECT ROWID, uuid, name, hosts, comment, lsc_credential,"
                   " smb_lsc_credential, port_range"
                   " FROM targets"
                   " WHERE ROWID = %llu"
                   " AND ((owner IS NULL) OR (owner ="
                   " (SELECT ROWID FROM users WHERE users.uuid = '%s')))"
                   " ORDER BY %s %s;",
                   target,
                   current_credentials.uuid,
                   sort_field ? sort_field : "ROWID",
                   ascending ? "ASC" : "DESC");
  else
    init_iterator (iterator,
                   "SELECT ROWID, uuid, name, hosts, comment, lsc_credential,"
                   " smb_lsc_credential, port_range"
                   " FROM targets"
                   " WHERE ((owner IS NULL) OR (owner ="
                   " (SELECT ROWID FROM users WHERE users.uuid = '%s')))"
                   " ORDER BY %s %s;",
                   current_credentials.uuid,
                   sort_field ? sort_field : "ROWID",
                   ascending ? "ASC" : "DESC");
}

/**
 * @brief Get the target from a target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Target.
 */
target_t
target_iterator_target (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return (target_t) sqlite3_column_int64 (iterator->stmt, 0);
}

/**
 * @brief Get the UUID of the target from a target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return UUID of the target or NULL if iteration is complete.
 */
DEF_ACCESS (target_iterator_uuid, 1);

/**
 * @brief Get the name of the target from a target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name of the target or NULL if iteration is complete.
 */
DEF_ACCESS (target_iterator_name, 2);

/**
 * @brief Get the hosts of the target from a target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Hosts of the target or NULL if iteration is complete.
 */
DEF_ACCESS (target_iterator_hosts, 3);

/**
 * @brief Get the comment from a target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Comment.
 */
const char*
target_iterator_comment (iterator_t* iterator)
{
  const char *ret;
  if (iterator->done) return "";
  ret = (const char*) sqlite3_column_text (iterator->stmt, 4);
  return ret ? ret : "";
}

/**
 * @brief Get the SSH LSC credential from a target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return SSH LSC credential.
 */
int
target_iterator_ssh_credential (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (int) sqlite3_column_int (iterator->stmt, 5);
  return ret;
}

/**
 * @brief Get the SMB LSC credential from a target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return SMB LSC credential.
 */
int
target_iterator_smb_credential (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (int) sqlite3_column_int (iterator->stmt, 6);
  return ret;
}

/**
 * @brief Get the port range of the target from a target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Port range of the target or NULL if iteration is complete.
 */
DEF_ACCESS (target_iterator_port_range, 7);

/**
 * @brief Return the UUID of a target.
 *
 * @param[in]  target  Target.
 *
 * @return Newly allocated UUID if available, else NULL.
 */
char*
target_uuid (target_t target)
{
  return sql_string (0, 0,
                     "SELECT uuid FROM targets WHERE ROWID = %llu;",
                     target);
}

/**
 * @brief Return the name of a target.
 *
 * @param[in]  target  Target.
 *
 * @return Newly allocated name if available, else NULL.
 */
char*
target_name (target_t target)
{
  return sql_string (0, 0,
                     "SELECT name FROM targets WHERE ROWID = %llu;",
                     target);
}

/**
 * @brief Return the hosts associated with a target.
 *
 * @param[in]  target  Target.
 *
 * @return Newly allocated comma separated list of hosts if available,
 *         else NULL.
 */
char*
target_hosts (target_t target)
{
  return sql_string (0, 0,
                     "SELECT hosts FROM targets WHERE ROWID = %llu;",
                     target);
}

/**
 * @brief Return the port range of a target.
 *
 * @param[in]  target  Target.
 *
 * @return Newly allocated port range if available, else NULL.
 */
char*
target_port_range (target_t target)
{
  return sql_string (0, 0,
                     "SELECT port_range FROM targets WHERE ROWID = %llu;",
                     target);
}

/**
 * @brief Return the SSH credential associated with a target, if any.
 *
 * @param[in]  target  Target (corresponds to rowid).
 *
 * @return SSH credential if any, else 0.
 */
lsc_credential_t
target_ssh_lsc_credential (target_t target)
{
  lsc_credential_t lsc_credential;

  switch (sql_int64 (&lsc_credential, 0, 0,
                     "SELECT lsc_credential FROM targets"
                     " WHERE ROWID = %llu;",
                     target))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        return 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        /** @todo Move return to arg; return -1. */
        return 0;
        break;
    }
  return lsc_credential;
}

/**
 * @brief Return the SMB credential associated with a target, if any.
 *
 * @param[in]  target  Target (corresponds to rowid).
 *
 * @return SMB credential if any, else 0.
 */
lsc_credential_t
target_smb_lsc_credential (target_t target)
{
  lsc_credential_t lsc_credential;

  switch (sql_int64 (&lsc_credential, 0, 0,
                     "SELECT smb_lsc_credential FROM targets"
                     " WHERE ROWID = %llu;",
                     target))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        return 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        /** @todo Move return to arg; return -1. */
        return 0;
        break;
    }
  return lsc_credential;
}

/**
 * @brief Set the hosts associated with a target.
 *
 * @param[in]  target  Target.
 * @param[in]  hosts   New value for hosts.
 */
static void
set_target_hosts (target_t target, const char *hosts)
{
  gchar* quoted_hosts;

  assert (hosts);

  quoted_hosts = sql_quote (hosts);
  sql ("UPDATE targets SET hosts = '%s' WHERE ROWID = %llu;",
       quoted_hosts, target);
  g_free (quoted_hosts);
}

/**
 * @brief Return whether a target is referenced by a task
 *
 * @param[in]  target  Target.
 *
 * @return 1 if in use, else 0.
 */
int
target_in_use (target_t target)
{
  return sql_int (0, 0,
                  "SELECT count(*) FROM tasks WHERE target = %llu;",
                  target);
}

/**
 * @brief Initialise a target task iterator.
 *
 * Iterates over all tasks that use the target.
 *
 * @param[in]  iterator   Iterator.
 * @param[in]  target     Target.
 * @param[in]  ascending  Whether to sort ascending or descending.
 */
void
init_target_task_iterator (iterator_t* iterator, target_t target,
                           int ascending)
{
  assert (current_credentials.uuid);

  init_iterator (iterator,
                 "SELECT name, uuid FROM tasks"
                 " WHERE target = %llu"
                 " AND hidden = 0"
                 " AND ((owner IS NULL) OR (owner ="
                 " (SELECT ROWID FROM users WHERE users.uuid = '%s')))"
                 " ORDER BY name %s;",
                 target,
                 current_credentials.uuid,
                 ascending ? "ASC" : "DESC");
}

/**
 * @brief Get the name from a target_task iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The name of the host, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (target_task_iterator_name, 0);

/**
 * @brief Get the uuid from a target_task iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The uuid of the host, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (target_task_iterator_uuid, 1);


/* Configs. */

/**
 * @brief Find a config given a UUID.
 *
 * @param[in]   uuid    Config UUID.
 * @param[out]  config  Config return, 0 if succesfully failed to find config.
 *
 * @return FALSE on success (including if failed to find config), TRUE on error.
 */
gboolean
find_config (const char* uuid, config_t* config)
{
  gchar *quoted_uuid = sql_quote (uuid);
  if (user_owns_uuid ("config", quoted_uuid) == 0)
    {
      g_free (quoted_uuid);
      *config = 0;
      return FALSE;
    }
  switch (sql_int64 (config, 0, 0,
                     "SELECT ROWID FROM configs WHERE uuid = '%s';",
                     quoted_uuid))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *config = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        g_free (quoted_uuid);
        return TRUE;
        break;
    }
  g_free (quoted_uuid);
  return FALSE;
}

/**
 * @brief Insert preferences into a config.
 *
 * @param[in]  config       Config.
 * @param[in]  preferences  Preferences.
 *
 * @return 0 success, -1 error, -4 input error.
 */
static int
config_insert_preferences (config_t config,
                           const array_t* preferences /* preference_t. */)
{
  int index = 0;
  const preference_t *preference;
  if (preferences == NULL) return -4;
  while ((preference = (preference_t*) g_ptr_array_index (preferences, index++)))
    /* Simply skip the preference if the value is NULL, for exports
     * where sensitive information is left out. */
    if (preference->value)
      {
        GString *value;
        int alt_index = 0;
        const gchar *alt;
        gchar *quoted_value;

        if (preference->name == NULL) return -4;
        if (preference->type)
          {
            gchar *quoted_type, *quoted_nvt_name, *quoted_preference_name;

            /* Presume NVT preference. */

            if (preference->nvt_name == NULL) return -4;

            value = g_string_new (preference->value);
            while ((alt = (gchar*) g_ptr_array_index (preference->alts, alt_index++)))
              g_string_append_printf (value, ";%s", alt);

            quoted_nvt_name = sql_quote (preference->nvt_name);
            quoted_preference_name = sql_quote (preference->name);
            quoted_type = sql_quote (preference->type);
            quoted_value = sql_quote (value->str);
            g_string_free (value, TRUE);
            /* LDAPsearch[entry]:Timeout value */
            sql ("INSERT into config_preferences (config, type, name, value)"
                 " VALUES (%llu, 'PLUGINS_PREFS', '%s[%s]:%s', '%s');",
                 config,
                 quoted_nvt_name,
                 quoted_type,
                 quoted_preference_name,
                 quoted_value);
            g_free (quoted_nvt_name);
            g_free (quoted_preference_name);
            g_free (quoted_type);
            g_free (quoted_value);
          }
        else
          {
            gchar *quoted_name;

            /* Presume scanner preference. */

            quoted_name = sql_quote (preference->name);
            quoted_value = sql_quote (preference->value);
            sql ("INSERT into config_preferences (config, type, name, value)"
                 " VALUES (%llu, 'SERVER_PREFS', '%s', '%s');",
                 config,
                 quoted_name,
                 quoted_value);
            g_free (quoted_name);
            g_free (quoted_value);
          }
      }
  return 0;
}

/**
 * @brief Create a config.
 *
 * If a config with the same name exists already then add a unique integer
 * suffix onto the name.
 *
 * @param[in]   proposed_name  Proposed name of config.
 * @param[in]   comment        Comment on config.
 * @param[in]   selectors      NVT selectors.
 * @param[in]   preferences    Preferences.
 * @param[out]  config         On success the config.
 * @param[out]  name           On success the name of the config.
 *
 * @return 0 success, 1 config exists already, -1 error, -2 name empty,
 *         -3 input error in selectors, -4 input error in preferences.
 */
int
create_config (const char* proposed_name, const char* comment,
               const array_t* selectors /* nvt_selector_t. */,
               const array_t* preferences /* preference_t. */,
               config_t *config, char **name)
{
  int ret;
  gchar *quoted_comment, *candidate_name, *quoted_candidate_name;
  char *selector_uuid;
  unsigned int num = 1;

  assert (current_credentials.uuid);

  if (proposed_name == NULL || strlen (proposed_name) == 0) return -2;

  selector_uuid = openvas_uuid_make ();
  if (selector_uuid == NULL)
    return -1;

  candidate_name = g_strdup (proposed_name);
  quoted_candidate_name = sql_quote (candidate_name);

  sql ("BEGIN IMMEDIATE;");

  while (1)
    {
      if (sql_int (0, 0,
                   "SELECT COUNT(*) FROM configs WHERE name = '%s'"
                   " AND ((owner IS NULL) OR (owner ="
                   " (SELECT users.ROWID FROM users WHERE users.uuid = '%s')));",
                   quoted_candidate_name,
                   current_credentials.uuid)
          == 0)
        break;
      g_free (candidate_name);
      g_free (quoted_candidate_name);
      candidate_name = g_strdup_printf ("%s %u", proposed_name, ++num);
      quoted_candidate_name = sql_quote (candidate_name);
    }

  if (comment)
    {
      quoted_comment = sql_nquote (comment, strlen (comment));
      sql ("INSERT INTO configs (uuid, name, owner, nvt_selector, comment)"
           " VALUES (make_uuid (), '%s',"
           " (SELECT ROWID FROM users WHERE users.uuid = '%s'),"
           " '%s', '%s');",
           quoted_candidate_name,
           current_credentials.uuid,
           selector_uuid,
           quoted_comment);
      g_free (quoted_comment);
    }
  else
    sql ("INSERT INTO configs (uuid, name, owner, nvt_selector, comment)"
         " VALUES (make_uuid (), '%s',"
         " (SELECT ROWID FROM users WHERE users.uuid = '%s'),"
         " '%s', '');",
         quoted_candidate_name,
         current_credentials.uuid,
         selector_uuid);
  g_free (quoted_candidate_name);

  /* Insert the selectors into the nvt_selectors table. */

  *config = sqlite3_last_insert_rowid (task_db);
  if ((ret = insert_nvt_selectors (selector_uuid, selectors)))
    {
      sql ("ROLLBACK;");
      free (selector_uuid);
      return ret;
    }
  free (selector_uuid);

  /* Insert the preferences into the config_preferences table. */

  if ((ret = config_insert_preferences (*config, preferences)))
    {
      sql ("ROLLBACK;");
      return ret;
    }

  /* Update family and NVT count caches. */

  update_config_caches (*config);

  sql ("COMMIT;");
  *name = candidate_name;
  return 0;
}

/**
 * @brief Return the UUID of a config.
 *
 * @param[in]   config  Config.
 * @param[out]  id      Pointer to a newly allocated string.
 *
 * @return 0.
 */
int
config_uuid (config_t config, char ** id)
{
  *id = sql_string (0, 0,
                    "SELECT uuid FROM configs WHERE ROWID = %llu;",
                    config);
  return 0;
}

/**
 * @brief Get the value of a config preference.
 *
 * @param[in]  config      Config.
 * @param[in]  type        Preference category, NULL for general preferences.
 * @param[in]  preference  Name of the preference.
 *
 * @return If there is such a preference, the value of the preference as a
 *         newly allocated string, else NULL.
 */
static char *
config_preference (config_t config, const char *type, const char *preference)
{
  /** @todo Quote type and preference. */
  if (type)
    return sql_string (0, 0,
                       "SELECT value FROM config_preferences"
                       " WHERE ROWID = %llu AND  type = '%s' AND name = '%s';",
                       config, type, preference);
  else
    return sql_string (0, 0,
                       "SELECT value FROM config_preferences"
                       " WHERE ROWID = %llu AND type is NULL AND name = '%s';",
                       config, preference);
}

/**
 * @brief Get the timeout value for an NVT in a config.
 *
 * @param[in]  config  Config.
 * @param[in]  oid     ID of NVT.
 *
 * @return Newly allocated timeout if set for the NVT, else NULL.
 */
char *
config_nvt_timeout (config_t config, const char *oid)
{
  return sql_string (0, 0,
                     "SELECT value FROM config_preferences"
                     " WHERE config = %llu"
                     " AND type = 'SERVER_PREFS'"
                     " AND name = 'timeout.%s';",
                     config,
                     oid);
}

/**
 * @brief Exclude or include an array of NVTs in a config.
 *
 * @param[in]  nvt_selector  NVT selector name.
 * @param[in]  array         Array of OIDs of NVTs.
 * @param[in]  array_size    Size of \p array.
 * @param[in]  exclude       If true exclude, else include.
 * @param[in]  families      Families table, to lookup NVT family, or NULL.
 */
static void
clude (const char *nvt_selector, GArray *array, int array_size, int exclude,
       GHashTable *families)
{
  gint index;
  const char* tail;
  int ret;
  sqlite3_stmt* stmt;
  gchar* formatted;

  if (families)
    formatted = g_strdup_printf ("INSERT INTO nvt_selectors"
                                 " (name, exclude, type, family_or_nvt, family)"
                                 " VALUES ('%s', %i, 2, $value, $family);",
                                 nvt_selector,
                                 exclude);
  else
    formatted = g_strdup_printf ("INSERT INTO nvt_selectors"
                                 " (name, exclude, type, family_or_nvt, family)"
                                 " VALUES ('%s', %i, 2, $value, NULL);",
                                 nvt_selector,
                                 exclude);

  tracef ("   sql: %s\n", formatted);

  /* Prepare statement. */

  while (1)
    {
      ret = sqlite3_prepare (task_db, (char*) formatted, -1, &stmt, &tail);
      if (ret == SQLITE_BUSY) continue;
      g_free (formatted);
      if (ret == SQLITE_OK)
        {
          if (stmt == NULL)
            {
              g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              abort ();
            }
          break;
        }
      g_warning ("%s: sqlite3_prepare failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      /** @todo ROLLBACK if in transaction. */
      abort ();
    }

  for (index = 0; index < array_size; index++)
    {
      const char *id;
      id = g_array_index (array, char*, index);

      /* Bind the family name to the "$family" in the SQL statement. */

      if (families)
        {
          char *family = NULL;
          nvti_t *nvti = nvtis_lookup (nvti_cache, id);

          if (nvti)
            {
              family = nvti_family (nvti);

              if (family)
                g_hash_table_insert (families, family, (gpointer) 1);
              else
                {
                  g_warning ("%s: skipping NVT '%s' from import of config '%s'"
                             " because the NVT is missing a family in the"
                             " cache",
                             __FUNCTION__,
                             id,
                             nvt_selector);
                  continue;
                }
            }
          else
            {
              g_warning ("%s: skipping NVT '%s' from import of config '%s'"
                         " because the NVT is missing from the cache",
                         __FUNCTION__,
                         id,
                         nvt_selector);
              continue;
            }

          while (1)
            {
              assert (family);
              ret = sqlite3_bind_text (stmt, 2, family, -1,
                                       SQLITE_TRANSIENT);
              if (ret == SQLITE_BUSY) continue;
              if (ret == SQLITE_OK) break;
              g_warning ("%s: sqlite3_prepare failed: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              abort ();
            }
        }

      /* Bind the ID to the "$value" in the SQL statement. */

      while (1)
        {
          ret = sqlite3_bind_text (stmt, 1, id, -1, SQLITE_TRANSIENT);
          if (ret == SQLITE_BUSY) continue;
          if (ret == SQLITE_OK) break;
          g_warning ("%s: sqlite3_prepare failed: %s\n",
                     __FUNCTION__,
                     sqlite3_errmsg (task_db));
          abort ();
        }

      /* Run the statement. */

      while (1)
        {
          ret = sqlite3_step (stmt);
          if (ret == SQLITE_BUSY) continue;
          if (ret == SQLITE_DONE) break;
          if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
            {
              if (ret == SQLITE_ERROR) ret = sqlite3_reset (stmt);
              g_warning ("%s: sqlite3_step failed: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              abort ();
            }
        }

      /* Reset the statement. */

      while (1)
        {
          ret = sqlite3_reset (stmt);
          if (ret == SQLITE_BUSY) continue;
          if (ret == SQLITE_DONE || ret == SQLITE_OK) break;
          if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
            {
              g_warning ("%s: sqlite3_reset failed: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              abort ();
            }
        }
    }

  sqlite3_finalize (stmt);
}

/**
 * @brief Copy the preferences and nvt selector from an RC file to a config.
 *
 * @param[in]  config             Config to copy into.
 * @param[in]  config_name        Name of config to copy into, SQL quoted.
 * @param[in]  nvt_selector_name  Name of NVT selector associated with config,
 *                                SQL quoted.
 * @param[in]  rc                 Text of RC file.
 *
 * @return 0 success, -1 error.
 */
static int
insert_rc_into_config (config_t config, const char *config_name,
                       const char *nvt_selector_name, char *rc)
{
  GArray *yes = g_array_sized_new (FALSE, FALSE, sizeof (rc), 20000);
  GArray *no = g_array_sized_new (FALSE, FALSE, sizeof (rc), 20000);
  int yes_size = 0, no_size = 0;
  char* seek;
  GHashTable *families;

  if (rc == NULL)
    {
      tracef ("   rc NULL\n");
      return -1;
    }

  if (config_name == NULL)
    {
      tracef ("   config_name NULL\n");
      return -1;
    }

  families = g_hash_table_new_full (g_str_hash,
                                    g_str_equal,
                                    NULL,
                                    NULL);

  while (1)
    {
      char* eq;
      seek = strchr (rc, '\n');
      eq = seek
           ? memchr (rc, '=', seek - rc)
           : strchr (rc, '=');
      if (eq)
        {
          char* rc_end = eq;
          rc_end--;
          while (*rc_end == ' ') rc_end--;
          rc_end++;
          while (*rc == ' ') rc++;
          if (rc < rc_end)
            {
              gchar *name, *value;
              name = sql_nquote (rc, rc_end - rc);
              value = sql_nquote (eq + 2, /* Daring. */
                                  (seek ? seek - (eq + 2) : strlen (eq + 2)));
              sql ("INSERT OR REPLACE INTO config_preferences"
                   " (config, type, name, value)"
                   " VALUES (%llu, NULL, '%s', '%s');",
                   config, name, value);
              g_free (name);
              g_free (value);
            }
        }
      else if (((seek ? seek - rc >= 7 + strlen ("PLUGIN_SET") : 0)
                && (strncmp (rc, "begin(", 6) == 0)
                && (strncmp (rc + 6, "PLUGIN_SET", strlen ("PLUGIN_SET")) == 0)
                && (rc[6 + strlen ("PLUGIN_SET")] == ')'))
               || ((seek ? seek - rc >= 7 + strlen ("SCANNER_SET") : 0)
                   && (strncmp (rc, "begin(", 6) == 0)
                   && (strncmp (rc + 6, "SCANNER_SET", strlen ("SCANNER_SET"))
                       == 0)
                   && (rc[6 + strlen ("SCANNER_SET")] == ')')))
        {
          /* Create an NVT selector from the plugin list. */

          rc = seek + 1;
          while ((seek = strchr (rc, '\n')))
            {
              char* eq2;

              if ((seek ? seek - rc > 5 : 1)
                  && strncmp (rc, "end(", 4) == 0)
                {
                  break;
                }

              eq2 = memchr (rc, '=', seek - rc);
              if (eq2)
                {
                  char* rc_end = eq2;
                  rc_end--;
                  while (*rc_end == ' ') rc_end--;
                  rc_end++;
                  while (*rc == ' ') rc++;
                  if (rc < rc_end)
                    {
                      int value_len = (seek ? seek - (eq2 + 2)
                                            : strlen (eq2 + 2));
                      *rc_end = '\0';

                      if ((value_len == 3)
                          && strncasecmp (eq2 + 2, "yes", 3) == 0)
                        {
                          yes_size++;
                          g_array_append_val (yes, rc);
                        }
                      else
                        {
                          no_size++;
                          g_array_append_val (no, rc);
                        }
                    }
                }

              rc = seek + 1;
            }
        }
      else if ((seek ? seek - rc > 7 : 0)
               && (strncmp (rc, "begin(", 6) == 0))
        {
          gchar *section_name;

          section_name = sql_nquote (rc + 6, seek - (rc + 6) - 1);

          /* Insert the section. */

          rc = seek + 1;
          while ((seek = strchr (rc, '\n')))
            {
              char* eq2;

              if ((seek ? seek - rc > 5 : 1)
                  && strncmp (rc, "end(", 4) == 0)
                {
                  break;
                }

              eq2 = memchr (rc, '=', seek - rc);
              if (eq2)
                {
                  char* rc_end = eq2;
                  rc_end--;
                  while (*rc_end == ' ') rc_end--;
                  rc_end++;
                  while (*rc == ' ') rc++;
                  if (rc < rc_end)
                    {
                      gchar *name, *value;
                      name = sql_nquote (rc, rc_end - rc);
                      value = sql_nquote (eq2 + 2, /* Daring. */
                                          seek - (eq2 + 2));
                      sql ("INSERT OR REPLACE INTO config_preferences"
                           " (config, type, name, value)"
                           " VALUES (%llu, '%s', '%s', '%s');",
                           config, section_name, name, value);
                      g_free (name);
                      g_free (value);
                    }
                }

              rc = seek + 1;
            }

          g_free (section_name);
        }
      if (seek == NULL) break;
      rc = seek + 1;
    }

  {
    char *auto_enable;
    auto_enable = config_preference (config, NULL, "auto_enable_new_plugins");
    if (auto_enable
        && strcmp (auto_enable, "no")
        && strcmp (auto_enable, "0"))
      {
        free (auto_enable);

        /* Include the all selector. */

        sql ("INSERT INTO nvt_selectors"
             " (name, exclude, type, family_or_nvt)"
             " VALUES ('%s', 0, 0, 0);",
             nvt_selector_name);

        /* Explicitly exclude any nos. */

        clude (nvt_selector_name, no, no_size, 1, NULL);

        /* Cache the counts and growth types. */

        sql ("UPDATE configs"
             " SET families_growing = 1, nvts_growing = 1,"
             " family_count = %i, nvt_count = %i"
             " WHERE name = '%s';",
             nvt_selector_family_count (nvt_selector_name, 1),
             nvt_selector_nvt_count (nvt_selector_name, NULL, 1),
             config_name);
      }
    else
      {
        /* Explictly include the yeses and exclude the nos.  Keep the nos
         * because the config may change to auto enable new plugins. */
        /** @todo The other selector manipulation functions may lose the nos. */

        clude (nvt_selector_name, yes, yes_size, 0, families);
        clude (nvt_selector_name, no, no_size, 1, NULL);

        /* Cache the family and NVT count and selector types. */

        sql ("UPDATE configs SET"
             " family_count = %i,"
             " nvt_count = %i, families_growing = 0, nvts_growing = 0"
             " WHERE name = '%s';",
             g_hash_table_size (families),
             yes_size,
             config_name);
        g_hash_table_destroy (families);
      }
  }

  return 0;
}

/**
 * @brief Create a config from an RC file.
 *
 * @param[in]   name     Name of config and NVT selector.
 * @param[in]   comment  Comment on config.
 * @param[in]   rc       RC file text.
 * @param[out]  config   Created config.
 *
 * @return 0 success, 1 config exists already, -1 error.
 */
int
create_config_rc (const char* name, const char* comment, char* rc,
                  config_t *config)
{
  gchar *quoted_name = sql_nquote (name, strlen (name));
  gchar *quoted_comment;
  char *selector_uuid;
  config_t new_config;

  assert (current_credentials.uuid);

  sql ("BEGIN IMMEDIATE;");

  if (sql_int (0, 0,
               "SELECT COUNT(*) FROM configs WHERE name = '%s'"
               " AND ((owner IS NULL) OR (owner ="
               " (SELECT users.ROWID FROM users WHERE users.uuid = '%s')));",
               quoted_name,
               current_credentials.uuid))
    {
      tracef ("   config \"%s\" already exists\n", name);
      sql ("ROLLBACK;");
      g_free (quoted_name);
      return 1;
    }

  selector_uuid = openvas_uuid_make ();
  if (selector_uuid == NULL)
    {
      tracef ("   failed to create UUID \n");
      sql ("ROLLBACK;");
      g_free (quoted_name);
      return -1;
    }

  if (sql_int (0, 0,
               "SELECT COUNT(*) FROM nvt_selectors WHERE name = '%s' LIMIT 1;",
               selector_uuid))
    {
      tracef ("   NVT selector \"%s\" already exists\n", selector_uuid);
      sql ("ROLLBACK;");
      free (selector_uuid);
      g_free (quoted_name);
      return -1;
    }

  if (comment)
    {
      quoted_comment = sql_nquote (comment, strlen (comment));
      sql ("INSERT INTO configs (uuid, name, owner, nvt_selector, comment)"
           " VALUES (make_uuid (), '%s',"
           " (SELECT ROWID FROM users WHERE users.uuid = '%s'),"
           " '%s', '%s');",
           quoted_name,
           current_credentials.uuid,
           selector_uuid,
           quoted_comment);
      g_free (quoted_comment);
    }
  else
    sql ("INSERT INTO configs (uuid, name, owner, nvt_selector, comment)"
         " VALUES (make_uuid (), '%s',"
         " (SELECT ROWID FROM users WHERE users.uuid = '%s'),"
         " '%s', '');",
         quoted_name, current_credentials.uuid, selector_uuid);

  /* Insert the RC into the config_preferences table. */

  new_config = sqlite3_last_insert_rowid (task_db);
  if (insert_rc_into_config (new_config, quoted_name, selector_uuid, rc))
    {
      sql ("ROLLBACK;");
      free (selector_uuid);
      g_free (quoted_name);
      return -1;
    }

  sql ("COMMIT;");
  free (selector_uuid);
  g_free (quoted_name);
  if (config)
    *config = new_config;
  return 0;
}

/**
 * @brief Create a config from an existing config.
 *
 * @param[in]  name        Name of new config and NVT selector.
 * @param[in]  comment     Comment on new config.
 * @param[in]  config      Existing config.
 * @param[out] new_config  New config.
 *
 * @return 0 success, 1 config exists already, 2 failed to find existing
 *         config, -1 error.
 */
int
copy_config (const char* name, const char* comment, config_t config,
             config_t* new_config)
{
  char *config_selector, *uuid;
  config_t id;
  gchar *quoted_name = sql_quote (name);
  gchar *quoted_comment, *quoted_config_selector;

  assert (current_credentials.uuid);

  config_selector = config_nvt_selector (config);
  if (config_selector == NULL)
    return -1;
  quoted_config_selector = sql_quote (config_selector);
  free (config_selector);

  sql ("BEGIN IMMEDIATE;");

  if (sql_int (0, 0,
               "SELECT COUNT(*) FROM configs WHERE name = '%s'"
               " AND ((owner IS NULL) OR (owner ="
               " (SELECT users.ROWID FROM users WHERE users.uuid = '%s')));",
               quoted_name,
               current_credentials.uuid))
    {
      tracef ("   config \"%s\" already exists\n", name);
      sql ("ROLLBACK;");
      g_free (quoted_name);
      g_free (quoted_config_selector);
      return 1;
    }

  if (sql_int (0, 0,
               "SELECT COUNT(*) FROM configs"
               " WHERE ROWID = %llu"
               " AND ((owner IS NULL) OR (owner ="
               " (SELECT ROWID FROM users WHERE users.uuid = '%s')))",
               config,
               current_credentials.uuid)
      == 0)
    {
      sql ("ROLLBACK;");
      g_free (quoted_name);
      g_free (quoted_config_selector);
      return 2;
    }

  uuid = openvas_uuid_make ();
  if (uuid == NULL)
    {
      tracef ("   failed to create UUID \n");
      sql ("ROLLBACK;");
      g_free (quoted_name);
      g_free (quoted_config_selector);
      return -1;
    }

  if (sql_int (0, 0,
               "SELECT COUNT(*) FROM nvt_selectors WHERE name = '%s' LIMIT 1;",
               uuid))
    {
      tracef ("   NVT selector \"%s\" already exists\n", uuid);
      sql ("ROLLBACK;");
      free (uuid);
      g_free (quoted_name);
      g_free (quoted_config_selector);
      return -1;
    }

  /* Copy the existing config. */

  if (comment)
    {
      quoted_comment = sql_nquote (comment, strlen (comment));
      sql ("INSERT INTO configs"
           " (uuid, name, owner, nvt_selector, comment, family_count,"
           "  nvt_count, families_growing, nvts_growing)"
           " SELECT make_uuid (), '%s',"
           " (SELECT ROWID FROM users where users.uuid = '%s'),"
           " '%s', '%s', family_count, nvt_count,"
           " families_growing, nvts_growing"
           " FROM configs WHERE ROWID = %llu;",
           quoted_name,
           current_credentials.uuid,
           uuid,
           quoted_comment,
           config);
      g_free (quoted_comment);
    }
  else
    sql ("INSERT INTO configs"
         " (uuid, name, owner, nvt_selector, comment, family_count, nvt_count,"
         "  families_growing, nvts_growing)"
         " SELECT make_uuid (), '%s',"
         " (SELECT ROWID FROM users where users.uuid = '%s'),"
         " '%s', '', family_count, nvt_count,"
         " families_growing, nvts_growing"
         " FROM configs WHERE ROWID = %llu",
         quoted_name,
         current_credentials.uuid,
         uuid,
         config);

  id = sqlite3_last_insert_rowid (task_db);

  sql ("INSERT INTO config_preferences (config, type, name, value)"
       " SELECT %llu, type, name, value FROM config_preferences"
       " WHERE config = %llu;",
       id,
       config);

  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " SELECT '%s', exclude, type, family_or_nvt, family FROM nvt_selectors"
       " WHERE name = '%s';",
       uuid,
       quoted_config_selector);

  sql ("COMMIT;");
  free (uuid);
  g_free (quoted_name);
  g_free (quoted_config_selector);
  if (new_config) *new_config = id;
  return 0;
}

/**
 * @brief Delete a config.
 *
 * @param[in]  config  Config.
 *
 * @return 0 success, 1 fail because a task refers to the config, -1 error.
 */
int
delete_config (config_t config)
{
  if (config == CONFIG_ID_FULL_AND_FAST
      || config == CONFIG_ID_FULL_AND_FAST_ULTIMATE
      || config == CONFIG_ID_FULL_AND_VERY_DEEP
      || config == CONFIG_ID_FULL_AND_VERY_DEEP_ULTIMATE
      || config == sql_int (0, 0,
                            "SELECT ROWID FROM configs WHERE name = 'empty';"))
    return 1;

  sql ("BEGIN IMMEDIATE;");
  if (sql_int (0, 0,
               "SELECT count(*) FROM tasks WHERE config = %llu;",
               config))
    {
      sql ("ROLLBACK;");
      return 1;
    }
  sql ("DELETE FROM nvt_selectors WHERE name ="
       " (SELECT nvt_selector FROM configs WHERE ROWID = %llu);",
       config);
  sql ("DELETE FROM config_preferences WHERE config = %llu;",
       config);
  sql ("DELETE FROM configs WHERE ROWID = %llu;",
       config);
  sql ("COMMIT;");
  return 0;
}

/**
 * @brief Database fields used in config iterators.
 */
#define CONFIG_ITERATOR_FIELDS "ROWID, uuid, name, nvt_selector, comment, families_growing, nvts_growing"

/**
 * @brief Initialise a config iterator.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  config      Config.  0 for all.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for "ROWID".
 */
void
init_config_iterator (iterator_t* iterator, config_t config,
                      int ascending, const char* sort_field)

{
  gchar *sql;

  assert (current_credentials.uuid);

  if (config)
    sql = g_strdup_printf ("SELECT " CONFIG_ITERATOR_FIELDS
                           " FROM configs"
                           " WHERE ROWID = %llu"
                           " AND ((owner IS NULL) OR (owner ="
                           " (SELECT ROWID FROM users"
                           "  WHERE users.uuid = '%s')))"
                           " ORDER BY %s %s;",
                           config,
                           current_credentials.uuid,
                           sort_field ? sort_field : "ROWID",
                           ascending ? "ASC" : "DESC");
  else
    sql = g_strdup_printf ("SELECT " CONFIG_ITERATOR_FIELDS
                           " FROM configs"
                           " WHERE ((owner IS NULL) OR (owner ="
                           " (SELECT ROWID FROM users"
                           "  WHERE users.uuid = '%s')))"
                           " ORDER BY %s %s;",
                           current_credentials.uuid,
                           sort_field ? sort_field : "ROWID",
                           ascending ? "ASC" : "DESC");
  init_iterator (iterator, sql);
  g_free (sql);
}

/**
 * @brief Get the config from a config iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Config.
 */
config_t
config_iterator_config (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return (config_t) sqlite3_column_int64 (iterator->stmt, 0);
}

/**
 * @brief Get the uuid from a config iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The uuid of the config, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (config_iterator_uuid, 1);

/**
 * @brief Get the name from a config iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The name of the config, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (config_iterator_name, 2);

/**
 * @brief Get the nvt_selector from a config iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The nvt_selector of the config, or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (config_iterator_nvt_selector, 3);

/**
 * @brief Get the comment from a config iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Comment.
 */
const char*
config_iterator_comment (iterator_t* iterator)
{
  const char *ret;
  if (iterator->done) return "";
  ret = (const char*) sqlite3_column_text (iterator->stmt, 4);
  return ret ? ret : "";
}

/**
 * @brief Get the families growing state from a config iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Families growing flag.
 */
int
config_iterator_families_growing (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (int) sqlite3_column_int (iterator->stmt, 5);
  return ret;
}

/**
 * @brief Get the NVTs growing state from a config iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return NVTs growing flag.
 */
int
config_iterator_nvts_growing (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (int) sqlite3_column_int (iterator->stmt, 6);
  return ret;
}

/**
 * @brief Return whether a config is referenced by a task.
 *
 * The predefined configs are always in use.
 *
 * @param[in]  config  Config.
 *
 * @return 1 if in use, else 0.
 */
int
config_in_use (config_t config)
{
  if (config == CONFIG_ID_FULL_AND_FAST
      || config == CONFIG_ID_FULL_AND_FAST_ULTIMATE
      || config == CONFIG_ID_FULL_AND_VERY_DEEP
      || config == CONFIG_ID_FULL_AND_VERY_DEEP_ULTIMATE
      || config == sql_int (0, 0,
                            "SELECT ROWID FROM configs WHERE name = 'empty';"))
    return 1;

  return sql_int (0, 0,
                  "SELECT count(*) FROM tasks WHERE config = %llu;",
                  config);
}

/**
 * @brief Initialise a preference iterator.
 *
 * Assume the caller has permission to access the config.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  config    Config.
 * @param[in]  section   Preference section, NULL for general preferences.
 */
static void
init_preference_iterator (iterator_t* iterator,
                          config_t config,
                          const char* section)
{
  gchar* sql;
  if (section)
    {
      gchar *quoted_section = sql_nquote (section, strlen (section));
      sql = g_strdup_printf ("SELECT name, value FROM config_preferences"
                             " WHERE config = %llu"
                             " AND type = '%s';",
                             config, quoted_section);
      g_free (quoted_section);
    }
  else
    sql = g_strdup_printf ("SELECT name, value FROM config_preferences"
                           " WHERE config = %llu"
                           " AND type is NULL;",
                           config);
  init_iterator (iterator, sql);
  g_free (sql);
}

/**
 * @brief Get the name from a preference iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The name of the preference iterator, or NULL if iteration is
 *         complete.  Freed by cleanup_iterator.
 */
static DEF_ACCESS (preference_iterator_name, 0);

/**
 * @brief Get the value from a preference iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The value of the preference iterator, or NULL if iteration is
 *         complete.  Freed by cleanup_iterator.
 */
static DEF_ACCESS (preference_iterator_value, 1);

/**
 * @brief Initialise an "OTP" preference iterator.
 *
 * Assume the caller has permission to access the config.
 *
 * This version substitutes the scanner preference when the NVT preference
 * is missing.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  config    Config containing preferences.
 * @param[in]  section   Preference section, NULL for general preferences.
 */
void
init_otp_pref_iterator (iterator_t* iterator,
                        config_t config,
                        const char* section)
{
  gchar *quoted_section;

  assert (config);
  assert (section);
  assert ((strcmp (section, "PLUGINS_PREFS") == 0)
          || (strcmp (section, "SERVER_PREFS") == 0));

  quoted_section = sql_quote (section);

  init_iterator (iterator,
                 "SELECT config_preferences.name, config_preferences.value"
                 " FROM config_preferences, nvt_preferences"
                 " WHERE config_preferences.config = %llu"
                 " AND config_preferences.type = '%s'"
                 " AND config_preferences.name = nvt_preferences.name"
                 " UNION"
                 " SELECT nvt_preferences.name, nvt_preferences.value"
                 " FROM nvt_preferences"
                 " WHERE nvt_preferences.name %s"
                 " AND (SELECT COUNT(*) FROM config_preferences"
                 "      WHERE config = %llu"
                 "      AND config_preferences.name = nvt_preferences.name) = 0;",
                 config,
                 quoted_section,
                 strcmp (quoted_section, "SERVER_PREFS") == 0
                  ? "NOT LIKE '%[%]%'" : "LIKE '%[%]%'",
                 config);
  g_free (quoted_section);
}

/**
 * @brief Get the NAME from a host iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return NAME, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (otp_pref_iterator_name, 0);

/**
 * @brief Get the value from a otp_pref iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (otp_pref_iterator_value, 1);

/**
 * @brief Return the NVT selector associated with a config.
 *
 * @param[in]  config  Config.
 *
 * @return Name of NVT selector if config exists and NVT selector is set, else
 *         NULL.
 */
char*
config_nvt_selector (config_t config)
{
  return sql_string (0, 0,
                     "SELECT nvt_selector FROM configs WHERE ROWID = %llu;",
                     config);
}

/**
 * @brief Set a preference of a config.
 *
 * @param[in]  config    Config.
 * @param[in]  nvt       UUID of NVT.  NULL for scanner preference.
 * @param[in]  name      Preference name, including NVT name and preference
 *                       type.
 * @param[in]  value_64  Preference value in base64.  NULL for an NVT
 *                       preference removes the preference from the config.
 *
 * @return 0 success, 1 config in use, 2 empty radio value, -1 error.
 */
int
manage_set_config_preference (config_t config, const char* nvt, const char* name,
                              const char* value_64)
{
  gchar *quoted_name, *quoted_value, *value;
  int type_start = -1, type_end = -1, count;

  if (value_64 == NULL)
    {
      int end = -1;

      sql ("BEGIN IMMEDIATE;");

      if (sql_int (0, 0,
                   "SELECT count(*) FROM tasks WHERE config = %llu;",
                   config))
        {
          sql ("ROLLBACK;");
          return 1;
        }

      quoted_name = sql_quote (name);

      /* scanner[scanner]:Timeout */
      count = sscanf (name, "%*[^[][scanner]:%n", &end);
      if (count == 0 && end > 0)
        {
          /* A scanner preference.  Remove type decoration from name. */
          g_free (quoted_name);
          quoted_name = sql_quote (name + end);
        }

      sql ("DELETE FROM config_preferences"
           " WHERE config = %llu"
           " AND name = '%s';",
           config,
           quoted_name);

      sql ("COMMIT;");

      g_free (quoted_name);
      return 0;
    }

  sql ("BEGIN IMMEDIATE;");

  if (sql_int (0, 0,
               "SELECT count(*) FROM tasks WHERE config = %llu;",
               config))
    {
      sql ("ROLLBACK;");
      return 1;
    }

  quoted_name = sql_quote (name);

  if (strlen (value_64))
    {
      gsize value_len;
      value = (gchar*) g_base64_decode (value_64, &value_len);
    }
  else
    value = g_strdup ("");

  /* LDAPsearch[entry]:Timeout value */
  count = sscanf (name, "%*[^[][%n%*[^]]%n]:", &type_start, &type_end);
  if (count == 0 && type_start > 0 && type_end > 0)
    {
      if (strncmp (name + type_start, "radio", type_end - type_start) == 0)
        {
          char *old_value;
          gchar **split, **point;
          GString *string;

          if (strlen (value) == 0)
            {
              g_free (quoted_name);
              g_free (value);
              sql ("ROLLBACK;");
              return 2;
            }

          /* A radio.  Put the new value on the front of the list of options. */

          old_value = sql_string (0, 0,
                                  "SELECT value FROM config_preferences"
                                  " WHERE config = %llu"
                                  " AND type %s"
                                  " AND name = '%s'",
                                  config,
                                  nvt ? "= 'PLUGINS_PREFS'" : "is NULL",
                                  quoted_name);
          if (old_value == NULL)
            old_value = sql_string (0, 0,
                                    "SELECT value FROM nvt_preferences"
                                    " WHERE name = '%s'",
                                    quoted_name);
          if (old_value)
            {
              string = g_string_new (value);
              split = g_strsplit (old_value, ";", 0);
              free (old_value);
              point = split;
              while (*point)
                {
                  if (strlen (*point) == 0)
                    {
                      g_free (quoted_name);
                      g_strfreev (split);
                      g_free (value);
                      g_string_free (string, TRUE);
                      sql ("ROLLBACK;");
                      return -1;
                    }

                  if (strcmp (*point, value))
                    {
                      g_string_append_c (string, ';');
                      g_string_append (string, *point);
                    }
                  point++;
                }
              g_strfreev (split);
              g_free (value);
              value = g_string_free (string, FALSE);
            }
        }
      else if (strncmp (name + type_start, "scanner", type_end - type_start)
               == 0)
        {
          /* A scanner preference.  Remove type decoration from name. */

          g_free (quoted_name);
          quoted_name = sql_quote (name + type_end + 2);
        }
    }

  quoted_value = sql_quote ((gchar*) value);
  g_free (value);

  sql ("DELETE FROM config_preferences"
       " WHERE config = %llu"
       " AND type %s"
       " AND name = '%s'",
       config,
       nvt ? "= 'PLUGINS_PREFS'" : "= 'SERVER_PREFS'",
       quoted_name);
  sql ("INSERT INTO config_preferences"
       " (config, type, name, value)"
       " VALUES (%llu, %s, '%s', '%s');",
       config,
       nvt ? "'PLUGINS_PREFS'" : "'SERVER_PREFS'",
       quoted_name,
       quoted_value);
  sql ("COMMIT;");

  g_free (quoted_name);
  g_free (quoted_value);
  return 0;
}

/**
 * @brief Set the NVT's selected for a single family of a config.
 *
 * @param[in]  config         Config.
 * @param[in]  family         Family name.
 * @param[in]  selected_nvts  NVT's.
 *
 * @return 0 success, 1 config in use, -1 error.
 */
int
manage_set_config_nvts (config_t config, const char* family,
                        GPtrArray* selected_nvts)
{
  char *selector;
  gchar *quoted_family, *quoted_selector;
  int new_nvt_count = 0, old_nvt_count;

  sql ("BEGIN EXCLUSIVE;");

  if (sql_int (0, 0,
               "SELECT count(*) FROM tasks WHERE config = %llu;",
               config))
    {
      sql ("ROLLBACK;");
      return 1;
    }

  quoted_family = sql_quote (family);

  selector = config_nvt_selector (config);
  if (selector == NULL)
    /* The config should always have a selector. */
    return -1;

  quoted_selector = sql_quote (selector);

  /* If the family is growing, then exclude all no's, otherwise the family
   * is static, so include all yes's. */

  if (nvt_selector_family_growing (selector,
                                   family,
                                   config_families_growing (config)))
    {
      iterator_t nvts;

      old_nvt_count = nvt_selector_nvt_count (selector, family, 1);

      free (selector);

      /* Clear any NVT selectors for this family from the config. */

      sql ("DELETE FROM nvt_selectors"
           " WHERE name = '%s'"
           " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
           " AND family = '%s';",
           quoted_selector,
           quoted_family);

      /* Exclude all no's. */

      new_nvt_count = family_nvt_count (family);

      init_nvt_iterator (&nvts, (nvt_t) 0, config, family, 1, NULL);
      while (next (&nvts))
        {
          const char *oid = nvt_iterator_oid (&nvts);
          gchar *quoted_oid;

          if (member (selected_nvts, oid)) continue;

          quoted_oid = sql_quote (oid);
          sql ("INSERT INTO nvt_selectors"
               " (name, exclude, type, family_or_nvt, family)"
               " VALUES ('%s', 1, "
               G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
               ", '%s', '%s');",
               quoted_selector,
               quoted_oid,
               quoted_family);
          g_free (quoted_oid);

          new_nvt_count--;
        }
      cleanup_iterator (&nvts);
    }
  else
    {
      old_nvt_count = nvt_selector_nvt_count (selector, family, 0);

      free (selector);

      /* Clear any NVT selectors for this family from the config. */

      sql ("DELETE FROM nvt_selectors"
           " WHERE name = '%s'"
           " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
           " AND family = '%s';",
           quoted_selector,
           quoted_family);

      /* Include all yes's. */

      if (selected_nvts)
        {
          gchar *nvt;
          new_nvt_count = 0;

          while ((nvt = (gchar*) g_ptr_array_index (selected_nvts,
                                                    new_nvt_count)))
            {
              gchar *quoted_nvt = sql_quote (nvt);
              sql ("INSERT INTO nvt_selectors"
                   " (name, exclude, type, family_or_nvt, family)"
                   " VALUES ('%s', 0, "
                   G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
                   ", '%s', '%s');",
                   quoted_selector,
                   quoted_nvt,
                   quoted_family);
              g_free (quoted_nvt);
              new_nvt_count++;
            }
        }
    }

  /* Update the cached config info. */

  sql ("UPDATE configs SET family_count = family_count + %i,"
       " nvt_count = nvt_count - %i + %i"
       " WHERE ROWID = %llu;",
       old_nvt_count == 0
        ? (new_nvt_count == 0 ? 0 : 1)
        : (new_nvt_count == 0 ? -1 : 0),
       old_nvt_count,
       MAX (new_nvt_count, 0),
       config);

  sql ("COMMIT;");

  g_free (quoted_family);
  g_free (quoted_selector);
  return 0;
}

/**
 * @brief Switch between constraining and generating representation.
 *
 * It's up to the caller to start and end a transaction.
 *
 * @param[in]  config        Config name.
 * @param[in]  constraining  1 families currently growing, 0 families currently
 *                           static.
 *
 * @return 0 success, -1 error.
 */
static int
switch_representation (config_t config, int constraining)
{
  char* selector;
  gchar *quoted_selector;

  selector = config_nvt_selector (config);
  if (selector == NULL)
    return -1;
  quoted_selector = sql_quote (selector);

  if (constraining)
    {
      iterator_t families;

      /* Currently constraining the universe. */

      /* Remove the all selector. */

      nvt_selector_remove_selector (quoted_selector,
                                    NULL,
                                    NVT_SELECTOR_TYPE_ALL);

      /* Convert each family. */

      init_family_iterator (&families, 0, NULL, 1);
      while (next (&families))
        {
          const char *family = family_iterator_name (&families);
          if (family)
            {
              gchar *quoted_family = sql_quote (family);
              if (nvt_selector_family_growing (selector, family, 1))
                /* Add a family include. */
                nvt_selector_add (quoted_selector,
                                  quoted_family,
                                  NULL,
                                  0);
              else
                /* Remove the family exclude. */
                nvt_selector_remove_selector (quoted_selector,
                                              quoted_family,
                                              NVT_SELECTOR_TYPE_FAMILY);
              g_free (quoted_family);
            }
        }
      cleanup_iterator (&families);

      /* Update the cached config info. */

      sql ("UPDATE configs SET families_growing = 0 WHERE ROWID = %llu;",
           config);
    }
  else
    {
      iterator_t families;

      /* Currently generating from empty. */

      /* Add the all selector. */

      sql ("INSERT INTO nvt_selectors"
           " (name, exclude, type, family_or_nvt)"
           " VALUES ('%s', 0, 0, 0);",
           quoted_selector);

      /* Convert each family. */

      init_family_iterator (&families, 0, NULL, 1);
      while (next (&families))
        {
          const char *family = family_iterator_name (&families);
          if (family)
            {
              gchar *quoted_family = sql_quote (family);
              if (nvt_selector_family_growing (selector, family, 0))
                /* Remove the family include. */
                nvt_selector_remove_selector (quoted_selector,
                                              quoted_family,
                                              NVT_SELECTOR_TYPE_FAMILY);
              else
                /* Add a family exclude. */
                nvt_selector_add (quoted_selector,
                                  quoted_family,
                                  NULL,
                                  1);
              g_free (quoted_family);
            }
        }
      cleanup_iterator (&families);

      /* Update the cached config info. */

      sql ("UPDATE configs SET families_growing = 1 WHERE ROWID = %llu;",
           config);
    }

  free (selector);
  g_free (quoted_selector);
  return 0;
}

/**
 * @brief Initialise a config task iterator.
 *
 * Iterate over all tasks that use the config.
 *
 * @param[in]  iterator   Iterator.
 * @param[in]  config     Config.
 * @param[in]  ascending  Whether to sort ascending or descending.
 */
void
init_config_task_iterator (iterator_t* iterator, config_t config,
                           int ascending)
{
  init_iterator (iterator,
                 "SELECT name, uuid FROM tasks"
                 " WHERE config = %llu"
                 " AND hidden = 0"
                 " ORDER BY name %s;",
                 config,
                 ascending ? "ASC" : "DESC");
}

/**
 * @brief Get the name from a config_task iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (config_task_iterator_name, 0);

/**
 * @brief Get the UUID from a config_task iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return UUID, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (config_task_iterator_uuid, 1);


/* NVT's. */

/**
 * @brief Get the name of an NVT.
 *
 * @param[in]  nvt  NVT.
 *
 * @return Freshly allocated name of NVT if possible, else NULL.
 */
char *
manage_nvt_name (nvt_t nvt)
{
  return sql_string (0, 0, "SELECT name FROM nvts WHERE ROWID = %llu;", nvt);
}

/**
 * @brief Guess the OID of an NVT given a name.
 *
 * @param[in]  name  Name of NVT.
 *
 * @return OID of NVT if possible, else NULL.
 */
char *
nvt_oid (const char *name)
{
  gchar *quoted_name = sql_quote (name);
  char *ret = sql_string (0, 0,
                          "SELECT oid FROM nvts WHERE name = '%s' LIMIT 1;",
                          quoted_name);
  g_free (quoted_name);
  return ret;
}

/**
 * @brief Return number of plugins in the plugin cache.
 *
 * @return Number of plugins.
 */
int
nvts_size ()
{
  return sql_int (0, 0, "SELECT count(*) FROM nvts;");
}

/**
 * @brief Return md5sum of the plugins in the plugin cache.
 *
 * @return Number of plugins if the plugins are cached, else NULL.
 */
char*
nvts_md5sum ()
{
  return sql_string (0, 0,
                     "SELECT value FROM meta WHERE name = 'nvts_md5sum';");
}

/**
 * @brief Set the md5sum of the plugins in the plugin cache.
 *
 * @param[in]  md5sum  New md5sum.
 *
 * Also queue an update to the nvti cache.
 */
void
set_nvts_md5sum (const char *md5sum)
{
  gchar* quoted = sql_quote (md5sum);
  sql ("INSERT OR REPLACE INTO meta (name, value)"
       " VALUES ('nvts_md5sum', '%s');",
       quoted);
  g_free (quoted);

  sql ("UPDATE meta SET value = 1 WHERE name = 'update_nvti_cache';");
}

/**
 * @brief Find an NVT given an identifier.
 *
 * @param[in]   oid  An NVT identifier.
 * @param[out]  nvt  NVT return, 0 if succesfully failed to find task.
 *
 * @return FALSE on success (including if failed to find NVT), TRUE on error.
 */
gboolean
find_nvt (const char* oid, nvt_t* nvt)
{
  switch (sql_int64 (nvt, 0, 0,
                     "SELECT ROWID FROM nvts WHERE oid = '%s';",
                     oid))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *nvt = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        return TRUE;
        break;
    }

  return FALSE;
}

/**
 * @brief Get the family of an NVT.
 *
 * @param[in]  nvt  NVT.
 *
 * @return Family name if set, else NULL.
 */
char *
nvt_family (nvt_t nvt)
{
  return sql_string (0, 0,
                     "SELECT family FROM nvts WHERE ROWID = %llu LIMIT 1;",
                     nvt);
}

/**
 * @brief Make an nvt from an nvti.
 *
 * @param[in]  nvti    NVTI.
 * @param[in]  remove  Whether to remove the NVT from the cache first.
 *
 * @return An NVT.
 */
nvt_t
make_nvt_from_nvti (const nvti_t *nvti, int remove)
{
  /** @todo Freeing string literals. */
  gchar *quoted_version, *quoted_name, *quoted_summary, *quoted_description;
  gchar *quoted_copyright, *quoted_cve, *quoted_bid, *quoted_xref, *quoted_tag;
  gchar *quoted_cvss_base, *quoted_risk_factor, *quoted_sign_key_ids;
  gchar *quoted_family;

  quoted_version = sql_quote (nvti_version (nvti));
  quoted_name = sql_quote (nvti_name (nvti) ? nvti_name (nvti) : "");
  quoted_summary = sql_quote (nvti_summary (nvti) ? nvti_summary (nvti) : "");
  quoted_description = sql_quote (nvti_description (nvti)
                                  ? nvti_description (nvti)
                                  : "");
  quoted_copyright = sql_quote (nvti_copyright (nvti)
                                ? nvti_copyright (nvti)
                                : "");
  quoted_cve = sql_quote (nvti_cve (nvti) ? nvti_cve (nvti) : "");
  quoted_bid = sql_quote (nvti_bid (nvti) ? nvti_bid (nvti) : "");
  quoted_xref = sql_quote (nvti_xref (nvti) ? nvti_xref (nvti) : "");
  quoted_tag = sql_quote (nvti_tag (nvti) ? nvti_tag (nvti) : "");
  quoted_cvss_base = sql_quote (nvti_cvss_base (nvti)
                                 ? nvti_cvss_base (nvti)
                                 : "");
  quoted_risk_factor = sql_quote (nvti_risk_factor (nvti)
                                   ? nvti_risk_factor (nvti)
                                   : "");
  quoted_sign_key_ids = sql_quote (nvti_sign_key_ids (nvti)
                                   ? nvti_sign_key_ids (nvti)
                                   : "");
  quoted_family = sql_quote (nvti_family (nvti) ? nvti_family (nvti) : "");

  if (remove)
    {
      sql ("BEGIN EXCLUSIVE;");
      sql ("DELETE FROM nvts WHERE oid = '%s';", nvti_oid (nvti));
    }

  sql ("INSERT into nvts (oid, version, name, summary, description, copyright,"
       " cve, bid, xref, tag, sign_key_ids, category, family, cvss_base,"
       " risk_factor)"
       " VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s',"
       " '%s', %i, '%s', '%s', '%s');",
       nvti_oid (nvti),
       quoted_version,
       quoted_name,
       quoted_summary,
       quoted_description,
       quoted_copyright,
       quoted_cve,
       quoted_bid,
       quoted_xref,
       quoted_tag,
       quoted_sign_key_ids,
       nvti_category (nvti),
       quoted_family,
       quoted_cvss_base,
       quoted_risk_factor);

  if (remove)
    sql ("COMMIT;");

  g_free (quoted_version);
  g_free (quoted_name);
  g_free (quoted_summary);
  g_free (quoted_description);
  g_free (quoted_copyright);
  g_free (quoted_cve);
  g_free (quoted_bid);
  g_free (quoted_xref);
  g_free (quoted_tag);
  g_free (quoted_cvss_base);
  g_free (quoted_risk_factor);
  g_free (quoted_sign_key_ids);
  g_free (quoted_family);

  return sqlite3_last_insert_rowid (task_db);
}

/**
 * @brief Initialise an NVT iterator.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  nvt         NVT to iterate over, all if 0.
 * @param[in]  config      Config to limit selection to.  NULL for all NVTs.
 *                         Overridden by \arg nvt.
 * @param[in]  family      Family to limit selection to.  NULL for all NVTs.
 *                         Overridden by \arg config.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for "ROWID".
 */
void
init_nvt_iterator (iterator_t* iterator, nvt_t nvt, config_t config,
                   const char* family, int ascending, const char* sort_field)
{
  assert ((nvt && family) == 0);

  if (nvt)
    {
      gchar* sql;
      sql = g_strdup_printf ("SELECT oid, version, name, summary, description,"
                             " copyright, cve, bid, xref, tag, sign_key_ids,"
                             " category, family, cvss_base, risk_factor"
                             " FROM nvts WHERE ROWID = %llu;",
                             nvt);
      init_iterator (iterator, sql);
      g_free (sql);
    }
  else if (config)
    {
      gchar* sql;
      if (family == NULL) abort ();
      sql = select_config_nvts (config, family, ascending, sort_field);
      if (sql)
        {
          init_iterator (iterator, sql);
          g_free (sql);
        }
      else
        init_iterator (iterator,
                       "SELECT oid, version, name, summary, description,"
                       " copyright, cve, bid, xref, tag, sign_key_ids,"
                       " category, family, cvss_base, risk_factor"
                       " FROM nvts LIMIT 0;");
    }
  else if (family)
    {
      gchar *quoted_family = sql_quote (family);
      init_iterator (iterator,
                     "SELECT oid, version, name, summary, description,"
                     " copyright, cve, bid, xref, tag, sign_key_ids,"
                     " category, family, cvss_base, risk_factor"
                     " FROM nvts"
                     " WHERE family = '%s'"
                     " ORDER BY %s %s;",
                     quoted_family,
                     sort_field ? sort_field : "name",
                     ascending ? "ASC" : "DESC");
      g_free (quoted_family);
    }
  else
    init_iterator (iterator,
                   "SELECT oid, version, name, summary, description,"
                   " copyright, cve, bid, xref, tag, sign_key_ids,"
                   " category, family, cvss_base, risk_factor"
                   " FROM nvts"
                   " ORDER BY %s %s;",
                   sort_field ? sort_field : "name",
                   ascending ? "ASC" : "DESC");
}

/**
 * @brief Get the OID from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return OID, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_oid, 0);

/**
 * @brief Get the version from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Version, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_version, 1);

/**
 * @brief Get the name from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_name, 2);

/**
 * @brief Get the summary from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Summary, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_summary, 3);

/**
 * @brief Get the description from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Description, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_description, 4);

/**
 * @brief Get the copyright from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Copyright, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_copyright, 5);

/**
 * @brief Get the cve from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Cve, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_cve, 6);

/**
 * @brief Get the bid from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Bid, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_bid, 7);

/**
 * @brief Get the xref from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Xref, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_xref, 8);

/**
 * @brief Get the tag from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Tag, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_tag, 9);

/**
 * @brief Get the sign_key_ids from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Sign_key_ids, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_sign_key_ids, 10);

/**
 * @brief Get the category from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Category.
 */
int
nvt_iterator_category (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (int) sqlite3_column_int (iterator->stmt, 11);
  return ret;
}

/**
 * @brief Get the family from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Family, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_family, 12);

/**
 * @brief Get the cvss_base from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Cvss_base, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_cvss_base, 13);

/**
 * @brief Get the risk_factor from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Risk_factor, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_risk_factor, 14);

/**
 * @brief Get the number of NVTs in one or all families.
 *
 * @param[in]  family  Family name.  NULL for all families.
 *
 * @return Number of NVTs in family, or total number of nvts.
 */
int
family_nvt_count (const char *family)
{
  gchar *quoted_family;

  if (family == NULL)
    {
      static int nvt_count = -1;
      if (nvt_count == -1)
        nvt_count = sql_int (0, 0, "SELECT COUNT(*) FROM nvts;");
      return nvt_count;
    }

  quoted_family = sql_quote (family);
  int ret = sql_int (0, 0,
                     "SELECT COUNT(*) FROM nvts WHERE family = '%s';",
                     quoted_family);
  g_free (quoted_family);
  return ret;
}

/**
 * @brief Get the number of families.
 *
 * @return Total number of families.
 */
int
family_count ()
{
  return sql_int (0, 0, "SELECT COUNT(distinct family) FROM nvts;");
}

/**
 * @brief Update the cached count and growing information in a config.
 *
 * It's up to the caller to organise a transaction.
 *
 * @param[in]  configs  Config to update.
 */
static void
update_config_cache (iterator_t *configs)
{
  const char *selector;
  gchar *quoted_selector, *quoted_name;
  int families_growing;

  quoted_name = sql_quote (config_iterator_name (configs));
  selector = config_iterator_nvt_selector (configs);
  families_growing = nvt_selector_families_growing (selector);
  quoted_selector = sql_quote (selector);

  sql ("UPDATE configs"
       " SET family_count = %i, nvt_count = %i,"
       " families_growing = %i, nvts_growing = %i"
       " WHERE name = '%s';",
       nvt_selector_family_count (quoted_selector, families_growing),
       nvt_selector_nvt_count (quoted_selector, NULL, families_growing),
       families_growing,
       nvt_selector_nvts_growing_2 (quoted_selector, families_growing),
       quoted_name);

  g_free (quoted_name);
  g_free (quoted_selector);
}

/**
 * @brief Update the cached count and growing information in every config.
 *
 * Only consider configs for the current user.
 *
 * It's up to the caller to organise a transaction.
 *
 * @param[in]  config  Config to update.  0 for all.
 */
static void
update_config_caches (config_t config)
{
  iterator_t configs;

  init_config_iterator (&configs, config, 1, NULL);
  while (next (&configs))
    update_config_cache (&configs);
  cleanup_iterator (&configs);
}

/**
 * @brief Update count and growing info in every config across all users.
 *
 * It's up to the caller to organise a transaction.
 */
static void
update_all_config_caches ()
{
  iterator_t configs;

  init_iterator (&configs, "SELECT " CONFIG_ITERATOR_FIELDS " FROM configs;");
  while (next (&configs))
    update_config_cache (&configs);
  cleanup_iterator (&configs);
}

/**
 * @brief Complete an update of the NVT cache.
 *
 * @param[in]  mode  -1 updating, -2 rebuilding.
 */
void
manage_complete_nvt_cache_update (int mode)
{
  iterator_t configs;

  /* Remove preferences from configs where the preference has vanished from
   * the associated NVT. */
  init_iterator (&configs, "SELECT " CONFIG_ITERATOR_FIELDS " FROM configs;");
  while (next (&configs))
    sql ("DELETE FROM config_preferences"
         " WHERE config = %llu"
         " AND type = 'PLUGINS_PREFS'"
         " AND name NOT IN (SELECT nvt_preferences.name FROM nvt_preferences);",
         config_iterator_config (&configs));
  cleanup_iterator (&configs);

  update_all_config_caches ();
  if (mode == -2) sql ("COMMIT;");
}


/* NVT selectors.
 *
 * An NVT selector is a named selection of NVT's from the cache of all
 * NVT's.
 *
 * An NVT selector is made up of zero or more selectors.  The selectors
 * combine in ROWID order to make a selection.  Depending on the choice
 * of selectors the selection can be static or growing.  A growing
 * selection can grow when new NVT's enter the NVT cache, either because it
 * selects new families or because it selects new NVT's within exising
 * families.
 *
 * There are three types of selectors that an NVT selector can contain.
 *
 *   1) The "all selector", which selects all families and all NVT's in
 *      those families.  The only way to construct the NVT selector so
 *      that it grows to includes new families, is to add this selector.
 *
 *   2) A "family" selector, which designates an entire family.
 *
 *   3) An "NVT" selector, which designates a single NVT.
 *
 *      The naming overlaps here.  It's a selector of type NVT, which is
 *      part of an "NVT selector" (a named collection of selectors).
 *
 * The family and NVT type selectors can either include or exclude the
 * designated NVT's.
 *
 * While the all selector provides a way to select every single NVT, the
 * empty NVT selector corresponds to an empty NVT set.
 *
 * The selectors provide a mechanism to select a wide range of NVT
 * combinations.  The mechanism allows for complex selections involving
 * redundant selectors.  The Manager, however, only implements a simple
 * subset of the possible combinations of selectors.  This simple subset
 * is split into two cases.
 *
 *   1) Constraining the universe.
 *
 *      The all selector and an optional exclude for each family,
 *      optional NVT includes in the excluded families, and optional NVT
 *      includes in all other families.
 *
 *      This allows a growing collection of families, while any family
 *      can still have a static NVT selection.
 *
 *   2) Generating from empty.
 *
 *      An empty set of selectors with an optional include for each family,
 *      optional NVT excludes in the included families, and optional NVT
 *      includes in all other families.
 *
 *      This allows a static collection of families, while any family
 *      can still grow when new NVT's enter the family.
 *
 * Either case allows one or more NVT's to be excluded from the family, both
 * when the family is growing and when the family is static.
 */

/* These could handle strange cases, like when a family is
 * included then excluded, or all is included then later excluded.
 * However, OMP prevents those cases from occuring. */

/**
 * @brief Get the number of families selected by an NVT selector.
 *
 * A growing family which has all current NVT's excluded is still
 * considered as selected by the NVT selector.
 *
 * @param[in]  quoted_selector   SQL-quoted selector name.
 * @param[in]  families_growing  1 if families are growing, else 0.
 *
 * @return The number of families selected by an NVT selector.
 */
static int
nvt_selector_family_count (const char* quoted_selector, int families_growing)
{
  if (families_growing)
    /* Assume the only family selectors are excludes. */
    return family_count ()
           - sql_int (0, 0,
                      "SELECT COUNT(distinct family_or_nvt) FROM nvt_selectors"
                      " WHERE name = '%s'"
                      " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_FAMILY)
                      " AND exclude = 0"
                      " LIMIT 1;",
                      quoted_selector);

  /* Assume that the only family selectors are includes, and that if a
   * selection has any NVT includes then it only has NVT includes. */
  return sql_int (0, 0,
                  "SELECT COUNT(*) FROM nvt_selectors"
                  " WHERE name = '%s'"
                  " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_FAMILY)
                  " AND exclude = 0"
                  " LIMIT 1;",
                  quoted_selector)
         + sql_int (0, 0,
                    "SELECT COUNT(DISTINCT family) FROM nvt_selectors"
                    " WHERE name = '%s'"
                    " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
                    " AND exclude = 0"
                    " AND family NOT NULL"
                    " LIMIT 1;",
                    quoted_selector);
}

/**
 * @brief Get the family growth status of an NVT selector.
 *
 * @param[in]  selector  NVT selector.
 *
 * @return 1 growing, 0 static.
 */
static int
nvt_selector_families_growing (const char* selector)
{
  /** @todo Quote selector. */
  /* The number of families can only grow if there is selector that includes
   * all. */
#if 0
  return sql_int (0, 0,
                  "SELECT COUNT(*) FROM nvt_selectors"
                  " WHERE name = '%s'"
                  " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_ALL)
                  " AND exclude = 0"
                  " LIMIT 1;",
                  selector);
#else
  char *string;
  string = sql_string (0, 0,
                       "SELECT name FROM nvt_selectors"
                       " WHERE name = '%s'"
                       " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_ALL)
                       " AND exclude = 0"
                       " LIMIT 1;",
                       selector);
  if (string == NULL) return 0;
  free (string);
  return 1;
#endif
}

/**
 * @brief Get the NVT growth status of an NVT selector.
 *
 * @param[in]  quoted_selector   SQL-quoted selector name.
 * @param[in]  families_growing  1 if families are growing, else 0.
 *
 * @return 1 growing, 0 static.
 */
static int
nvt_selector_nvts_growing_2 (const char* quoted_selector, int families_growing)
{
  if (families_growing)
    /* Assume the only family selectors are excludes. */
    return (family_count ()
            - sql_int (0, 0,
                       "SELECT COUNT(distinct family_or_nvt) FROM nvt_selectors"
                       " WHERE name = '%s'"
                       " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_FAMILY)
                       " AND exclude = 0"
                       " LIMIT 1;",
                       quoted_selector))
           > 0;

  /* Assume the only family selectors are includes. */
  return sql_int (0, 0,
                  "SELECT COUNT(*) FROM nvt_selectors"
                  " WHERE name = '%s'"
                  " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_FAMILY)
                  " AND exclude = 0"
                  " LIMIT 1;",
                  quoted_selector)
         > 0;
}

/**
 * @brief Get the NVT growth status of an NVT selector.
 *
 * @param[in]  selector   Selector name.
 *
 * @return 1 growing, 0 static.
 */
static int
nvt_selector_nvts_growing (const char* selector)
{
  int ret;
  gchar *quoted_selector = sql_quote (selector);
  ret = nvt_selector_nvts_growing_2 (quoted_selector,
                                     nvt_selector_families_growing (selector));
  g_free (quoted_selector);
  return ret;
}

/** @todo Move these config functions to the config section. */

/**
 * @brief Get the NVT growth status of a config.
 *
 * @param[in]  config  Config.
 *
 * @return 1 growing, 0 static.
 */
int
config_nvts_growing (config_t config)
{
  return sql_int (0, 0,
                  "SELECT nvts_growing FROM configs"
                  " WHERE ROWID = %llu;",
                  config);
}

/**
 * @brief Get the family growth status of a config.
 *
 * @param[in]  config  Config.
 *
 * @return 1 growing, 0 static.
 */
int
config_families_growing (config_t config)
{
  return sql_int (0, 0,
                  "SELECT families_growing FROM configs"
                  " WHERE ROWID = %llu;",
                  config);
}

/**
 * @brief Initialise an NVT selector iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  selector  Name of single selector to iterate over, NULL for all.
 * @param[in]  config    Config to limit iteration to, 0 for all.
 * @param[in]  type      Type of selector.  All if config is given.
 */
void
init_nvt_selector_iterator (iterator_t* iterator, const char* selector,
                            config_t config, int type)
{
  gchar *sql;

  assert (selector ? config == 0 : (config ? selector == NULL : 1));
  assert (config ? type == NVT_SELECTOR_TYPE_ANY : (type >= 0 && type <= 2));

  if (selector)
    {
      gchar *quoted_selector = sql_quote (selector);
      sql = g_strdup_printf ("SELECT exclude, family_or_nvt, name, type"
                             " FROM nvt_selectors"
                             " WHERE name = '%s' AND type = %i;",
                             quoted_selector,
                             type);
      g_free (quoted_selector);
    }
  else if (config)
    sql = g_strdup_printf ("SELECT exclude, family_or_nvt, name, type"
                           " FROM nvt_selectors"
                           " WHERE name ="
                           " (SELECT nvt_selector FROM configs"
                           "  WHERE configs.ROWID = %llu);",
                           config);
  else
    sql = g_strdup_printf ("SELECT exclude, family_or_nvt, name, type"
                           " FROM nvt_selectors"
                           " WHERE type = %i;",
                           type);
  init_iterator (iterator, sql);
  g_free (sql);
}

/**
 * @brief Get whether the selector rule is an include rule.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return -1 if iteration is complete, 1 if include, else 0.
 */
int
nvt_selector_iterator_include (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (int) sqlite3_column_int (iterator->stmt, 0);
  return ret == 0;
}

/**
 * @brief Get the NVT or family from an NVT selector iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return NVT selector, or NULL if iteration is complete.
 */
DEF_ACCESS (nvt_selector_iterator_nvt, 1);

/**
 * @brief Get the name from an NVT selector iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return NVT selector, or NULL if iteration is complete.
 */
DEF_ACCESS (nvt_selector_iterator_name, 2);

/**
 * @brief Get the type from an NVT selector.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return -1 if iteration is complete, 1 if include, else 0.
 */
int
nvt_selector_iterator_type (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (int) sqlite3_column_int (iterator->stmt, 3);
  return ret;
}

/**
 * @brief Get the number of families included in a config.
 *
 * @param[in]  config  Config.
 *
 * @return Family count if known, else -1.
 */
int
config_family_count (config_t config)
{
  return sql_int (0, 0,
                  "SELECT family_count FROM configs"
                  " WHERE ROWID = %llu"
                  " LIMIT 1;",
                  config);
}

/**
 * @brief Get the number of NVTs included in a config.
 *
 * @param[in]  config  Config.
 *
 * @return NVT count if known, else -1.
 */
int
config_nvt_count (config_t config)
{
  return sql_int (0, 0,
                  "SELECT nvt_count FROM configs"
                  " WHERE ROWID = %llu"
                  " LIMIT 1;",
                  config);
}

/**
 * @brief Initialise an NVT selector family iterator.
 *
 * @param[in]  iterator   Iterator.
 * @param[in]  all        True if families are growing in the selector, else 0.
 *                        Only considered with a selector.
 * @param[in]  selector   Name of NVT selector.  NULL for all families.
 * @param[in]  ascending  Whether to sort ascending or descending.
 */
void
init_family_iterator (iterator_t* iterator, int all, const char* selector,
                      int ascending)
{
  gchar *quoted_selector;

  if (selector == NULL)
    {
      init_iterator (iterator,
                     "SELECT distinct family FROM nvts ORDER BY family %s;",
                     ascending ? "ASC" : "DESC");
      return;
    }

  quoted_selector = sql_quote (selector);
  if (all)
    /* Constraining the universe.  Presume there is a family exclude for
     * every NVT include. */
    init_iterator (iterator,
                   "SELECT distinct family FROM nvts"
                   " EXCEPT"
                   " SELECT distinct family FROM nvt_selectors"
                   " WHERE type = " G_STRINGIFY (NVT_SELECTOR_TYPE_FAMILY)
                   " AND exclude = 1"
                   " AND name = '%s'"
                   " UNION"
                   " SELECT distinct family FROM nvt_selectors"
                   " WHERE type = " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
                   " AND exclude = 0"
                   " AND name = '%s'"
                   " ORDER BY family %s;",
                   quoted_selector,
                   quoted_selector,
                   ascending ? "ASC" : "DESC");
  else
    /* Generating from empty.  Presume any exclude is covered by an include. */
    init_iterator (iterator,
                   "SELECT distinct family FROM nvt_selectors"
                   " WHERE (type = 1 OR type = 2) AND name = '%s'"
                   " ORDER BY family %s;",
                   quoted_selector,
                   ascending ? "ASC" : "DESC");
  g_free (quoted_selector);
}

/**
 * @brief Get the name from a family iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (family_iterator_name, 0);

/**
 * @brief Get whether an NVT selector family is growing.
 *
 * @param[in]  selector  NVT selector.
 * @param[in]  family    Family name.
 * @param[in]  all       True if selector is an "all" selector, else 0.
 *
 * @return 1 growing, 0 static.
 */
int
nvt_selector_family_growing (const char *selector,
                             const char *family,
                             int all)
{
  int ret;
  gchar *quoted_family;
  gchar *quoted_selector;

  quoted_selector = sql_quote (selector);
  quoted_family = sql_quote (family);

  if (all)
    {
      /* Constraining the universe.  It's static if there is a family
       * exclude. */

      ret = sql_int (0, 0,
                     "SELECT COUNT(*) FROM nvt_selectors"
                     " WHERE name = '%s'"
                     " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_FAMILY)
                     " AND family_or_nvt = '%s'"
                     " AND exclude = 1"
                     " LIMIT 1;",
                     quoted_selector,
                     quoted_family);

      g_free (quoted_selector);
      g_free (quoted_family);

      return ret ? 0 : 1;
    }

  /* Generating from empty.  It's growing if there is a family include. */

  ret = sql_int (0, 0,
                 "SELECT COUNT(*) FROM nvt_selectors"
                 " WHERE name = '%s'"
                 " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_FAMILY)
                 " AND family_or_nvt = '%s'"
                 " AND exclude = 0"
                 " LIMIT 1;",
                 quoted_selector,
                 quoted_family);

  g_free (quoted_selector);
  g_free (quoted_family);

  return ret ? 1 : 0;
}

/**
 * @brief Get the number of NVTs selected by an NVT selector.
 *
 * @param[in]  selector  NVT selector.
 * @param[in]  family    Family name.  NULL for all.
 * @param[in]  growing   True if the given family is growing, else 0.
 *                       If \param family is NULL, true if the the families
 *                       are growing, else 0.
 *
 * @return Number of NVTs selected in one or all families.
 */
int
nvt_selector_nvt_count (const char *selector,
                        const char *family,
                        int growing)
{
  if (family)
    {
      int ret;

      /* Count in a single family. */

      if (growing)
        {
          gchar *quoted_family = sql_quote (family);
          gchar *quoted_selector = sql_quote (selector);
          ret = sql_int (0, 0,
                         "SELECT COUNT(*) FROM nvts WHERE family = '%s';",
                         quoted_family);
          ret -= sql_int (0, 0,
                          "SELECT COUNT(*) FROM nvt_selectors"
                          " WHERE exclude = 1 AND type = 2"
                          " AND name = '%s' AND family = '%s';",
                          quoted_selector,
                          quoted_family);
          g_free (quoted_family);
          g_free (quoted_selector);
        }
      else
        {
          gchar *quoted_selector = sql_quote (selector);
          gchar *quoted_family = sql_quote (family);
          ret = sql_int (0, 0,
                         "SELECT COUNT(*) FROM nvt_selectors"
                         " WHERE exclude = 0 AND type = 2"
                         " AND name = '%s' AND family = '%s';",
                         quoted_selector,
                         quoted_family);
          g_free (quoted_family);
          g_free (quoted_selector);
        }

      return ret;
   }
 else
   {
     int count;
     iterator_t families;

     /* Count in each family. */

     count = 0;
     init_family_iterator (&families, 0, NULL, 1);
     while (next (&families))
       {
         const char *family = family_iterator_name (&families);
         if (family)
           count += nvt_selector_nvt_count (selector,
                                            family,
                                            nvt_selector_family_growing
                                             (selector, family, growing));
       }
     cleanup_iterator (&families);

     return count;
   }
}

/**
 * @brief Return SQL for selecting NVT's of a config from one family.
 *
 * @param[in]  config      Config.
 * @param[in]  family      Family to limit selection to.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for "nvts.ROWID".
 *
 * @return Freshly allocated SELECT statement on success, or NULL on error.
 */
static gchar*
select_config_nvts (const config_t config, const char* family, int ascending,
                    const char* sort_field)
{
  gchar *quoted_selector;
  char *selector = config_nvt_selector (config);
  if (selector == NULL)
    /* The config should always have a selector. */
    return NULL;

  /** @todo Free. */
  quoted_selector = sql_quote (selector);
  free (selector);

  /** @todo Quote family. */

  if (config_nvts_growing (config))
    {
      int constraining;

      /* The number of NVT's can increase. */

      constraining = config_families_growing (config);

      if (constraining)
        {
          /* Constraining the universe. */

          if (sql_int (0, 0,
                        "SELECT COUNT(*) FROM nvt_selectors WHERE name = '%s';",
                        quoted_selector)
              == 1)
            /* There is one selector, it should be the all selector. */
            return g_strdup_printf
                    ("SELECT oid, version, name, summary, description,"
                     " copyright, cve, bid, xref, tag, sign_key_ids,"
                     " category, family, cvss_base, risk_factor"
                     " FROM nvts WHERE family = '%s'"
                     " ORDER BY %s %s;",
                     family,
                     sort_field ? sort_field : "name",
                     ascending ? "ASC" : "DESC");

          /* There are multiple selectors. */

          if (sql_int (0, 0,
                       "SELECT COUNT(*) FROM nvt_selectors"
                       " WHERE name = '%s' AND exclude = 1"
                       " AND type = "
                       G_STRINGIFY (NVT_SELECTOR_TYPE_FAMILY)
                       " AND family_or_nvt = '%s'"
                       ";",
                       quoted_selector,
                       family))
            /* The family is excluded, just iterate the NVT includes. */
            return g_strdup_printf
                    ("SELECT oid, version, nvts.name, summary, description,"
                     " copyright, cve, bid, xref, tag, sign_key_ids,"
                     " category, nvts.family, cvss_base, risk_factor"
                     " FROM nvts, nvt_selectors"
                     " WHERE"
                     " nvts.family = '%s'"
                     " AND nvt_selectors.name = '%s'"
                     " AND nvt_selectors.family = '%s'"
                     " AND nvt_selectors.type = "
                     G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
                     " AND nvt_selectors.exclude = 0"
                     " AND nvts.oid == nvt_selectors.family_or_nvt"
                     " ORDER BY %s %s;",
                     family,
                     quoted_selector,
                     family,
                     sort_field ? sort_field : "nvts.name",
                     ascending ? "ASC" : "DESC");

          /* The family is included.  Iterate all NVT's minus excluded NVT's. */
          return g_strdup_printf
                  ("SELECT oid, version, name, summary, description,"
                   " copyright, cve, bid, xref, tag, sign_key_ids,"
                   " category, family, cvss_base, risk_factor"
                   " FROM nvts"
                   " WHERE family = '%s'"
                   " EXCEPT"
                   " SELECT oid, version, nvts.name, summary, description,"
                   " copyright, cve, bid, xref, tag, sign_key_ids,"
                   " category, nvts.family, cvss_base, risk_factor"
                   " FROM nvt_selectors, nvts"
                   " WHERE"
                   " nvts.family = '%s'"
                   " AND nvt_selectors.name = '%s'"
                   " AND nvt_selectors.family = '%s'"
                   " AND nvt_selectors.type = "
                   G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
                   " AND nvt_selectors.exclude = 1"
                   " AND nvts.oid == nvt_selectors.family_or_nvt"
                   " ORDER BY %s %s;",
                   family,
                   family,
                   quoted_selector,
                   family,
                   sort_field ? sort_field : "nvts.name",
                   ascending ? "ASC" : "DESC");
        }
      else
        {
          int all;

          /* Generating from empty. */

          all = sql_int (0, 0,
                         "SELECT COUNT(*) FROM nvt_selectors"
                         " WHERE name = '%s' AND exclude = 0"
                         " AND type = "
                         G_STRINGIFY (NVT_SELECTOR_TYPE_FAMILY)
                         " AND family_or_nvt = '%s';",
                         quoted_selector,
                         family);

          if (all)
            /* There is a family include for this family. */
            return g_strdup_printf
                    ("SELECT oid, version, name, summary, description,"
                     " copyright, cve, bid, xref, tag, sign_key_ids,"
                     " category, family, cvss_base, risk_factor"
                     " FROM nvts"
                     " WHERE family = '%s'"
                     " EXCEPT"
                     " SELECT oid, version, nvts.name, summary, description,"
                     " copyright, cve, bid, xref, tag, sign_key_ids,"
                     " category, nvts.family, cvss_base, risk_factor"
                     " FROM nvt_selectors, nvts"
                     " WHERE"
                     " nvts.family = '%s'"
                     " AND nvt_selectors.name = '%s'"
                     " AND nvt_selectors.family = '%s'"
                     " AND nvt_selectors.type = "
                     G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
                     " AND nvt_selectors.exclude = 1"
                     " AND nvts.oid == nvt_selectors.family_or_nvt"
                     " ORDER BY %s %s;",
                     family,
                     family,
                     quoted_selector,
                     family,
                     sort_field ? sort_field : "nvts.name",
                     ascending ? "ASC" : "DESC");

          return g_strdup_printf
                  (" SELECT oid, version, nvts.name, summary, description,"
                   " copyright, cve, bid, xref, tag, sign_key_ids,"
                   " category, nvts.family, cvss_base, risk_factor"
                   " FROM nvt_selectors, nvts"
                   " WHERE"
                   " nvts.family = '%s'"
                   " AND nvt_selectors.name = '%s'"
                   " AND nvt_selectors.family = '%s'"
                   " AND nvt_selectors.type = "
                   G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
                   " AND nvt_selectors.exclude = 0"
                   " AND nvts.oid == nvt_selectors.family_or_nvt"
                   " ORDER BY %s %s;",
                   family,
                   quoted_selector,
                   family,
                   sort_field ? sort_field : "nvts.name",
                   ascending ? "ASC" : "DESC");
        }
    }
  else
    {
      gchar *sql, *quoted_family;

      /* The number of NVT's is static.  Assume a simple list of NVT
       * includes. */

      quoted_family = sql_quote (family);
      sql = g_strdup_printf
             ("SELECT oid, version, nvts.name, summary, description,"
              " copyright, cve, bid, xref, tag, sign_key_ids,"
              " category, nvts.family, cvss_base, risk_factor"
              " FROM nvt_selectors, nvts"
              " WHERE nvts.family = '%s'"
              " AND nvt_selectors.exclude = 0"
              " AND nvt_selectors.type = " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
              " AND nvt_selectors.name = '%s'"
              " AND nvts.oid = nvt_selectors.family_or_nvt"
              " ORDER BY %s %s;",
              quoted_family,
              quoted_selector,
              sort_field ? sort_field : "nvts.ROWID",
              ascending ? "ASC" : "DESC");
      g_free (quoted_family);

      return sql;
    }
}

/**
 * @brief Remove all selectors of a certain family from an NVT selector.
 *
 * @param[in]  quoted_selector  SQL-quoted selector name.
 * @param[in]  quoted_family    SQL-quoted family name.
 * @param[in]  type             Selector type to remove.
 *
 * @return 0 success, -1 error.
 */
static void
nvt_selector_remove (const char* quoted_selector,
                     const char* quoted_family,
                     int type)
{
  if (type == NVT_SELECTOR_TYPE_ANY)
    sql ("DELETE FROM nvt_selectors"
         " WHERE name = '%s'"
         " AND"
         " ((type = " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
         "   AND family = '%s')"
         "  OR (type = " G_STRINGIFY (NVT_SELECTOR_TYPE_FAMILY)
         "      AND family_or_nvt = '%s'));",
         quoted_selector,
         quoted_family,
         quoted_family);
  else if (type == NVT_SELECTOR_TYPE_NVT)
    sql ("DELETE FROM nvt_selectors"
         " WHERE name = '%s'"
         " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
         " AND family = '%s';",
         quoted_selector,
         quoted_family);
  else if (type == NVT_SELECTOR_TYPE_FAMILY)
    sql ("DELETE FROM nvt_selectors"
         " WHERE name = '%s'"
         " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_FAMILY)
         " AND family_or_nvt = '%s';",
         quoted_selector,
         quoted_family);
}

/**
 * @brief Remove all selectors of a certain type from an NVT selector.
 *
 * @param[in]  quoted_selector  SQL-quoted selector name.
 * @param[in]  family_or_nvt    SQL-quoted family name or NVT UUID.
 * @param[in]  type             Selector type to remove.
 *
 * @return 0 success, -1 error.
 */
static void
nvt_selector_remove_selector (const char* quoted_selector,
                              const char* family_or_nvt,
                              int type)
{
  if (type == NVT_SELECTOR_TYPE_ANY)
    sql ("DELETE FROM nvt_selectors"
         " WHERE name = '%s' AND family_or_nvt = '%s');",
         quoted_selector,
         family_or_nvt);
  else if (type == NVT_SELECTOR_TYPE_ALL)
    sql ("DELETE FROM nvt_selectors"
         " WHERE name = '%s'"
         " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_ALL) ";",
         quoted_selector);
  else
    sql ("DELETE FROM nvt_selectors"
         " WHERE name = '%s'"
         " AND type = %i"
         " AND family_or_nvt = '%s';",
         quoted_selector,
         type,
         family_or_nvt);
}

/**
 * @brief Add a selector to an NVT selector.
 *
 * @param[in]  quoted_selector  SQL-quoted selector name.
 * @param[in]  quoted_family_or_nvt  SQL-quoted family or NVT name.
 * @param[in]  quoted_family    SQL-quoted family name (NULL for families).
 * @param[in]  exclude          1 exclude selector, 0 include selector.
 *
 * @return 0 success, -1 error.
 */
static void
nvt_selector_add (const char* quoted_selector,
                  const char* quoted_family_or_nvt,
                  const char* quoted_family,
                  int exclude)
{
  if (quoted_family == NULL)
    sql ("INSERT INTO nvt_selectors"
         " (name, exclude, type, family_or_nvt, family)"
         " VALUES ('%s', %i, "
         G_STRINGIFY (NVT_SELECTOR_TYPE_FAMILY)
         ", '%s', '%s');",
         quoted_selector,
         exclude,
         quoted_family_or_nvt,
         quoted_family_or_nvt);
  else
    sql ("INSERT INTO nvt_selectors"
         " (name, exclude, type, family_or_nvt, family)"
         " VALUES ('%s', %i, "
         G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
         ", '%s', '%s');",
         quoted_selector,
         exclude,
         quoted_family_or_nvt,
         quoted_family);
}

/**
 * @brief Check whether a family is selected.
 *
 * Only works for "generating from empty" selection.
 *
 * @param[in]  quoted_selector  SQL-quoted selector name.
 * @param[in]  quoted_family    SQL-quoted family name (NULL for families).
 *
 * @return 1 if selected, else 0.
 */
static int
family_is_selected (const char* quoted_selector, const char* quoted_family)
{
  return sql_int (0, 0,
                  "SELECT count(*) FROM nvt_selectors"
                  " WHERE name = '%s'"
                  " AND (type = " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT)
                  "      AND family = '%s')"
                  " OR (type = " G_STRINGIFY (NVT_SELECTOR_TYPE_FAMILY)
                  "     AND family_or_nvt = '%s');",
                  quoted_selector,
                  quoted_family,
                  quoted_family);
}

/**
 * @brief Check whether an NVT selector has a particular selector.
 *
 * @param[in]  quoted_selector  SQL-quoted selector name.
 * @param[in]  family_or_nvt    SQL-quoted UUID of NVT, or family name.
 * @param[in]  type             Selector type.
 * @param[in]  exclude          1 exclude, 0 include.
 *
 * @return 1 if contains include/exclude, else 0.
 */
static int
nvt_selector_has (const char* quoted_selector, const char* family_or_nvt,
                  int type, int exclude)
{
  return sql_int (0, 0,
                  "SELECT count(*) FROM nvt_selectors"
                  " WHERE name = '%s'"
                  " AND type = %i"
                  " AND exclude = %i"
                  " AND family_or_nvt = '%s'"
                  " LIMIT 1;",
                  quoted_selector,
                  type,
                  exclude,
                  family_or_nvt);
}

/**
 * @brief Refresh NVT selection of a config from given families.
 *
 * @param[in]  config                Config.
 * @param[in]  growing_all_families  Growing families with all selection.
 * @param[in]  static_all_families   Static families with all selection.
 * @param[in]  growing_families      The rest of the growing families.
 * @param[in]  grow_families         1 if families should grow, else 0.
 *
 * @return 0 success, config in use, -1 error.
 */
int
manage_set_config_families (config_t config,
                            GPtrArray* growing_all_families,
                            GPtrArray* static_all_families,
                            GPtrArray* growing_families,
                            int grow_families)
{
  iterator_t families;
  gchar *quoted_selector;
  int constraining;
  char *selector;

  sql ("BEGIN EXCLUSIVE;");

  if (sql_int (0, 0,
               "SELECT count(*) FROM tasks WHERE config = %llu;",
               config))
    {
      sql ("ROLLBACK;");
      return 1;
    }

  constraining = config_families_growing (config);

  if (constraining + grow_families == 1)
    {
      if (switch_representation (config, constraining))
        {
          sql ("ROLLBACK;");
          return -1;
        }
      constraining = constraining == 0;
    }

  selector = config_nvt_selector (config);
  if (selector == NULL)
    {
      /* The config should always have a selector. */
      sql ("ROLLBACK;");
      return -1;
    }
  quoted_selector = sql_quote (selector);

  /* Loop through all the known families. */

  init_family_iterator (&families, 1, NULL, 1);
  while (next (&families))
    {
      const char *family;

      family = family_iterator_name (&families);
      if (family)
        {
          int old_nvt_count, new_nvt_count = 0, was_selected, max_nvt_count;
          int family_growing;
          int growing_all = member (growing_all_families, family);
          int static_all = member (static_all_families, family);
          gchar *quoted_family = sql_quote (family);

          assert ((growing_all && static_all) == 0);

          family_growing = nvt_selector_family_growing (selector,
                                                        family,
                                                        constraining);

          old_nvt_count
            = nvt_selector_nvt_count (selector, family, family_growing);

          max_nvt_count = family_nvt_count (family);

          if (growing_all || static_all)
            {
              if (old_nvt_count == max_nvt_count
                  && ((growing_all && family_growing)
                      || (static_all && family_growing == 0)))
                {
                  /* Already in required state. */
                  g_free (quoted_family);
                  continue;
                }

              was_selected = family_is_selected (quoted_selector,
                                                 quoted_family);

              /* Flush all selectors in the family from the config. */

              nvt_selector_remove (quoted_selector,
                                   quoted_family,
                                   NVT_SELECTOR_TYPE_ANY);

              if (static_all)
                {
                  iterator_t nvts;

                  /* Static selection of all the NVT's currently in the
                   * family. */

                  if (constraining)
                    {
                      /* Constraining the universe. */

                      /* Add an exclude for the family. */

                      nvt_selector_add (quoted_selector,
                                        quoted_family,
                                        NULL,
                                        1);
                    }
                  else
                    {
                      /* Generating from empty. */
                    }

                  /* Add an include for every NVT in the family. */

                  init_nvt_iterator (&nvts, (nvt_t) 0, (config_t) 0, family, 1,
                                     NULL);
                  while (next (&nvts))
                    {
                      nvt_selector_add (quoted_selector,
                                        nvt_iterator_oid (&nvts),
                                        quoted_family,
                                        0);
                      new_nvt_count++;
                    }
                  cleanup_iterator (&nvts);
                }
              else if (growing_all)
                {
                  /* Selection of an entire family, which grows with the family. */

                  if (constraining)
                    {
                      /* Constraining the universe. */
                    }
                  else
                    {
                      /* Generating from empty.  Add an include for the
                       * family. */

                      nvt_selector_add (quoted_selector,
                                        quoted_family,
                                        NULL,
                                        0);

                    }

                  new_nvt_count = max_nvt_count;
                }

              /* Update the cached config info. */

              sql ("UPDATE configs SET nvt_count = nvt_count - %i + %i,"
                   " nvts_growing = %i, family_count = family_count + %i"
                   " WHERE ROWID = %llu;",
                   old_nvt_count,
                   new_nvt_count,
                   growing_all ? 1 : 0,
                   was_selected ? 0 : 1,
                   config);
            }
          else
            {
              int must_grow = member (growing_families, family);

              if (must_grow)
                {
                  /* The resulting family must be growing.  If currently
                   * growing, leave as is, otherwise switch family to
                   * growing. */

                  if (old_nvt_count == max_nvt_count)
                    {
                      iterator_t nvts;

                      /* All were selected.  Clear selection, ensuring that
                       * the family is growing in the process.  */

                      nvt_selector_remove (quoted_selector,
                                           quoted_family,
                                           NVT_SELECTOR_TYPE_ANY);

                      if (constraining == 0)
                        /* Generating. */
                        nvt_selector_add (quoted_selector,
                                          quoted_family,
                                          NULL,
                                          0);

                      /* Add an exclude for every NVT in the family. */

                      init_nvt_iterator (&nvts, (nvt_t) 0, (config_t) 0,
                                         family, 1, NULL);
                      while (next (&nvts))
                        nvt_selector_add (quoted_selector,
                                          nvt_iterator_oid (&nvts),
                                          quoted_family,
                                          1);
                      cleanup_iterator (&nvts);

                      /* Update the cached config info. */

                      sql ("UPDATE configs SET nvt_count = nvt_count - %i,"
                           " nvts_growing = 1"
                           " WHERE ROWID = %llu;",
                           old_nvt_count,
                           config);
                    }
                  else if (family_growing == 0)
                    {
                      iterator_t nvts;

                      if (constraining == 0)
                        nvt_selector_add (quoted_selector,
                                          quoted_family,
                                          NULL,
                                          0);

                      /* Remove any included NVT, add excludes for all
                       * other NVT's. */

                      init_nvt_iterator (&nvts, (nvt_t) 0, (config_t) 0,
                                         family, 1, NULL);
                      while (next (&nvts))
                        if (nvt_selector_has (quoted_selector,
                                              nvt_iterator_oid (&nvts),
                                              NVT_SELECTOR_TYPE_NVT,
                                              0))
                          nvt_selector_remove_selector
                           (quoted_selector,
                            nvt_iterator_oid (&nvts),
                            NVT_SELECTOR_TYPE_NVT);
                        else
                          nvt_selector_add (quoted_selector,
                                            nvt_iterator_oid (&nvts),
                                            quoted_family,
                                            1);
                      cleanup_iterator (&nvts);

                      /* Update the cached config info. */

                      sql ("UPDATE configs SET nvts_growing = 1"
                           " WHERE ROWID = %llu;",
                           config);
                    }
                }
              else
                {
                  /* The resulting family must be static.  If currently
                   * static, leave as is, otherwise switch family to
                   * static. */

                  if (old_nvt_count == max_nvt_count)
                    {
                      /* All were selected, clear selection, ensuring the
                       * family is static in the process. */

                      nvt_selector_remove (quoted_selector,
                                           quoted_family,
                                           NVT_SELECTOR_TYPE_ANY);
                      if (constraining)
                        nvt_selector_add (quoted_selector,
                                          quoted_family,
                                          NULL,
                                          1);

                      /* Update the cached config info. */

                      sql ("UPDATE configs SET nvts_growing = %i,"
                           " nvt_count = nvt_count - %i,"
                           " family_count = family_count - 1"
                           " WHERE ROWID = %llu;",
                           /* Recalculate the NVT growing state. */
                           nvt_selector_nvts_growing_2 (quoted_selector,
                                                        constraining),
                           old_nvt_count,
                           config);
                    }
                  else if (family_growing)
                    {
                      iterator_t nvts;

                      if (constraining)
                        nvt_selector_add (quoted_selector,
                                          quoted_family,
                                          NULL,
                                          1);
                      else
                        nvt_selector_remove (quoted_selector,
                                             quoted_family,
                                             NVT_SELECTOR_TYPE_FAMILY);

                      /* Remove any excluded NVT; add includes for all
                       * other NVT's. */

                      init_nvt_iterator (&nvts, (nvt_t) 0, (config_t) 0,
                                         family, 1, NULL);
                      while (next (&nvts))
                        if (nvt_selector_has (quoted_selector,
                                              nvt_iterator_oid (&nvts),
                                              NVT_SELECTOR_TYPE_NVT,
                                              1))
                          nvt_selector_remove_selector
                            (quoted_selector,
                             nvt_iterator_oid (&nvts),
                             NVT_SELECTOR_TYPE_NVT);
                        else
                          nvt_selector_add (quoted_selector,
                                            nvt_iterator_oid (&nvts),
                                            quoted_family,
                                            0);
                      cleanup_iterator (&nvts);

                      /* Update the cached config info. */

                      sql ("UPDATE configs SET nvts_growing = %i"
                           " WHERE ROWID = %llu;",
                           /* Recalculate the NVT growing state. */
                           nvt_selector_nvts_growing_2 (quoted_selector,
                                                        constraining),
                           config);
                    }
                }
            }

          g_free (quoted_family);
        }
    }
  cleanup_iterator (&families);

  sql ("COMMIT;");

  g_free (quoted_selector);
  free (selector);
  return 0;
}

/**
 * @brief Insert NVT selectors.
 *
 * @param[in]  quoted_name  Name of NVT selector.
 * @param[in]  selectors    NVT selectors.
 *
 * @return 0 success, -1 error, -3 input error.
 */
static int
insert_nvt_selectors (const char *quoted_name,
                      const array_t* selectors /* nvt_selector_t. */)
{
  int index = 0;
  const nvt_selector_t *selector;
  if (selectors == NULL) return -3;
  while ((selector = (nvt_selector_t*) g_ptr_array_index (selectors, index++)))
    {
      int type;

      if (selector->type == NULL) return -3;

      /** @todo Check that selector->type is actually an integer. */
      type = atoi (selector->type);

      if ((selector->family_or_nvt != NULL)
          && (type == NVT_SELECTOR_TYPE_NVT))
        {
          gchar *quoted_family_or_nvt, *quoted_family, *family = NULL;
          nvti_t *nvti = nvtis_lookup (nvti_cache, selector->family_or_nvt);

          /* An NVT selector. */

          if (nvti)
            {
              family = nvti_family (nvti);

              if (family == NULL)
                {
                  g_warning ("%s: skipping NVT '%s' from import of config '%s'"
                             " because the NVT is missing a family in the"
                             " cache",
                             __FUNCTION__,
                             selector->family_or_nvt,
                             quoted_name);
                  continue;
                }
            }
          else
            {
              g_warning ("%s: skipping NVT '%s' from import of config '%s'"
                         " because the NVT is missing from the cache",
                         __FUNCTION__,
                         selector->family_or_nvt,
                         quoted_name);
              continue;
            }

          quoted_family_or_nvt = sql_quote (selector->family_or_nvt);
          quoted_family = sql_quote (family);
          sql ("INSERT into nvt_selectors (name, exclude, type, family_or_nvt,"
               " family)"
               " VALUES ('%s', %i, %i, '%s', '%s');",
               quoted_name,
               selector->include ? 0 : 1,
               type,
               quoted_family_or_nvt,
               quoted_family);
          g_free (quoted_family_or_nvt);
          g_free (quoted_family);
        }
      else if (selector->family_or_nvt)
        {
          gchar *quoted_family_or_nvt;

          /* A family selector. */

          if (type != NVT_SELECTOR_TYPE_FAMILY)
            {
              g_warning ("%s: skipping NVT '%s' from import of config '%s'"
                         " because the type is wrong (expected family)",
                         __FUNCTION__,
                         selector->family_or_nvt,
                         quoted_name);
              continue;
            }

          quoted_family_or_nvt = sql_quote (selector->family_or_nvt);

          sql ("INSERT into nvt_selectors (name, exclude, type, family_or_nvt,"
               " family)"
               " VALUES ('%s', %i, %i, '%s', '%s');",
               quoted_name,
               selector->include ? 0 : 1,
               type,
               quoted_family_or_nvt,
               quoted_family_or_nvt);
          g_free (quoted_family_or_nvt);
        }
      else
        {
          /* An "all" selector. */

          if (type != NVT_SELECTOR_TYPE_ALL)
            {
              g_warning ("%s: skipping NVT from import of config '%s'"
                         " because the type is wrong (expected all)",
                         __FUNCTION__,
                         quoted_name);
              continue;
            }

          sql ("INSERT into nvt_selectors (name, exclude, type, family_or_nvt,"
               " family)"
               " VALUES ('%s', %i, %i, NULL, NULL);",
               quoted_name,
               selector->include ? 0 : 1,
               type);
        }
    }
  return 0;
}


/* NVT preferences. */

/**
 * @brief Add an NVT preference.
 *
 * @param[in]  name    The name of the preference.
 * @param[in]  value   The value of the preference.
 * @param[in]  remove  Whether to remove the preference from the database first.
 */
void
manage_nvt_preference_add (const char* name, const char* value, int remove)
{
  gchar* quoted_name = sql_quote (name);
  gchar* quoted_value = sql_quote (value);

  if (remove)
    {
      sql ("BEGIN EXCLUSIVE;");
      sql ("DELETE FROM nvt_preferences WHERE name = '%s';", quoted_name);
    }

  if (strcmp (name, "port_range"))
    sql ("INSERT into nvt_preferences (name, value)"
         " VALUES ('%s', '%s');",
         quoted_name, quoted_value);

  if (remove)
    sql ("COMMIT;");

  g_free (quoted_name);
  g_free (quoted_value);
}

/**
 * @brief Enable the NVT preferences.
 */
void
manage_nvt_preferences_enable ()
{
  sql ("INSERT OR REPLACE INTO meta (name, value)"
       " VALUES ('nvt_preferences_enabled', 1);");
}

/**
 * @brief Initialise an NVT preference iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  name      Name of NVT, NULL for all preferences.
 */
void
init_nvt_preference_iterator (iterator_t* iterator, const char *name)
{
  if (name)
    {
      gchar *quoted_name = sql_quote (name);
      init_iterator (iterator,
                     "SELECT name, value FROM nvt_preferences"
                     " WHERE name LIKE '%s[%%'"
                     " AND name != 'cache_folder'"
                     " AND name != 'include_folders'"
                     " AND name != 'nasl_no_signature_check'"
                     " AND name != 'ntp_save_sessions'"
                     " AND name NOT LIKE 'server_info_%'"
                     " ORDER BY name ASC",
                     quoted_name);
      g_free (quoted_name);
    }
  else
    init_iterator (iterator,
                   "SELECT name, value FROM nvt_preferences"
                   " WHERE name != 'cache_folder'"
                   " AND name != 'include_folders'"
                   " AND name != 'nasl_no_signature_check'"
                   " AND name != 'ntp_save_sessions'"
                   " AND name NOT LIKE 'server_info_%'"
                   " ORDER BY name ASC");
}

/**
 * @brief Get the name from an NVT preference iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_preference_iterator_name, 0);

/**
 * @brief Get the value from an NVT preference iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_preference_iterator_value, 1);

/**
 * @brief Get the real name from an NVT preference iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Real name.
 */
char*
nvt_preference_iterator_real_name (iterator_t* iterator)
{
  const char *ret;
  if (iterator->done) return NULL;
  ret = (const char*) sqlite3_column_text (iterator->stmt, 0);
  if (ret)
    {
      int value_start = -1, value_end = -1, count;
      /* LDAPsearch[entry]:Timeout value */
      count = sscanf (ret, "%*[^[][%*[^]]]:%n%*[ -~]%n", &value_start, &value_end);
      if (count == 0 && value_start > 0 && value_end > 0)
        {
          ret += value_start;
          return g_strndup (ret, value_end - value_start);
        }
      return g_strdup (ret);
    }
  return NULL;
}

/**
 * @brief Get the type from an NVT preference iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Type.
 */
char*
nvt_preference_iterator_type (iterator_t* iterator)
{
  const char *ret;
  if (iterator->done) return NULL;
  ret = (const char*) sqlite3_column_text (iterator->stmt, 0);
  if (ret)
    {
      int type_start = -1, type_end = -1, count;
      count = sscanf (ret, "%*[^[][%n%*[^]]%n]:", &type_start, &type_end);
      if (count == 0 && type_start > 0 && type_end > 0)
        {
          ret += type_start;
          return g_strndup (ret, type_end - type_start);
        }
      return NULL;
    }
  return NULL;
}

/**
 * @brief Get the NVT from an NVT preference iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return NVT.
 */
char*
nvt_preference_iterator_nvt (iterator_t* iterator)
{
  const char *ret;
  if (iterator->done) return NULL;
  ret = (const char*) sqlite3_column_text (iterator->stmt, 0);
  if (ret)
    {
      int type_start = -1, count;
      count = sscanf (ret, "%*[^[]%n[%*[^]]]:", &type_start);
      if (count == 0 && type_start > 0)
        {
          return g_strndup (ret, type_start);
        }
      return NULL;
    }
  return NULL;
}

/**
 * @brief Get the config value from an NVT preference iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  config    Config.
 *
 * @return Freshly allocated config value.
 */
char*
nvt_preference_iterator_config_value (iterator_t* iterator, config_t config)
{
  gchar *quoted_name, *value;
  const char *ret;
  if (iterator->done) return NULL;

  quoted_name = sql_quote ((const char *) sqlite3_column_text (iterator->stmt, 0));
  value = sql_string (0, 0,
                      "SELECT value FROM config_preferences"
                      " WHERE config = %llu"
                      " AND name = '%s'"
                      /* Ensure that the NVT pref comes first, in case an
                       * error in the GSA added the NVT pref as a Scanner
                       * pref. */
                      " ORDER BY type",
                      config,
                      quoted_name);
  g_free (quoted_name);
  if (value) return value;

  ret = (const char*) sqlite3_column_text (iterator->stmt, 1);
  if (ret) return g_strdup (ret);
  return NULL;
}

/**
 * @brief Get the number preferences available for an NVT.
 *
 * @param[in]  name  Name of NVT.
 *
 * @return Number of possible preferences on NVT.
 */
int
nvt_preference_count (const char *name)
{
  gchar *quoted_name = sql_quote (name);
  int ret = sql_int (0, 0,
                     "SELECT COUNT(*) FROM nvt_preferences"
                     " WHERE name LIKE '%s[%%';",
                     quoted_name);
  g_free (quoted_name);
  return ret;
}


/* LSC Credentials. */

/**
 * @brief Find an LSC credential given a UUID.
 *
 * @param[in]   uuid            UUID of LSC credential.
 * @param[out]  lsc_credential  LSC credential return, 0 if succesfully failed
 *                              to find credential.
 *
 * @return FALSE on success (including if failed to find LSC credential),
 *         TRUE on error.
 */
gboolean
find_lsc_credential (const char* uuid, lsc_credential_t* lsc_credential)
{
  gchar *quoted_uuid = sql_quote (uuid);
  if (user_owns_uuid ("lsc_credential", quoted_uuid) == 0)
    {
      g_free (quoted_uuid);
      *lsc_credential = 0;
      return FALSE;
    }
  switch (sql_int64 (lsc_credential, 0, 0,
                     "SELECT ROWID FROM lsc_credentials WHERE uuid = '%s';",
                     quoted_uuid))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *lsc_credential = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        g_free (quoted_uuid);
        return TRUE;
        break;
    }

  g_free (quoted_uuid);
  return FALSE;
}

/**
 * @brief Length of password generated in create_lsc_credential.
 */
#define PASSWORD_LENGTH 10

/**
 * @brief Create an LSC credential.
 *
 * @param[in]  name            Name of LSC credential.  Must be at least one
 *                             character long.
 * @param[in]  comment         Comment on LSC credential.
 * @param[in]  login           Name of LSC credential user.  Must be at least
 *                             one character long.
 * @param[in]  given_password  Password for password-only credential, NULL to
 *                             generate credentials.
 * @param[out] lsc_credential  Created LSC credential.
 *
 * @return 0 success, 1 LSC credential exists already, 2 name contains space,
 *         -1 error.
 */
int
create_lsc_credential (const char* name, const char* comment,
                       const char* login, const char* given_password,
                       lsc_credential_t *lsc_credential)
{
  gchar *quoted_name;
  gchar *public_key, *private_key;
  int i;
  GRand *rand;
  gchar password[PASSWORD_LENGTH];
  const char *s = login;

  assert (name && strlen (name) > 0);
  assert (login && strlen (login) > 0);
  assert (current_credentials.uuid);
  assert (comment);

  quoted_name = sql_quote (name);

  sql ("BEGIN IMMEDIATE;");

  if (sql_int (0, 0,
               "SELECT COUNT(*) FROM lsc_credentials WHERE name = '%s'"
               " AND ((owner IS NULL) OR (owner ="
               " (SELECT users.ROWID FROM users WHERE users.uuid = '%s')));",
               quoted_name,
               current_credentials.uuid))
    {
      g_free (quoted_name);
      sql ("ROLLBACK;");
      return 1;
    }

  if (given_password)
    {
      gchar *quoted_login = sql_quote (login);
      gchar *quoted_password = sql_quote (given_password);
      gchar *quoted_comment = sql_quote (comment);

      /* Password-only credential. */

      sql ("INSERT INTO lsc_credentials"
           " (uuid, name, owner, login, password, comment, public_key,"
           "  private_key, rpm, deb, exe)"
           " VALUES"
           " (make_uuid (), '%s',"
           "  (SELECT ROWID FROM users WHERE users.uuid = '%s'),"
           "  '%s', '%s', '%s', NULL, NULL, NULL, NULL, NULL);",
           quoted_name,
           current_credentials.uuid,
           quoted_login,
           quoted_password,
           quoted_comment);

      g_free (quoted_name);
      g_free (quoted_login);
      g_free (quoted_password);
      g_free (quoted_comment);

      if (lsc_credential)
        *lsc_credential = sqlite3_last_insert_rowid (task_db);

      sql ("COMMIT;");
      return 0;
    }

  /* Ensure the login is alphanumeric, to help the package generation. */

  while (*s)
    if (isalnum (*s))
      s++;
    else
      {
        g_free (quoted_name);
        sql ("ROLLBACK;");
        return 2;
      }

  /* Create the keys and packages. */

  rand = g_rand_new ();
  for (i = 0; i < PASSWORD_LENGTH - 1; i++)
    password[i] = (gchar) g_rand_int_range (rand, '0', 'z');
  password[PASSWORD_LENGTH - 1] = '\0';
  g_rand_free (rand);

  if (lsc_user_keys_create (login,
                            password,
                            &public_key,
                            &private_key))
    {
      g_free (quoted_name);
      sql ("ROLLBACK;");
      return -1;
    }

  {
    gchar *quoted_login = sql_quote (login);
    gchar *quoted_password = sql_quote (password);
    gchar *quoted_comment = sql_quote (comment);
    gchar *quoted_public_key = sql_quote (public_key);
    gchar *quoted_private_key = sql_quote (private_key);

    /* Password-only credential. */

    sql ("INSERT INTO lsc_credentials"
         " (uuid, name, owner, login, password, comment, public_key,"
         "  private_key, rpm, deb, exe)"
         " VALUES"
         " (make_uuid (), '%s',"
         "  (SELECT ROWID FROM users WHERE users.uuid = '%s'),"
         "  '%s', '%s', '%s', '%s', '%s', NULL, NULL, NULL);",
         quoted_name,
         current_credentials.uuid,
         quoted_login,
         quoted_password,
         quoted_comment,
         quoted_public_key,
         quoted_private_key);

    g_free (quoted_name);
    g_free (quoted_login);
    g_free (quoted_password);
    g_free (quoted_comment);
    g_free (quoted_public_key);
    g_free (quoted_private_key);
  }

  if (lsc_credential)
    *lsc_credential = sqlite3_last_insert_rowid (task_db);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Delete an LSC credential.
 *
 * @param[in]  lsc_credential  LSC credential.
 *
 * @return 0 success, 1 fail because the LSC credential is in use, -1 error.
 */
int
delete_lsc_credential (lsc_credential_t lsc_credential)
{
  sql ("BEGIN IMMEDIATE;");

  if (sql_int (0, 0,
               "SELECT count(*) FROM targets WHERE lsc_credential = %llu;",
               lsc_credential))
    {
      sql ("ROLLBACK;");
      return 1;
    }

  sql ("DELETE FROM lsc_credentials WHERE ROWID = %llu;", lsc_credential);
  sql ("COMMIT;");
  return 0;
}

/**
 * @brief Set the name of an LSC credential.
 *
 * @param[in]  lsc_credential  The LSC credential.
 * @param[in]  name            Name.
 */
void
set_lsc_credential_name (lsc_credential_t lsc_credential, const char *name)
{
  gchar *quoted_name = sql_quote (name);
  sql ("UPDATE lsc_credentials SET name = '%s' WHERE ROWID = %llu;",
       quoted_name,
       lsc_credential);
  g_free (quoted_name);
}

/**
 * @brief Set the comment of an LSC credential.
 *
 * @param[in]  lsc_credential  The LSC credential.
 * @param[in]  comment         Comment.
 */
void
set_lsc_credential_comment (lsc_credential_t lsc_credential,
                            const char *comment)
{
  gchar *quoted_comment = sql_quote (comment);
  sql ("UPDATE lsc_credentials SET comment = '%s' WHERE ROWID = %llu;",
       quoted_comment,
       lsc_credential);
  g_free (quoted_comment);
}

/**
 * @brief Set the login of an LSC credential.
 *
 * @param[in]  lsc_credential  The LSC credential.
 * @param[in]  login           Login.
 */
void
set_lsc_credential_login (lsc_credential_t lsc_credential, const char *login)
{
  gchar *quoted_login = sql_quote (login);
  sql ("UPDATE lsc_credentials SET login = '%s' WHERE ROWID = %llu;",
       quoted_login,
       lsc_credential);
  g_free (quoted_login);
}

/**
 * @brief Set the password of an LSC credential.
 *
 * @param[in]  lsc_credential  The LSC credential.
 * @param[in]  password        Password.
 */
void
set_lsc_credential_password (lsc_credential_t lsc_credential,
                             const char *password)
{
  gchar *quoted_password = sql_quote (password);
  sql ("UPDATE lsc_credentials SET password = '%s' WHERE ROWID = %llu;",
       quoted_password,
       lsc_credential);
  g_free (quoted_password);
}

/**
 * @brief Return whether an LSC credential is the packaged type.
 *
 * @param[in]  lsc_credential  The LSC credential.
 *
 * @return 0 false, else true.
 */
int
lsc_credential_packaged (lsc_credential_t lsc_credential)
{
  return sql_int (0, 0,
                  "SELECT public_key NOTNULL FROM lsc_credentials"
                  " WHERE ROWID = %llu;",
                  lsc_credential);
}

/**
 * @brief Initialise an LSC Credential iterator.
 *
 * @param[in]  iterator        Iterator.
 * @param[in]  lsc_credential  Single LSC credential to iterate, 0 for all.
 * @param[in]  ascending       Whether to sort ascending or descending.
 * @param[in]  sort_field      Field to sort on, or NULL for "ROWID".
 */
void
init_lsc_credential_iterator (iterator_t* iterator,
                              lsc_credential_t lsc_credential, int ascending,
                              const char* sort_field)
{
  assert (current_credentials.uuid);

  if (lsc_credential)
    init_iterator (iterator,
                   "SELECT ROWID, uuid, name, login, password, comment,"
                   " public_key, private_key, rpm, deb, exe,"
                   " (SELECT count(*) > 0 FROM targets"
                   "  WHERE lsc_credential = lsc_credentials.ROWID)"
                   " FROM lsc_credentials"
                   " WHERE ROWID = %llu"
                   " AND ((owner IS NULL) OR (owner ="
                   " (SELECT ROWID FROM users WHERE users.uuid = '%s')))"
                   " ORDER BY %s %s;",
                   lsc_credential,
                   current_credentials.uuid,
                   sort_field ? sort_field : "ROWID",
                   ascending ? "ASC" : "DESC");
  else
    init_iterator (iterator,
                   "SELECT ROWID, uuid, name, login, password, comment,"
                   " public_key, private_key, rpm, deb, exe,"
                   " (SELECT count(*) > 0 FROM targets"
                   "  WHERE lsc_credential = lsc_credentials.ROWID)"
                   " FROM lsc_credentials"
                   " WHERE ((owner IS NULL) OR (owner ="
                   " (SELECT ROWID FROM users WHERE users.uuid = '%s')))"
                   " ORDER BY %s %s;",
                   current_credentials.uuid,
                   sort_field ? sort_field : "ROWID",
                   ascending ? "ASC" : "DESC");
}

/**
 * @brief Get the LSC credential from an LSC credential iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return LSC credential.
 */
lsc_credential_t
lsc_credential_iterator_lsc_credential (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return (lsc_credential_t) sqlite3_column_int64 (iterator->stmt, 0);
}

/**
 * @brief Get the UUID from an LSC credential iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return UUID, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (lsc_credential_iterator_uuid, 1);

/**
 * @brief Get the name from an LSC credential iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (lsc_credential_iterator_name, 2);

/**
 * @brief Get the login from an LSC credential iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Login, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (lsc_credential_iterator_login, 3);

/**
 * @brief Get the password from an LSC credential iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Password, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (lsc_credential_iterator_password, 4);

/**
 * @brief Get the comment from an LSC credential iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return LSC credential.
 */
const char*
lsc_credential_iterator_comment (iterator_t* iterator)
{
  const char *ret;
  if (iterator->done) return "";
  ret = (const char*) sqlite3_column_text (iterator->stmt, 5);
  return ret ? ret : "";
}

/**
 * @brief Get the public_key from an LSC credential iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Public_key, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (lsc_credential_iterator_public_key, 6);

/**
 * @brief Get the private_key from an LSC credential iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Private_key, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (lsc_credential_iterator_private_key, 7);

/**
 * @brief Get the rpm from an LSC credential iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Rpm, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
const char*
lsc_credential_iterator_rpm (iterator_t *iterator)
{
  const char *public_key, *name;
  void *rpm;
  gsize rpm_size;
  gchar *rpm64;

  if (iterator->done) return NULL;

  public_key = (const char*) sqlite3_column_text (iterator->stmt, 6);
  name = (const char*) sqlite3_column_text (iterator->stmt, 3);
  if (lsc_user_rpm_recreate (name, public_key, &rpm, &rpm_size))
    return NULL;
  rpm64 = (rpm && rpm_size)
          ? g_base64_encode (rpm, rpm_size)
          : g_strdup ("");
  free (rpm);
  return rpm64;
}

/**
 * @brief Get the deb from an LSC credential iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Deb, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
const char*
lsc_credential_iterator_deb (iterator_t *iterator)
{
  const char *name, *public_key;
  void *deb, *rpm;
  gsize deb_size, rpm_size;
  gchar *deb64;

  if (iterator->done) return NULL;

  public_key = (const char*) sqlite3_column_text (iterator->stmt, 6);
  name = (const char*) sqlite3_column_text (iterator->stmt, 3);
  if (lsc_user_rpm_recreate (name, public_key, &rpm, &rpm_size))
    return NULL;

  if (lsc_user_deb_recreate (name, rpm, rpm_size, &deb, &deb_size))
    {
      free (rpm);
      return NULL;
    }
  free (rpm);
  deb64 = (deb && deb_size)
          ? g_base64_encode (deb, deb_size)
          : g_strdup ("");
  free (deb);
  return deb64;
}

/**
 * @brief Get the exe from an LSC credential iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Exe, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
const char*
lsc_credential_iterator_exe (iterator_t *iterator)
{
  const char *name, *password;
  void *exe;
  gsize exe_size;
  gchar *exe64;

  if (iterator->done) return NULL;

  name = (const char*) sqlite3_column_text (iterator->stmt, 3);
  password = (const char*) sqlite3_column_text (iterator->stmt, 4);
  if (lsc_user_exe_recreate (name, password, &exe, &exe_size))
    return NULL;
  exe64 = (exe && exe_size)
          ? g_base64_encode (exe, exe_size)
          : g_strdup ("");
  free (exe);
  return exe64;
}

/**
 * @brief Get the "in use" state from an LSC credential iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return "In use" flag.
 */
int
lsc_credential_iterator_in_use (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (int) sqlite3_column_int (iterator->stmt, 11);
  return ret;
}

/**
 * @brief Get the UUID of an LSC credential.
 *
 * @param[in]  lsc_credential  LSC credential.
 *
 * @return UUID.
 */
char*
lsc_credential_uuid (lsc_credential_t lsc_credential)
{
  return sql_string (0, 0,
                     "SELECT uuid FROM lsc_credentials WHERE ROWID = %llu;",
                     lsc_credential);
}

/**
 * @brief Get the name of an LSC credential.
 *
 * @param[in]  lsc_credential  LSC credential.
 *
 * @return Name.
 */
char*
lsc_credential_name (lsc_credential_t lsc_credential)
{
  return sql_string (0, 0,
                     "SELECT name FROM lsc_credentials WHERE ROWID = %llu;",
                     lsc_credential);
}

/**
 * @brief Initialise an LSC credential target iterator.
 *
 * Iterates over all targets that use the credential.
 *
 * @param[in]  iterator        Iterator.
 * @param[in]  lsc_credential  Name of LSC credential.
 * @param[in]  ascending       Whether to sort ascending or descending.
 */
void
init_lsc_credential_target_iterator (iterator_t* iterator,
                                     lsc_credential_t lsc_credential,
                                     int ascending)
{
  init_iterator (iterator,
                 "SELECT uuid, name FROM targets"
                 " WHERE lsc_credential = %llu OR smb_lsc_credential = %llu"
                 " ORDER BY name %s;",
                 lsc_credential,
                 lsc_credential,
                 ascending ? "ASC" : "DESC");
}

/**
 * @brief Get the uuid from an LSC credential_target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Uuid, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (lsc_credential_target_iterator_uuid, 0);

/**
 * @brief Get the name from an LSC credential_target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (lsc_credential_target_iterator_name, 1);


/* Agents. */

/**
 * @brief Find an agent given a name.
 *
 * @param[in]   uuid   UUID of agent.
 * @param[out]  agent  Agent return, 0 if succesfully failed to find agent.
 *
 * @return FALSE on success (including if failed to find agent), TRUE on error.
 */
gboolean
find_agent (const char* uuid, agent_t* agent)
{
  gchar *quoted_uuid = sql_quote (uuid);
  if (user_owns_uuid ("agent", quoted_uuid) == 0)
    {
      g_free (quoted_uuid);
      *agent = 0;
      return FALSE;
    }
  switch (sql_int64 (agent, 0, 0,
                     "SELECT ROWID FROM agents WHERE uuid = '%s';",
                     quoted_uuid))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *agent = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        g_free (quoted_uuid);
        return TRUE;
        break;
    }

  g_free (quoted_uuid);
  return FALSE;
}

/**
 * @brief Find a signature in a feed.
 *
 * @param[in]   location            Feed directory to search for signature.
 * @param[in]   installer_filename  Installer filename.
 * @param[out]  signature           Freshly allocated installer signature.
 * @param[out]  signature_size      Size of installer signature.
 *
 * @return 0 success, -1 error.
 */
static int
find_signature (const gchar *location, const gchar *installer_filename,
                gchar **signature, gsize *signature_size)
{
  gchar *installer_basename = g_path_get_basename (installer_filename);

  if (strlen (installer_basename))
    {
      gchar *signature_filename, *signature_basename;
      GError *error = NULL;

      signature_basename  = g_strdup_printf ("%s.asc", installer_basename);
      g_free (installer_basename);
      signature_filename = g_build_filename (OPENVAS_LIB_INSTALL_DIR,
                                             "openvas",
                                             "plugins",
                                             location,
                                             signature_basename,
                                             NULL);
      g_free (signature_basename);

      tracef ("signature_filename: %s\n", signature_filename);

      g_file_get_contents (signature_filename, signature, signature_size,
                           &error);
      g_free (signature_filename);
      if (error)
        {
          g_error_free (error);
          return -1;
        }
      return 0;
    }

  g_free (installer_basename);
  return -1;
}

/**
 * @brief Execute gpg to verify an installer signature.
 *
 * @param[in]  installer       Installer.
 * @param[in]  installer_size  Size of installer.
 * @param[in]  signature       Installer signature.
 * @param[in]  signature_size  Size of installer signature.
 * @param[out] trust           Trust value.
 *
 * @return 0 success, -1 error.
 */
static int
verify_signature (const gchar *installer, gsize installer_size,
                  const gchar *signature, gsize signature_size,
                  int *trust)
{
  gchar **cmd;
  gint exit_status;
  int ret = 0, installer_fd, signature_fd;
  gchar *standard_out = NULL;
  gchar *standard_err = NULL;
  char installer_file[] = "/tmp/openvasmd-installer-XXXXXX";
  char signature_file[] = "/tmp/openvasmd-signature-XXXXXX";
  GError *error = NULL;

  installer_fd = mkstemp (installer_file);
  if (installer_fd == -1)
    return -1;

  g_file_set_contents (installer_file, installer, installer_size, &error);
  if (error)
    {
      g_warning ("%s", error->message);
      g_error_free (error);
      close (installer_fd);
      return -1;
    }

  signature_fd = mkstemp (signature_file);
  if (signature_fd == -1)
    {
      close (installer_fd);
      return -1;
    }

  g_file_set_contents (signature_file, signature, signature_size, &error);
  if (error)
    {
      g_warning ("%s", error->message);
      g_error_free (error);
      close (installer_fd);
      close (signature_fd);
      return -1;
    }

  cmd = (gchar **) g_malloc (8 * sizeof (gchar *));

  cmd[0] = g_strdup ("gpg");
  cmd[1] = g_strdup ("--batch");
  cmd[2] = g_strdup ("--quiet");
  cmd[3] = g_strdup ("--no-tty");
  cmd[4] = g_strdup ("--verify");
  cmd[5] = g_strdup (signature_file);
  cmd[6] = g_strdup (installer_file);
  cmd[7] = NULL;
  g_debug ("%s: Spawning in /tmp/: %s %s %s %s %s %s %s\n",
           __FUNCTION__,
           cmd[0], cmd[1], cmd[2], cmd[3], cmd[4], cmd[5], cmd[6]);
  if ((g_spawn_sync ("/tmp/",
                     cmd,
                     NULL,                 /* Environment. */
                     G_SPAWN_SEARCH_PATH,
                     NULL,                 /* Setup func. */
                     NULL,
                     &standard_out,
                     &standard_err,
                     &exit_status,
                     NULL) == FALSE)
      || (WIFEXITED (exit_status) == 0)
      || WEXITSTATUS (exit_status))
    {
      if (WEXITSTATUS (exit_status) == 1)
        *trust = TRUST_NO;
      else
        {
#if 0
          g_debug ("%s: failed to run gpg --verify: %d (WIF %i, WEX %i)",
                   __FUNCTION__,
                   exit_status,
                   WIFEXITED (exit_status),
                   WEXITSTATUS (exit_status));
          g_debug ("%s: stdout: %s\n", __FUNCTION__, standard_out);
          g_debug ("%s: stderr: %s\n", __FUNCTION__, standard_err);
          ret = -1;
#endif
          /* This can be caused by the contents of the signature file, so
           * always return success. */
          *trust = TRUST_UNKNOWN;
        }
    }
  else
    *trust = TRUST_YES;

  g_free (cmd[0]);
  g_free (cmd[1]);
  g_free (cmd[2]);
  g_free (cmd[3]);
  g_free (cmd[4]);
  g_free (cmd[5]);
  g_free (cmd[6]);
  g_free (cmd);
  g_free (standard_out);
  g_free (standard_err);
  close (installer_fd);
  close (signature_fd);

  return ret;
}

/**
 * @brief Create an agent entry.
 *
 * @param[in]  name           Name of agent.  Must be at least one character long.
 * @param[in]  comment        Comment on agent.
 * @param[in]  installer_64   Installer, in base64.
 * @param[in]  installer_filename   Installer filename.
 * @param[in]  installer_signature_64   Installer signature, in base64.
 * @param[in]  howto_install  Install HOWTO, in base64.
 * @param[in]  howto_use      Usage HOWTO, in base64.
 * @param[out] agent          Created agent.
 *
 * @return 0 success, 1 agent exists already, -1 error.
 */
int
create_agent (const char* name, const char* comment, const char* installer_64,
              const char* installer_filename, const char* installer_signature_64,
              const char* howto_install, const char* howto_use, agent_t *agent)
{
  gchar *quoted_name = sql_nquote (name, strlen (name));
  gchar *quoted_comment, *installer, *installer_signature;
  int installer_trust = TRUST_UNKNOWN;
  gsize installer_size = 0, installer_signature_size = 0;

  assert (strlen (name) > 0);
  assert (installer_64);
  assert (installer_filename);
  assert (installer_signature_64);
  assert (current_credentials.uuid);

  /* Translate the installer and signature. */

  if (strlen (installer_64))
    installer = (gchar*) g_base64_decode (installer_64, &installer_size);
  else
    installer = g_strdup ("");

  if (strlen (installer_signature_64))
    installer_signature = (gchar*) g_base64_decode (installer_signature_64,
                                                    &installer_signature_size);
  else
    installer_signature = g_strdup ("");

  /* Verify the installer signature. */

  if (strlen (installer_signature))
    {
      if (verify_signature (installer, installer_size, installer_signature,
                            installer_signature_size, &installer_trust))
        {
          g_free (installer);
          g_free (installer_signature);
          return -1;
        }
    }
  else
    {
      g_free (installer_signature);

      if (find_signature ("agents", installer_filename, &installer_signature,
                          &installer_signature_size)
          == 0)
        {
          if (verify_signature (installer, installer_size, installer_signature,
                                installer_signature_size, &installer_trust))
            {
              g_free (installer);
              g_free (installer_signature);
              return -1;
            }
        }
    }

  /* Check that the name is unique. */

  sql ("BEGIN IMMEDIATE;");

  if (sql_int (0, 0,
               "SELECT COUNT(*) FROM agents WHERE name = '%s'"
               " AND ((owner IS NULL) OR (owner ="
               " (SELECT users.ROWID FROM users WHERE users.uuid = '%s')));",
               quoted_name,
               current_credentials.uuid))
    {
      g_free (quoted_name);
      g_free (installer);
      g_free (installer_signature);
      sql ("ROLLBACK;");
      return 1;
    }

  /* Insert the packages. */

  {
    const char* tail;
    int ret;
    sqlite3_stmt* stmt;
    gchar* formatted;
    gchar* quoted_filename = sql_quote (installer_filename);

    if (comment)
      {
        quoted_comment = sql_nquote (comment, strlen (comment));
        formatted = g_strdup_printf ("INSERT INTO agents"
                                     " (uuid, name, owner, comment, installer,"
                                     "  installer_64, installer_filename,"
                                     "  installer_signature_64,"
                                     "  installer_trust, installer_trust_time,"
                                     "  howto_install, howto_use)"
                                     " VALUES"
                                     " (make_uuid (), '%s',"
                                     "  (SELECT ROWID FROM users"
                                     "   WHERE users.uuid = '%s'),"
                                     "  '%s',"
                                     "  $installer, $installer_64,"
                                     "  '%s',"
                                     "  $installer_signature_64,"
                                     "  %i, %i, $howto_install,"
                                     "  $howto_use);",
                                     quoted_name,
                                     current_credentials.uuid,
                                     quoted_comment,
                                     quoted_filename,
                                     installer_trust,
                                     (int) time (NULL));
        g_free (quoted_comment);
      }
    else
      {
        formatted = g_strdup_printf ("INSERT INTO agents"
                                     " (uuid, name, owner, comment, installer,"
                                     "  installer_64, installer_filename,"
                                     "  installer_signature_64,"
                                     "  installer_trust, howto_install,"
                                     "  howto_use)"
                                     " VALUES"
                                     " (make_uuid (), '%s',"
                                     "  (SELECT ROWID FROM users"
                                     "   WHERE users.uuid = '%s'),"
                                     "  '',"
                                     "  $installer, $installer_64,"
                                     "  '%s',"
                                     "  $installer_signature_64,"
                                     "  %i, %i, $howto_install,"
                                     "  $howto_use);",
                                     quoted_name,
                                     current_credentials.uuid,
                                     quoted_filename,
                                     installer_trust,
                                     (int) time (NULL));
      }

    g_free (quoted_name);
    g_free (quoted_filename);

    tracef ("   sql: %s\n", formatted);

    /* Prepare statement. */

    while (1)
      {
        ret = sqlite3_prepare (task_db, (char*) formatted, -1, &stmt, &tail);
        if (ret == SQLITE_BUSY) continue;
        g_free (formatted);
        if (ret == SQLITE_OK)
          {
            if (stmt == NULL)
              {
                g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s\n",
                           __FUNCTION__,
                           sqlite3_errmsg (task_db));
                g_free (installer);
                g_free (installer_signature);
                sql ("ROLLBACK;");
                return -1;
              }
            break;
          }
        g_warning ("%s: sqlite3_prepare failed: %s\n",
                   __FUNCTION__,
                   sqlite3_errmsg (task_db));
        g_free (installer);
        g_free (installer_signature);
        sql ("ROLLBACK;");
        return -1;
      }

    /* Bind the packages to the "$values" in the SQL statement. */

    while (1)
      {
        ret = sqlite3_bind_text (stmt,
                                 1,
                                 installer,
                                 installer_size,
                                 SQLITE_TRANSIENT);
        if (ret == SQLITE_BUSY) continue;
        if (ret == SQLITE_OK) break;
        g_warning ("%s: sqlite3_prepare failed: %s\n",
                   __FUNCTION__,
                   sqlite3_errmsg (task_db));
        sql ("ROLLBACK;");
        g_free (installer);
        g_free (installer_signature);
        return -1;
      }
    g_free (installer);

    while (1)
      {
        ret = sqlite3_bind_text (stmt,
                                 2,
                                 installer_64,
                                 strlen (installer_64),
                                 SQLITE_TRANSIENT);
        if (ret == SQLITE_BUSY) continue;
        if (ret == SQLITE_OK) break;
        g_warning ("%s: sqlite3_prepare failed: %s\n",
                   __FUNCTION__,
                   sqlite3_errmsg (task_db));
        sql ("ROLLBACK;");
        g_free (installer_signature);
        return -1;
      }
    g_free (installer_signature);

    while (1)
      {
        ret = sqlite3_bind_text (stmt,
                                 3,
                                 installer_signature_64,
                                 strlen (installer_signature_64),
                                 SQLITE_TRANSIENT);
        if (ret == SQLITE_BUSY) continue;
        if (ret == SQLITE_OK) break;
        g_warning ("%s: sqlite3_prepare failed: %s\n",
                   __FUNCTION__,
                   sqlite3_errmsg (task_db));
        sql ("ROLLBACK;");
        return -1;
      }

    while (1)
      {
        ret = sqlite3_bind_text (stmt,
                                 4,
                                 howto_install,
                                 strlen (howto_install),
                                 SQLITE_TRANSIENT);
        if (ret == SQLITE_BUSY) continue;
        if (ret == SQLITE_OK) break;
        g_warning ("%s: sqlite3_prepare failed: %s\n",
                   __FUNCTION__,
                   sqlite3_errmsg (task_db));
        sql ("ROLLBACK;");
        return -1;
      }

    while (1)
      {
        ret = sqlite3_bind_blob (stmt,
                                 5,
                                 howto_use,
                                 strlen (howto_use),
                                 SQLITE_TRANSIENT);
        if (ret == SQLITE_BUSY) continue;
        if (ret == SQLITE_OK) break;
        g_warning ("%s: sqlite3_prepare failed: %s\n",
                   __FUNCTION__,
                   sqlite3_errmsg (task_db));
        sql ("ROLLBACK;");
        return -1;
      }

    /* Run the statement. */

    while (1)
      {
        ret = sqlite3_step (stmt);
        if (ret == SQLITE_BUSY) continue;
        if (ret == SQLITE_DONE) break;
        if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
          {
            if (ret == SQLITE_ERROR) ret = sqlite3_reset (stmt);
            g_warning ("%s: sqlite3_step failed: %s\n",
                       __FUNCTION__,
                       sqlite3_errmsg (task_db));
            sql ("ROLLBACK;");
            return -1;
          }
      }

    sqlite3_finalize (stmt);
  }

  if (agent)
    *agent = sqlite3_last_insert_rowid (task_db);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Delete an agent.
 *
 * @param[in]  agent  Agent.
 *
 * @return 0 success, -1 error.
 */
int
delete_agent (agent_t agent)
{
  sql ("DELETE FROM agents WHERE ROWID = %llu;", agent);
  return 0;
}

/**
 * @brief Verify an agent.
 *
 * @param[in]  agent  Agent.
 *
 * @return 0 success, -1 error.
 */
int
verify_agent (agent_t agent)
{
  int agent_trust = TRUST_UNKNOWN;
  iterator_t agents;

  sql ("BEGIN IMMEDIATE;");

  init_agent_iterator (&agents, agent, 1, NULL);
  if (next (&agents))
    {
      const char *signature_64;
      gchar *agent_signature = NULL;
      gsize agent_signature_size;

      signature_64 = agent_iterator_installer_signature_64 (&agents);

      find_signature ("agents",
                      agent_iterator_installer_filename (&agents),
                      &agent_signature,
                      &agent_signature_size);

      if ((signature_64 && strlen (signature_64))
          || agent_signature)
        {
          const char *installer;
          gsize installer_size;

          installer = agent_iterator_installer (&agents);
          installer_size = agent_iterator_installer_size (&agents);

          if (signature_64 && strlen (signature_64))
            {
              gchar *signature;
              gsize signature_length;

              /* Try the signature from the database. */

              signature = (gchar*) g_base64_decode (signature_64,
                                                    &signature_length);

              if (verify_signature (installer, installer_size, signature,
                                    signature_length, &agent_trust))
                {
                  cleanup_iterator (&agents);
                  g_free (agent_signature);
                  sql ("ROLLBACK;");
                  return -1;
                }
            }

          /* If the database signature is empty or the database
           * signature is bad, and there is a feed signature, then
           * try the feed signature. */
          if (((agent_trust == TRUST_NO)
               || (agent_trust == TRUST_UNKNOWN))
              && agent_signature)
            {
              if (verify_signature (installer, installer_size, agent_signature,
                                    strlen (agent_signature), &agent_trust))
                {
                  cleanup_iterator (&agents);
                  g_free (agent_signature);
                  sql ("ROLLBACK;");
                  return -1;
                }

              if (agent_trust == TRUST_YES)
                {
                  gchar *quoted_signature, *base64;
                  base64 = (strlen (agent_signature)
                            ? g_base64_encode ((guchar*) agent_signature,
                                               agent_signature_size)
                            : g_strdup (""));
                  quoted_signature = sql_quote (base64);
                  g_free (base64);
                  sql ("UPDATE agents SET installer_signature_64 = '%s'"
                       " WHERE ROWID = %llu;",
                       quoted_signature,
                       agent);
                  g_free (quoted_signature);
                }
            }
          g_free (agent_signature);
        }
    }
  else
    {
      cleanup_iterator (&agents);
      sql ("ROLLBACK;");
      return -1;
    }
  cleanup_iterator (&agents);

  sql ("UPDATE agents SET installer_trust = %i, installer_trust_time = %i"
       " WHERE ROWID = %llu;",
       agent_trust,
       time (NULL),
       agent);
  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Return the UUID of a agent.
 *
 * @param[in]   agent  Agent.
 * @param[out]  id     Pointer to a newly allocated string.
 *
 * @return 0.
 */
int
agent_uuid (agent_t agent, char ** id)
{
  *id = sql_string (0, 0,
                    "SELECT uuid FROM agents WHERE ROWID = %llu;",
                    agent);
  return 0;
}

/**
 * @brief Initialise an agent iterator.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  agent       Single agent to iterate, 0 for all.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for "ROWID".
 */
void
init_agent_iterator (iterator_t* iterator, agent_t agent,
                     int ascending, const char* sort_field)
{
  assert (current_credentials.uuid);

  if (agent)
    init_iterator (iterator,
                   "SELECT uuid, name, comment, installer, installer_64,"
                   " installer_filename, installer_signature_64,"
                   " installer_trust, installer_trust_time, howto_install,"
                   " howto_use"
                   " FROM agents"
                   " WHERE ROWID = %llu"
                   " AND ((owner IS NULL) OR (owner ="
                   " (SELECT ROWID FROM users WHERE users.uuid = '%s')))"
                   " ORDER BY %s %s;",
                   agent,
                   current_credentials.uuid,
                   sort_field ? sort_field : "ROWID",
                   ascending ? "ASC" : "DESC");
  else
    init_iterator (iterator,
                   "SELECT uuid, name, comment, installer, installer_64,"
                   " installer_filename, installer_signature_64,"
                   " installer_trust, installer_trust_time, howto_install,"
                   " howto_use"
                   " FROM agents"
                   " WHERE ((owner IS NULL) OR (owner ="
                   " (SELECT ROWID FROM users WHERE users.uuid = '%s')))"
                   " ORDER BY %s %s;",
                   current_credentials.uuid,
                   sort_field ? sort_field : "ROWID",
                   ascending ? "ASC" : "DESC");
}

/**
 * @brief Get the UUID from an agent iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return UUID, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (agent_iterator_uuid, 0);

/**
 * @brief Get the name from an agent iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (agent_iterator_name, 1);

/**
 * @brief Get the comment from an agent iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Comment.
 */
const char*
agent_iterator_comment (iterator_t* iterator)
{
  const char *ret;
  if (iterator->done) return "";
  ret = (const char*) sqlite3_column_text (iterator->stmt, 2);
  return ret ? ret : "";
}

/**
 * @brief Get the installer from an agent iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Installer, or NULL if iteration is complete.  Freed
 *         by cleanup_iterator.
 */
DEF_ACCESS (agent_iterator_installer, 3);

/**
 * @brief Get the installer_64 from an agent iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Base 64 encoded installer, or NULL if iteration is complete.  Freed
 *         by cleanup_iterator.
 */
DEF_ACCESS (agent_iterator_installer_64, 4);

/**
 * @brief Get the installer size from an agent iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Installer size, or NULL if iteration is complete.  Freed
 *         by cleanup_iterator.
 */
gsize
agent_iterator_installer_size (iterator_t* iterator)
{
  const char *installer_64;
  gsize installer_size;

  installer_64 = agent_iterator_installer_64 (iterator);
  if (installer_64 && strlen (installer_64))
    {
      gchar *installer;
      installer = (gchar*) g_base64_decode ((gchar*) installer_64,
                                            &installer_size);
      g_free (installer);
      return installer_size;
    }
  return 0;
}

/**
 * @brief Get the installer_filename from an agent iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Installer filename, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (agent_iterator_installer_filename, 5);

/**
 * @brief Get the installer_signature_64 from an agent iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Installer signature in base64, or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (agent_iterator_installer_signature_64, 6);

/**
 * @brief Get the trust value from an agent iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Trust value.
 */
const char*
agent_iterator_trust (iterator_t* iterator)
{
  if (iterator->done) return NULL;
  switch (sqlite3_column_int (iterator->stmt, 7))
    {
      case 1:  return "yes";
      case 2:  return "no";
      case 3:  return "unknown";
      default: return NULL;
    }
}

/**
 * @brief Get the installer trust time from a agent iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Time agent installer was verified.
 */
time_t
agent_iterator_trust_time (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (time_t) sqlite3_column_int (iterator->stmt, 8);
  return ret;
}

/**
 * @brief Get the install HOWTO from an agent iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Install HOWTO, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (agent_iterator_howto_install, 9);

/**
 * @brief Get the usage HOWTO from an agent iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Usage HOWTO, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (agent_iterator_howto_use, 10);

/**
 * @brief Get the name of an agent.
 *
 * @param[in]  agent  Agent.
 *
 * @return Name.
 */
char*
agent_name (agent_t agent)
{
  return sql_string (0, 0,
                     "SELECT name FROM agents WHERE ROWID = %llu;",
                     agent);
}


/* Notes. */

/**
 * @brief Find a note given a UUID.
 *
 * @param[in]   uuid  UUID of note.
 * @param[out]  note  Note return, 0 if succesfully failed to find note.
 *
 * @return FALSE on success (including if failed to find note), TRUE on error.
 */
gboolean
find_note (const char* uuid, note_t* note)
{
  gchar *quoted_uuid = sql_quote (uuid);
  if (user_owns_uuid ("note", quoted_uuid) == 0)
    {
      g_free (quoted_uuid);
      *note = 0;
      return FALSE;
    }
  switch (sql_int64 (note, 0, 0,
                     "SELECT ROWID FROM notes WHERE uuid = '%s';",
                     quoted_uuid))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *note = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        g_free (quoted_uuid);
        return TRUE;
        break;
    }

  g_free (quoted_uuid);
  return FALSE;
}

/**
 * @brief Create a note.
 *
 * @param[in]  nvt         OID of noted NVT.
 * @param[in]  text        Note text.
 * @param[in]  hosts       Hosts to apply note to, NULL for any host.
 * @param[in]  port        Port to apply note to, NULL for any port.
 * @param[in]  threat      Threat to apply note to, "" or NULL for any threat.
 * @param[in]  task        Task to apply note to, 0 for any task.
 * @param[in]  result      Result to apply note to, 0 for any result.
 * @param[out] note        Created note.
 *
 * @return 0 success, -1 error.
 */
int
create_note (const char* nvt, const char* text, const char* hosts,
             const char* port, const char* threat, task_t task,
             result_t result, note_t *note)
{
  gchar *quoted_text, *quoted_hosts, *quoted_port, *quoted_threat;

  if (nvt == NULL)
    return -1;

  if (text == NULL)
    return -1;

  if (threat && strcmp (threat, "High") && strcmp (threat, "Medium")
      && strcmp (threat, "Low") && strcmp (threat, "Log")
      && strcmp (threat, "Debug") && strcmp (threat, ""))
    return -1;

  quoted_text = sql_insert (text);
  quoted_hosts = sql_insert (hosts);
  quoted_port = sql_insert (port);
  quoted_threat = sql_insert ((threat && strlen (threat))
                                ? threat_message_type (threat) : NULL);

  sql ("INSERT INTO notes"
       " (uuid, owner, nvt, creation_time, modification_time, text, hosts,"
       "  port, threat, task, result)"
       " VALUES"
       " (make_uuid (), (SELECT ROWID FROM users WHERE users.uuid = '%s'),"
       "  '%s', %i, %i, %s, %s, %s, %s, %llu, %llu);",
       current_credentials.uuid,
       nvt,
       time (NULL),
       time (NULL),
       quoted_text,
       quoted_hosts,
       quoted_port,
       quoted_threat,
       task,
       result);

  g_free (quoted_text);
  g_free (quoted_hosts);
  g_free (quoted_port);
  g_free (quoted_threat);

  if (note)
    *note = sqlite3_last_insert_rowid (task_db);

  return 0;
}

/**
 * @brief Delete a note.
 *
 * @param[in]  note  Note.
 *
 * @return 0 success.
 */
int
delete_note (note_t note)
{
  sql ("DELETE FROM notes WHERE ROWID = %llu;", note);
  return 0;
}

/**
 * @brief Return the UUID of a note.
 *
 * @param[in]   note  Note.
 * @param[out]  id    Pointer to a newly allocated string.
 *
 * @return 0.
 */
int
note_uuid (note_t note, char ** id)
{
  *id = sql_string (0, 0,
                    "SELECT uuid FROM notes WHERE ROWID = %llu;",
                    note);
  return 0;
}

/**
 * @brief Modify a note.
 *
 * @param[in]  note        Note.
 * @param[in]  text        Note text.
 * @param[in]  hosts       Hosts to apply note to, NULL for any host.
 * @param[in]  port        Port to apply note to, NULL for any port.
 * @param[in]  threat      Threat to apply note to, "" or NULL for any threat.
 * @param[in]  task        Task to apply note to, 0 for any task.
 * @param[in]  result      Result to apply note to, 0 for any result.
 *
 * @return 0 success, -1 error.
 */
int
modify_note (note_t note, const char* text, const char* hosts,
             const char* port, const char* threat, task_t task,
             result_t result)
{
  gchar *quoted_text, *quoted_hosts, *quoted_port, *quoted_threat;

  if (note == 0)
    return -1;

  if (text == NULL)
    return -1;

  if (threat && strcmp (threat, "High") && strcmp (threat, "Medium")
      && strcmp (threat, "Low") && strcmp (threat, "Log")
      && strcmp (threat, "Debug") && strcmp (threat, ""))
    return -1;

  quoted_text = sql_insert (text);
  quoted_hosts = sql_insert (hosts);
  quoted_port = sql_insert (port);
  quoted_threat = sql_insert ((threat && strlen (threat))
                                ? threat_message_type (threat) : NULL);

  sql ("UPDATE notes SET"
       " modification_time = %i,"
       " text = %s,"
       " hosts = %s,"
       " port = %s,"
       " threat = %s,"
       " task = %llu,"
       " result = %llu"
       " WHERE ROWID = %llu;",
       time (NULL),
       quoted_text,
       quoted_hosts,
       quoted_port,
       quoted_threat,
       task,
       result,
       note);

  g_free (quoted_text);
  g_free (quoted_hosts);
  g_free (quoted_port);
  g_free (quoted_threat);

  return 0;
}

/**
 * @brief Database columns used in note iterators.
 */
#define NOTE_COLUMNS "notes.ROWID, notes.uuid, notes.nvt,"                 \
                     " notes.creation_time, notes.modification_time,"      \
                     " notes.text, notes.hosts, notes.port, notes.threat," \
                     " notes.task, notes.result"

/**
 * @brief Initialise a note iterator.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  note        Single note to iterate, 0 for all.
 * @param[in]  result      Result to limit notes to, 0 for all.
 * @param[in]  task        If result is > 0, task whose notes on result to
 *                         include, otherwise task to limit notes to.  0 for
 *                         all tasks.
 * @param[in]  nvt         NVT to limit notes to, 0 for all.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for "ROWID".
 */
void
init_note_iterator (iterator_t* iterator, note_t note, nvt_t nvt,
                    result_t result, task_t task, int ascending,
                    const char* sort_field)
{
  gchar *result_clause, *join_clause = NULL;

  assert (current_credentials.uuid);
  assert ((nvt && note) == 0);
  assert ((task && note) == 0);

  if (result)
    result_clause = g_strdup_printf (" AND"
                                     " (result = %llu"
                                     "  OR (result = 0 AND nvt ="
                                     "      (SELECT results.nvt FROM results"
                                     "       WHERE results.ROWID = %llu)))"
                                     " AND (hosts is NULL"
                                     "      OR hosts = \"\""
                                     "      OR hosts_contains (hosts,"
                                     "      (SELECT results.host FROM results"
                                     "       WHERE results.ROWID = %llu)))"
                                     " AND (port is NULL"
                                     "      OR port = \"\""
                                     "      OR port ="
                                     "      (SELECT results.port FROM results"
                                     "       WHERE results.ROWID = %llu))"
                                     " AND (threat is NULL"
                                     "      OR threat = \"\""
                                     "      OR threat ="
                                     "      (SELECT results.type FROM results"
                                     "       WHERE results.ROWID = %llu))"
                                     " AND (task = 0 OR task = %llu)",
                                     result,
                                     result,
                                     result,
                                     result,
                                     result,
                                     task);
  else if (task)
    {
      result_clause = g_strdup_printf
                       (" AND (notes.task = %llu OR notes.task = 0)"
                        " AND reports.task = %llu"
                        " AND reports.ROWID = report_results.report"
                        " AND report_results.result = results.ROWID"
                        " AND results.nvt = notes.nvt"
                        " AND"
                        " (notes.result = 0"
                        "  OR report_results.result = notes.result)",
                        task,
                        task);
      join_clause = g_strdup (", reports, report_results, results");
    }
  else
    result_clause = NULL;

  if (note)
    init_iterator (iterator,
                   "SELECT " NOTE_COLUMNS
                   " FROM notes"
                   " WHERE ROWID = %llu"
                   " AND ((owner IS NULL) OR (owner ="
                   " (SELECT ROWID FROM users WHERE users.uuid = '%s')))"
                   "%s"
                   " ORDER BY %s %s;",
                   note,
                   current_credentials.uuid,
                   result_clause ? result_clause : "",
                   sort_field ? sort_field : "ROWID",
                   ascending ? "ASC" : "DESC");
  else if (nvt)
    init_iterator (iterator,
                   "SELECT DISTINCT " NOTE_COLUMNS
                   " FROM notes%s"
                   " WHERE (notes.nvt ="
                   " (SELECT oid FROM nvts WHERE nvts.ROWID = %llu))"
                   " AND ((notes.owner IS NULL) OR (notes.owner ="
                   " (SELECT ROWID FROM users WHERE users.uuid = '%s')))"
                   "%s"
                   " ORDER BY %s %s;",
                   join_clause ? join_clause : "",
                   nvt,
                   current_credentials.uuid,
                   result_clause ? result_clause : "",
                   sort_field ? sort_field : "notes.ROWID",
                   ascending ? "ASC" : "DESC");
  else
    init_iterator (iterator,
                   "SELECT DISTINCT " NOTE_COLUMNS
                   " FROM notes%s"
                   " WHERE ((notes.owner IS NULL) OR (notes.owner ="
                   " (SELECT ROWID FROM users WHERE users.uuid = '%s')))"
                   "%s"
                   " ORDER BY %s %s;",
                   join_clause ? join_clause : "",
                   current_credentials.uuid,
                   result_clause ? result_clause : "",
                   sort_field ? sort_field : "notes.ROWID",
                   ascending ? "ASC" : "DESC");

  g_free (result_clause);
  g_free (join_clause);
}

/**
 * @brief Get the uuid from a note iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return UUID, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (note_iterator_uuid, 1);

/**
 * @brief Get the NVT OID from a note iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return NVT OID, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (note_iterator_nvt_oid, 2);

/**
 * @brief Get the creation time from a note iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Time note was created.
 */
time_t
note_iterator_creation_time (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (time_t) sqlite3_column_int (iterator->stmt, 3);
  return ret;
}

/**
 * @brief Get the modification time from a note iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Time note was last modified.
 */
time_t
note_iterator_modification_time (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (time_t) sqlite3_column_int (iterator->stmt, 4);
  return ret;
}

/**
 * @brief Get the text from a note iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Text, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (note_iterator_text, 5);

/**
 * @brief Get the hosts from a note iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Hosts, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (note_iterator_hosts, 6);

/**
 * @brief Get the port from a note iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Port, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (note_iterator_port, 7);

/**
 * @brief Get the threat from a note iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Threat.
 */
const char *
note_iterator_threat (iterator_t *iterator)
{
  const char *ret;
  if (iterator->done) return NULL;
  ret = (const char*) sqlite3_column_text (iterator->stmt, 8);
  if (ret == NULL) return NULL;
  return message_type_threat (ret);
}

/**
 * @brief Get the task from a note iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The task associated with the note, or 0 on error.
 */
task_t
note_iterator_task (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return (task_t) sqlite3_column_int64 (iterator->stmt, 9);
}

/**
 * @brief Get the result from a note iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The result associated with the note, or 0 on error.
 */
result_t
note_iterator_result (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return (result_t) sqlite3_column_int64 (iterator->stmt, 10);
}

/**
 * @brief Get the NVT name from a note iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The name of the NVT associated with the note, or NULL on error.
 */
const char*
note_iterator_nvt_name (iterator_t *iterator)
{
  nvti_t *nvti;
  if (iterator->done) return NULL;
  nvti = nvtis_lookup (nvti_cache, note_iterator_nvt_oid (iterator));
  if (nvti)
    return nvti_name (nvti);
  return NULL;
}


/* Overrides. */

/**
 * @brief Find an override given a UUID.
 *
 * @param[in]   uuid  UUID of override.
 * @param[out]  override  Override return, 0 if succesfully failed to find override.
 *
 * @return FALSE on success (including if failed to find override), TRUE on error.
 */
gboolean
find_override (const char* uuid, override_t* override)
{
  gchar *quoted_uuid = sql_quote (uuid);
  if (user_owns_uuid ("override", quoted_uuid) == 0)
    {
      g_free (quoted_uuid);
      *override = 0;
      return FALSE;
    }
  switch (sql_int64 (override, 0, 0,
                     "SELECT ROWID FROM overrides WHERE uuid = '%s';",
                     quoted_uuid))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *override = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        g_free (quoted_uuid);
        return TRUE;
        break;
    }

  g_free (quoted_uuid);
  return FALSE;
}

/**
 * @brief Create an override.
 *
 * @param[in]  nvt         OID of overrided NVT.
 * @param[in]  text        Override text.
 * @param[in]  hosts       Hosts to apply override to, NULL for any host.
 * @param[in]  port        Port to apply override to, NULL for any port.
 * @param[in]  threat      Threat to apply override to, "" or NULL for any threat.
 * @param[in]  new_threat  Threat to override result to.
 * @param[in]  task        Task to apply override to, 0 for any task.
 * @param[in]  result      Result to apply override to, 0 for any result.
 * @param[out] override    Created override.
 *
 * @return 0 success, -1 error.
 */
int
create_override (const char* nvt, const char* text, const char* hosts,
                 const char* port, const char* threat, const char* new_threat,
                 task_t task, result_t result, override_t* override)
{
  gchar *quoted_text, *quoted_hosts, *quoted_port, *quoted_threat;
  gchar *quoted_new_threat;

  if (nvt == NULL)
    return -1;

  if (text == NULL)
    return -1;

  if (threat && strcmp (threat, "High") && strcmp (threat, "Medium")
      && strcmp (threat, "Low") && strcmp (threat, "Log")
      && strcmp (threat, "Debug") && strcmp (threat, ""))
    return -1;

  if (new_threat && strcmp (new_threat, "High") && strcmp (new_threat, "Medium")
      && strcmp (new_threat, "Low") && strcmp (new_threat, "Log")
      && strcmp (new_threat, "Debug") && strcmp (new_threat, "False Positive")
      && strcmp (new_threat, ""))
    return -1;

  quoted_text = sql_insert (text);
  quoted_hosts = sql_insert (hosts);
  quoted_port = sql_insert (port);
  quoted_threat = sql_insert ((threat && strlen (threat))
                                ? threat_message_type (threat) : NULL);
  quoted_new_threat = sql_insert ((new_threat && strlen (new_threat))
                                    ? threat_message_type (new_threat) : NULL);

  sql ("INSERT INTO overrides"
       " (uuid, owner, nvt, creation_time, modification_time, text, hosts,"
       "  port, threat, new_threat, task, result)"
       " VALUES"
       " (make_uuid (), (SELECT ROWID FROM users WHERE users.uuid = '%s'),"
       "  '%s', %i, %i, %s, %s, %s,  %s, %s, %llu, %llu);",
       current_credentials.uuid,
       nvt,
       time (NULL),
       time (NULL),
       quoted_text,
       quoted_hosts,
       quoted_port,
       quoted_threat,
       quoted_new_threat,
       task,
       result);

  g_free (quoted_text);
  g_free (quoted_hosts);
  g_free (quoted_port);
  g_free (quoted_threat);
  g_free (quoted_new_threat);

  if (override)
    *override = sqlite3_last_insert_rowid (task_db);

  return 0;
}

/**
 * @brief Return the UUID of an override.
 *
 * @param[in]   override  Override.
 * @param[out]  id        Pointer to a newly allocated string.
 *
 * @return 0.
 */
int
override_uuid (override_t override, char ** id)
{
  *id = sql_string (0, 0,
                    "SELECT uuid FROM overrides WHERE ROWID = %llu;",
                    override);
  return 0;
}

/**
 * @brief Delete an override.
 *
 * @param[in]  override  Override.
 *
 * @return 0 success.
 */
int
delete_override (override_t override)
{
  sql ("DELETE FROM overrides WHERE ROWID = %llu;", override);
  return 0;
}

/**
 * @brief Modify an override.
 *
 * @param[in]  override    Override.
 * @param[in]  text        Override text.
 * @param[in]  hosts       Hosts to apply override to, NULL for any host.
 * @param[in]  port        Port to apply override to, NULL for any port.
 * @param[in]  threat      Threat to apply override to, "" or NULL for any threat.
 * @param[in]  new_threat  Threat to override result to.
 * @param[in]  task        Task to apply override to, 0 for any task.
 * @param[in]  result      Result to apply override to, 0 for any result.
 *
 * @return 0 success, -1 error.
 */
int
modify_override (override_t override, const char* text, const char* hosts,
                 const char* port, const char* threat, const char* new_threat,
                 task_t task, result_t result)
{
  gchar *quoted_text, *quoted_hosts, *quoted_port, *quoted_threat;
  gchar *quoted_new_threat;

  if (override == 0)
    return -1;

  if (text == NULL)
    return -1;

  if (threat && strcmp (threat, "High") && strcmp (threat, "Medium")
      && strcmp (threat, "Low") && strcmp (threat, "Log")
      && strcmp (threat, "Debug") && strcmp (threat, ""))
    return -1;

  if (new_threat && strcmp (new_threat, "High") && strcmp (new_threat, "Medium")
      && strcmp (new_threat, "Low") && strcmp (new_threat, "Log")
      && strcmp (new_threat, "Debug") && strcmp (new_threat, "False Positive")
      && strcmp (new_threat, ""))
    return -1;

  quoted_text = sql_insert (text);
  quoted_hosts = sql_insert (hosts);
  quoted_port = sql_insert (port);
  quoted_threat = sql_insert ((threat && strlen (threat))
                                ? threat_message_type (threat) : NULL);
  quoted_new_threat = sql_insert ((new_threat && strlen (new_threat))
                                    ? threat_message_type (new_threat) : NULL);

  sql ("UPDATE overrides SET"
       " modification_time = %i,"
       " text = %s,"
       " hosts = %s,"
       " port = %s,"
       " threat = %s,"
       " new_threat = %s,"
       " task = %llu,"
       " result = %llu"
       " WHERE ROWID = %llu;",
       time (NULL),
       quoted_text,
       quoted_hosts,
       quoted_port,
       quoted_threat,
       quoted_new_threat,
       task,
       result,
       override);

  g_free (quoted_text);
  g_free (quoted_hosts);
  g_free (quoted_port);
  g_free (quoted_threat);
  g_free (quoted_new_threat);

  return 0;
}

/**
 * @brief Database columns used in override iterators.
 */
#define OVERRIDE_COLUMNS "overrides.ROWID, overrides.uuid, overrides.nvt,"     \
                         " overrides.creation_time,"                           \
                         " overrides.modification_time, overrides.text,"       \
                         " overrides.hosts, overrides.port, overrides.threat," \
                         " overrides.new_threat, overrides.task,"              \
                         " overrides.result"

/**
 * @brief Initialise an override iterator.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  override    Single override to iterate, 0 for all.
 * @param[in]  result      Result to limit overrides to, 0 for all.
 * @param[in]  task        If result is > 0, task whose overrides on result to
 *                         include, otherwise task to limit overrides to.  0 for
 *                         all tasks.
 * @param[in]  nvt         NVT to limit overrides to, 0 for all.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for "ROWID".
 */
void
init_override_iterator (iterator_t* iterator, override_t override, nvt_t nvt,
                        result_t result, task_t task, int ascending,
                        const char* sort_field)
{
  gchar *result_clause, *join_clause = NULL;

  assert (current_credentials.uuid);
  assert ((nvt && override) == 0);
  assert ((task && override) == 0);

  if (result)
    result_clause = g_strdup_printf (" AND"
                                     " (result = %llu"
                                     "  OR (result = 0 AND nvt ="
                                     "      (SELECT results.nvt FROM results"
                                     "       WHERE results.ROWID = %llu)))"
                                     " AND (hosts is NULL"
                                     "      OR hosts = \"\""
                                     "      OR hosts_contains (hosts,"
                                     "      (SELECT results.host FROM results"
                                     "       WHERE results.ROWID = %llu)))"
                                     " AND (port is NULL"
                                     "      OR port = \"\""
                                     "      OR port ="
                                     "      (SELECT results.port FROM results"
                                     "       WHERE results.ROWID = %llu))"
                                     " AND (threat is NULL"
                                     "      OR threat = \"\""
                                     "      OR threat ="
                                     "      (SELECT results.type FROM results"
                                     "       WHERE results.ROWID = %llu))"
                                     " AND (task = 0 OR task = %llu)",
                                     result,
                                     result,
                                     result,
                                     result,
                                     result,
                                     task);
  else if (task)
    {
      result_clause = g_strdup_printf
                       (" AND (overrides.task = %llu OR overrides.task = 0)"
                        " AND reports.task = %llu"
                        " AND reports.ROWID = report_results.report"
                        " AND report_results.result = results.ROWID"
                        " AND results.nvt = overrides.nvt"
                        " AND"
                        " (overrides.result = 0"
                        "  OR report_results.result = overrides.result)",
                        task,
                        task);
      join_clause = g_strdup (", reports, report_results, results");
    }
  else
    result_clause = NULL;

  if (override)
    init_iterator (iterator,
                   "SELECT " OVERRIDE_COLUMNS
                   " FROM overrides"
                   " WHERE ROWID = %llu"
                   " AND ((owner IS NULL) OR (owner ="
                   " (SELECT ROWID FROM users WHERE users.uuid = '%s')))"
                   "%s"
                   " ORDER BY %s %s;",
                   override,
                   current_credentials.uuid,
                   result_clause ? result_clause : "",
                   sort_field ? sort_field : "ROWID",
                   ascending ? "ASC" : "DESC");
  else if (nvt)
    init_iterator (iterator,
                   "SELECT DISTINCT " OVERRIDE_COLUMNS
                   " FROM overrides%s"
                   " WHERE (overrides.nvt ="
                   " (SELECT oid FROM nvts WHERE nvts.ROWID = %llu))"
                   " AND ((overrides.owner IS NULL) OR (overrides.owner ="
                   " (SELECT ROWID FROM users WHERE users.uuid = '%s')))"
                   "%s"
                   " ORDER BY %s %s;",
                   join_clause ? join_clause : "",
                   nvt,
                   current_credentials.uuid,
                   result_clause ? result_clause : "",
                   sort_field ? sort_field : "overrides.ROWID",
                   ascending ? "ASC" : "DESC");
  else
    init_iterator (iterator,
                   "SELECT DISTINCT " OVERRIDE_COLUMNS
                   " FROM overrides%s"
                   " WHERE ((overrides.owner IS NULL) OR (overrides.owner ="
                   " (SELECT ROWID FROM users WHERE users.uuid = '%s')))"
                   "%s"
                   " ORDER BY %s %s;",
                   join_clause ? join_clause : "",
                   current_credentials.uuid,
                   result_clause ? result_clause : "",
                   sort_field ? sort_field : "overrides.ROWID",
                   ascending ? "ASC" : "DESC");

  g_free (result_clause);
  g_free (join_clause);
}

/**
 * @brief Get the UUID from a override iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return UUID, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (override_iterator_uuid, 1);

/**
 * @brief Get the NVT OID from a override iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return NVT OID, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (override_iterator_nvt_oid, 2);

/**
 * @brief Get the creation time from an override iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Time override was created.
 */
time_t
override_iterator_creation_time (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (time_t) sqlite3_column_int (iterator->stmt, 3);
  return ret;
}

/**
 * @brief Get the modification time from an override iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Time override was last modified.
 */
time_t
override_iterator_modification_time (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (time_t) sqlite3_column_int (iterator->stmt, 4);
  return ret;
}

/**
 * @brief Get the text from a override iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Text, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (override_iterator_text, 5);

/**
 * @brief Get the hosts from a override iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Hosts, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (override_iterator_hosts, 6);

/**
 * @brief Get the port from a override iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Port, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (override_iterator_port, 7);

/**
 * @brief Get the threat from an override iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Threat.
 */
const char *
override_iterator_threat (iterator_t *iterator)
{
  const char *ret;
  if (iterator->done) return NULL;
  ret = (const char*) sqlite3_column_text (iterator->stmt, 8);
  if (ret == NULL) return NULL;
  return message_type_threat (ret);
}

/**
 * @brief Get the threat from an override iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Threat.
 */
const char *
override_iterator_new_threat (iterator_t *iterator)
{
  const char *ret;
  if (iterator->done) return NULL;
  ret = (const char*) sqlite3_column_text (iterator->stmt, 9);
  if (ret == NULL) return NULL;
  return message_type_threat (ret);
}

/**
 * @brief Get the task from an override iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The task associated with the override, or 0 on error.
 */
task_t
override_iterator_task (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return (task_t) sqlite3_column_int64 (iterator->stmt, 10);
}

/**
 * @brief Get the result from an override iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The result associated with the override, or 0 on error.
 */
result_t
override_iterator_result (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return (result_t) sqlite3_column_int64 (iterator->stmt, 11);
}

/**
 * @brief Get the NVT name from an override iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The name of the NVT associated with the override, or NULL on error.
 */
const char*
override_iterator_nvt_name (iterator_t *iterator)
{
  nvti_t *nvti;
  if (iterator->done) return NULL;
  nvti = nvtis_lookup (nvti_cache, override_iterator_nvt_oid (iterator));
  if (nvti)
    return nvti_name (nvti);
  return NULL;
}


/* Schedules. */

/**
 * @brief Find a schedule given a UUID.
 *
 * @param[in]   uuid      UUID of schedule.
 * @param[out]  schedule  Schedule return, 0 if succesfully failed to find schedule.
 *
 * @return FALSE on success (including if failed to find schedule), TRUE on error.
 */
gboolean
find_schedule (const char* uuid, schedule_t* schedule)
{
  gchar *quoted_uuid = sql_quote (uuid);
  if (user_owns_uuid ("schedule", quoted_uuid) == 0)
    {
      g_free (quoted_uuid);
      *schedule = 0;
      return FALSE;
    }
  switch (sql_int64 (schedule, 0, 0,
                     "SELECT ROWID FROM schedules WHERE uuid = '%s';",
                     quoted_uuid))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *schedule = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        g_free (quoted_uuid);
        return TRUE;
        break;
    }

  g_free (quoted_uuid);
  return FALSE;
}

/**
 * @brief Create a schedule.
 *
 * @param[in]   name        Name of schedule.
 * @param[in]   comment     Comment on schedule.
 * @param[in]   first_time  First time action will run.
 * @param[in]   period      How often the action will run in seconds.  0 means
 *                          once.
 * @param[in]   period_months  The months part of the period.
 * @param[in]   duration    The length of the time window the action will run
 *                          in.  0 means entire duration of action.
 * @param[out]  schedule    Created schedule.
 *
 * @return 0 success, 1 schedule exists already.
 */
int
create_schedule (const char* name, const char *comment, time_t first_time,
                 time_t period, time_t period_months, time_t duration,
                 schedule_t *schedule)
{
  gchar *quoted_name = sql_quote (name);

  sql ("BEGIN IMMEDIATE;");

  assert (current_credentials.uuid);

  if (sql_int (0, 0,
               "SELECT COUNT(*) FROM schedules"
               " WHERE name = '%s'"
               " AND ((owner IS NULL) OR (owner ="
               " (SELECT users.ROWID FROM users WHERE users.uuid = '%s')));",
               quoted_name,
               current_credentials.uuid))
    {
      g_free (quoted_name);
      sql ("ROLLBACK;");
      return 1;
    }

  if (comment)
    {
      gchar *quoted_comment = sql_nquote (comment, strlen (comment));
      sql ("INSERT INTO schedules"
           " (uuid, name, owner, comment, first_time, period, period_months,"
           "  duration)"
           " VALUES (make_uuid (), '%s',"
           " (SELECT ROWID FROM users WHERE users.uuid = '%s'),"
           " '%s', %i, %i, %i, %i);",
           quoted_name, current_credentials.uuid, quoted_comment, first_time,
           period, period_months, duration);
      g_free (quoted_comment);
    }
  else
    sql ("INSERT INTO schedules"
         " (uuid, name, owner, comment, first_time, period, period_months,"
         "  duration)"
         " VALUES (make_uuid (), '%s',"
         " (SELECT ROWID FROM users WHERE users.uuid = '%s'),"
         " '', %i, %i, %i, %i);",
         quoted_name, current_credentials.uuid, first_time, period,
         period_months, duration);

  if (schedule)
    *schedule = sqlite3_last_insert_rowid (task_db);

  g_free (quoted_name);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Delete a schedule.
 *
 * @param[in]  schedule  Schedule.
 *
 * @return 0 success, 1 fail because a task refers to the schedule, -1 error.
 */
int
delete_schedule (schedule_t schedule)
{
  sql ("BEGIN IMMEDIATE;");
  if (sql_int (0, 0,
               "SELECT count(*) FROM tasks WHERE schedule = %llu;",
               schedule))
    {
      sql ("ROLLBACK;");
      return 1;
    }
  sql ("DELETE FROM schedules WHERE ROWID = %llu;", schedule);
  sql ("COMMIT;");
  return 0;
}

/**
 * @brief Code fragment for months_between.
 */
#define MONTHS_WITHIN_YEAR()                                 \
  (same_month                                                \
    ? 0                                                      \
    : ((broken2->tm_mon - broken1.tm_mon)                    \
       - (same_day                                           \
           ? (same_hour                                      \
               ? (same_minute                                \
                   ? (same_second                            \
                       ? 0                                   \
                       : (broken2->tm_sec < broken1.tm_sec)) \
                   : (broken2->tm_min < broken1.tm_min))     \
               : (broken2->tm_hour < broken1.tm_hour))       \
           : (broken2->tm_mday < broken1.tm_mday))))

/**
 * @brief Count number of full months between two times.
 *
 * There are two full months between 0h00.00 1 February 2010 and 0h00.00 1
 * April 2010.  There is one full month between 0h00.00 1 February 2010 and
 * 23h59.59 31 March 2010.
 *
 * @param[in]  time1  Earlier time.
 * @param[in]  time2  Later time.
 *
 * @return Number of full months between time1 and time2.
 */
time_t
months_between (time_t time1, time_t time2)
{
  struct tm broken1, *broken2;
  int same_year, same_month, same_day, same_hour, same_minute, same_second;
  int year1_less, month1_less, day1_less, hour1_less, minute1_less;
  int second1_less;

  assert (time1 < time2);

  localtime_r (&time1, &broken1);
  broken2 = localtime (&time2);

  same_year = (broken1.tm_year == broken2->tm_year);
  same_month = (broken1.tm_mon == broken2->tm_mon);
  same_day = (broken1.tm_mday == broken2->tm_mday);
  same_hour = (broken1.tm_hour == broken2->tm_hour);
  same_minute = (broken1.tm_min == broken2->tm_min);
  same_second = (broken1.tm_sec == broken2->tm_sec);

  year1_less = (broken1.tm_year < broken2->tm_year);
  month1_less = (broken1.tm_mon < broken2->tm_mon);
  day1_less = (broken1.tm_mday < broken2->tm_mday);
  hour1_less = (broken1.tm_hour < broken2->tm_hour);
  minute1_less = (broken1.tm_min < broken2->tm_min);
  second1_less = (broken1.tm_sec < broken2->tm_sec);

  return
    (same_year
      ? MONTHS_WITHIN_YEAR ()
      : ((month1_less
          || (same_month
              && (day1_less
                  || (same_day
                      && (hour1_less
                          || (same_hour
                              && (minute1_less
                                  || (same_minute
                                      && second1_less))))))))
         ? (/* time1 is earlier in the year than time2. */
            ((broken2->tm_year - broken1.tm_year) * 12)
            + MONTHS_WITHIN_YEAR ())
         : (/* time1 is later in the year than time2. */
            ((broken2->tm_year - broken1.tm_year - 1) * 12)
            /* Months left in year of time1. */
            + (11 - broken1.tm_mon)
            /* Months past in year of time2. */
            + broken2->tm_mon
            /* Possible extra month due to position in month of each time. */
            + (day1_less
               || (same_day
                   && (hour1_less
                       || (same_hour
                           && (minute1_less
                               || (same_minute
                                   && second1_less)))))))));
}

/**
 * @brief Add months to a time.
 *
 * @param[in]  time    Time.
 * @param[in]  months  Months.
 *
 * @return Time plus given number of months.
 */
time_t
add_months (time_t time, int months)
{
  struct tm *broken = localtime (&time);
  broken->tm_mon += months;
  return mktime (broken);
}

/**
 * @brief Return the UUID of a schedule.
 *
 * @param[in]  schedule  Schedule.
 *
 * @return Newly allocated UUID.
 */
char *
schedule_uuid (schedule_t schedule)
{
  return sql_string (0, 0,
                     "SELECT uuid FROM schedules WHERE ROWID = %llu;",
                     schedule);
}

/**
 * @brief Return the name of a schedule.
 *
 * @param[in]  schedule  Schedule.
 *
 * @return Newly allocated name.
 */
char *
schedule_name (schedule_t schedule)
{
  return sql_string (0, 0,
                     "SELECT name FROM schedules WHERE ROWID = %llu;",
                     schedule);
}

/**
 * @brief Initialise a schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  schedule  Single schedule to iterate over, or 0 for all.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for "ROWID".
 */
void
init_schedule_iterator (iterator_t* iterator, schedule_t schedule,
                        int ascending, const char* sort_field)
{
  if (schedule)
    init_iterator (iterator,
                   "SELECT ROWID, uuid, name, comment, first_time,"
                   " period, period_months, duration,"
                   " (SELECT count(*) > 0 FROM tasks"
                   "  WHERE tasks.schedule = schedules.ROWID)"
                   " FROM schedules"
                   " WHERE ROWID = %llu"
                   " AND ((owner IS NULL) OR (owner ="
                   " (SELECT ROWID FROM users WHERE users.uuid = '%s')))"
                   " ORDER BY %s %s;",
                   schedule,
                   current_credentials.uuid,
                   sort_field ? sort_field : "ROWID",
                   ascending ? "ASC" : "DESC");
  else
    init_iterator (iterator,
                   "SELECT ROWID, uuid, name, comment, first_time,"
                   " period, period_months, duration,"
                   " (SELECT count(*) > 0 FROM tasks"
                   "  WHERE tasks.schedule = schedules.ROWID)"
                   " FROM schedules"
                   " WHERE ((owner IS NULL) OR (owner ="
                   " (SELECT ROWID FROM users WHERE users.uuid = '%s')))"
                   " ORDER BY %s %s;",
                   current_credentials.uuid,
                   sort_field ? sort_field : "ROWID",
                   ascending ? "ASC" : "DESC");
}

/**
 * @brief Get the schedule from a schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Schedule.
 */
schedule_t
schedule_iterator_schedule (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return (task_t) sqlite3_column_int64 (iterator->stmt, 0);
}

/**
 * @brief Get the UUID from a schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return UUID, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (schedule_iterator_uuid, 1);

/**
 * @brief Get the name from a schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (schedule_iterator_name, 2);

/**
 * @brief Get the comment from a schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Comment, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (schedule_iterator_comment, 3);

/**
 * @brief Get the first time from a schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return First time of schedule.
 */
time_t
schedule_iterator_first_time (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (time_t) sqlite3_column_int (iterator->stmt, 4);
  return ret;
}

/**
 * @brief Get the next time a schedule could be schedulable.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Next time an action associated with schedule could be run.
 */
time_t
schedule_iterator_next_time (iterator_t* iterator)
{
  time_t period = schedule_iterator_period (iterator);
  time_t now = time (NULL);
  if (period > 0)
    {
      time_t first = schedule_iterator_first_time (iterator);
      return first + ((((now - first) / period) + 1) * period);
    }
  else if (schedule_iterator_first_time (iterator) >= now)
    {
      return schedule_iterator_first_time (iterator);
    }
  return 0;
}

/**
 * @brief Get the period from a schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Period of schedule.
 */
time_t
schedule_iterator_period (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (time_t) sqlite3_column_int (iterator->stmt, 5);
  return ret;
}

/**
 * @brief Get the period months from a schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Period of schedule (months).
 */
time_t
schedule_iterator_period_months (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (time_t) sqlite3_column_int (iterator->stmt, 6);
  return ret;
}

/**
 * @brief Get the duration from a schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Duration of schedule.
 */
time_t
schedule_iterator_duration (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (time_t) sqlite3_column_int (iterator->stmt, 7);
  return ret;
}

/**
 * @brief Get whether a schedule iterator is in use by any tasks.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return 1 if schedule is in use, else 0.
 */
int
schedule_iterator_in_use (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (int) sqlite3_column_int (iterator->stmt, 8);
  return ret;
}

/**
 * @brief Initialise a task schedule iterator.
 *
 * Lock the database before initialising.
 *
 * @param[in]  iterator        Iterator.
 */
void
init_task_schedule_iterator (iterator_t* iterator)
{
  sql ("BEGIN EXCLUSIVE;");
  init_iterator (iterator,
                 "SELECT tasks.ROWID, tasks.uuid,"
                 " schedules.ROWID, tasks.schedule_next_time,"
                 " schedules.period, schedules.period_months,"
                 " schedules.first_time,"
                 " schedules.duration,"
                 " users.uuid, users.name"
                 " FROM tasks, schedules, users"
                 " WHERE tasks.schedule = schedules.ROWID"
                 " AND tasks.owner = users.ROWID;");
}

/**
 * @brief Cleanup a task schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 */
void
cleanup_task_schedule_iterator (iterator_t* iterator)
{
  cleanup_iterator (iterator);
  sql ("COMMIT;");
}

/**
 * @brief Get the task from a task schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return task.
 */
task_t
task_schedule_iterator_task (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return (task_t) sqlite3_column_int64 (iterator->stmt, 0);
}

/**
 * @brief Get the task UUID from a task schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Task UUID, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (task_schedule_iterator_task_uuid, 1);

/**
 * @brief Get the schedule from a task schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return task.
 */
schedule_t
task_schedule_iterator_schedule (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return (schedule_t) sqlite3_column_int64 (iterator->stmt, 2);
}

/**
 * @brief Get the next time from a task schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Next time.
 */
time_t
task_schedule_iterator_next_time (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return (time_t) sqlite3_column_int64 (iterator->stmt, 3);
}

/**
 * @brief Get the period from a task schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return period.
 */
time_t
task_schedule_iterator_period (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return (time_t) sqlite3_column_int64 (iterator->stmt, 4);
}

/**
 * @brief Get the period months from a task schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Period months.
 */
time_t
task_schedule_iterator_period_months (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return (time_t) sqlite3_column_int64 (iterator->stmt, 5);
}

/**
 * @brief Get the first time from a task schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return First time.
 */
time_t
task_schedule_iterator_first_time (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return (time_t) sqlite3_column_int64 (iterator->stmt, 6);
}

/**
 * @brief Get the duration from a task schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Duration.
 */
time_t
task_schedule_iterator_duration (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return (time_t) sqlite3_column_int64 (iterator->stmt, 7);
}

/**
 * @brief Get the owner uuid from a task schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Owner UUID, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (task_schedule_iterator_owner_uuid, 8);

/**
 * @brief Get the owner_name from a task schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Owner name, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (task_schedule_iterator_owner_name, 9);

/**
 * @brief Get the start due state from a task schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Start due flag.
 */
gboolean
task_schedule_iterator_start_due (iterator_t* iterator)
{
  task_status_t run_status;
  time_t start_time;

  if (iterator->done) return FALSE;

  run_status = task_run_status (task_schedule_iterator_task (iterator));
  start_time = task_schedule_iterator_next_time (iterator);

  if ((run_status == TASK_STATUS_DONE
       || run_status == TASK_STATUS_INTERNAL_ERROR
       || run_status == TASK_STATUS_NEW
       || run_status == TASK_STATUS_STOPPED)
      && (start_time > 0)
      && (start_time <= time (NULL)))
    return TRUE;

  return FALSE;
}

/**
 * @brief Get the stop due state from a task schedule iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Stop due flag.
 */
gboolean
task_schedule_iterator_stop_due (iterator_t* iterator)
{
  time_t period, period_months, duration;

  if (iterator->done) return FALSE;

  period = task_schedule_iterator_period (iterator);
  period_months = task_schedule_iterator_period_months (iterator);
  duration = task_schedule_iterator_duration (iterator);

  if (period && duration)
    {
      task_status_t run_status;

      run_status = task_run_status (task_schedule_iterator_task (iterator));

      if (run_status == TASK_STATUS_RUNNING
          || run_status == TASK_STATUS_REQUESTED)
        {
          time_t now, first, start;

          now = time (NULL);
          first = task_schedule_iterator_first_time (iterator);
          start = first + (((now - first) / period) * period);
          if ((start + duration) < now)
            return TRUE;
        }
    }
  else if (period_months && duration)
    {
      task_status_t run_status;

      run_status = task_run_status (task_schedule_iterator_task (iterator));

      if (run_status == TASK_STATUS_RUNNING
          || run_status == TASK_STATUS_REQUESTED)
        {
          time_t now, first, start;

          now = time (NULL);
          first = task_schedule_iterator_first_time (iterator);
          start = add_months (first, months_between (first, now));
          if ((start + duration) < now)
            return TRUE;
        }
    }

  return FALSE;
}

/**
 * @brief Initialise a schedule task iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  schedule  Schedule.
 */
void
init_schedule_task_iterator (iterator_t* iterator, schedule_t schedule)
{
  init_iterator (iterator,
                 "SELECT ROWID, uuid, name FROM tasks WHERE schedule = %llu;",
                 schedule);
}

/**
 * @brief Get the UUID from a schedule task iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return UUID, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (schedule_task_iterator_uuid, 1);

/**
 * @brief Get the name from a schedule task iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (schedule_task_iterator_name, 2);


/* Report Formats. */

/**
 * @brief Possible port types.
 */
typedef enum
{
  REPORT_FORMAT_FLAG_ACTIVE = 1
} report_format_flag_t;

/**
 * @brief Find a report format given a UUID.
 *
 * @param[in]   uuid           UUID of report format.
 * @param[out]  report_format  Report format return, 0 if succesfully failed to
 *                             find report format.
 *
 * @return FALSE on success (including if failed to find report format), TRUE
 *         on error.
 */
gboolean
find_report_format (const char* uuid, report_format_t* report_format)
{
  gchar *quoted_uuid = sql_quote (uuid);
  if (user_owns_uuid ("report_format", quoted_uuid) == 0)
    {
      g_free (quoted_uuid);
      *report_format = 0;
      return FALSE;
    }
  switch (sql_int64 (report_format, 0, 0,
                     "SELECT ROWID FROM report_formats WHERE uuid = '%s';",
                     quoted_uuid))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *report_format = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        g_free (quoted_uuid);
        return TRUE;
        break;
    }

  g_free (quoted_uuid);
  return FALSE;
}

/**
 * @brief Find a report format given a name.
 *
 * @param[in]   name           Name of report_format.
 * @param[out]  report_format  Report format return, 0 if succesfully failed to
 *                             find report_format.
 *
 * @return FALSE on success (including if failed to find report format), TRUE
 *         on error.
 */
gboolean
lookup_report_format (const char* name, report_format_t* report_format)
{
  gchar *quoted_name = sql_quote (name);
  if (user_owns ("report_format", "name", quoted_name) == 0)
    {
      g_free (quoted_name);
      *report_format = 0;
      return FALSE;
    }
  switch (sql_int64 (report_format, 0, 0,
                     "SELECT ROWID FROM report_formats WHERE name = '%s';",
                     quoted_name))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *report_format = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        g_free (quoted_name);
        return TRUE;
        break;
    }

  g_free (quoted_name);
  return FALSE;
}

/**
 * @brief Create a report format.
 *
 * @param[in]   uuid           UUID of format.
 * @param[in]   name           Name of format.
 * @param[in]   content_type   Content type of format.
 * @param[in]   extension      File extension of format.
 * @param[in]   summary        Summary of format.
 * @param[in]   description    Description of format.
 * @param[in]   global         Whether the report is global.
 * @param[in]   files          Array of memory.  Each item is a file name
 *                             string, a terminating NULL, the file contents
 *                             in base64 and a terminating NULL.
 * @param[in]   params         Array of params.
 * @param[in]   params_options Array.  Each item is an array corresponding to
 *                             params.  Each item of an inner array is a string,
 *                             the text of an option in a selection.
 * @param[in]   signature      Signature.
 * @param[out]  report_format  Created report format.
 *
 * @return 0 success, 1 report format exists, 2 empty file name, 3 param value
 *         validation failed, 4 param value validation failed, 5 param default
 *         missing, 6 param min or max out of range, 7 param type missing,
 *         8 duplicate param name, 9 bogus param type name, -1 error.
 */
int
create_report_format (const char *uuid, const char *name,
                      const char *content_type, const char *extension,
                      const char *summary, const char *description, int global,
                      array_t *files, array_t *params, array_t *params_options,
                      const char *signature, report_format_t *report_format)
{
  gchar *quoted_name, *quoted_summary, *quoted_description, *quoted_extension;
  gchar *quoted_content_type, *quoted_signature, *file_name, *dir;
  report_format_t report_format_rowid;
  int index;
  gchar *format_signature = NULL;
  gsize format_signature_size;
  int format_trust = TRUST_UNKNOWN;
  create_report_format_param_t *param;

  /* Verify the signature. */

  if (signature
      || (find_signature ("report_formats", uuid, &format_signature,
                          &format_signature_size)
          == 0))
    {
      GString *format;

      format = g_string_new ("");

      g_string_append_printf (format,
                              "%s%s%s%s%s%s%i",
                              uuid,
                              name,
                              extension,
                              content_type,
                              summary,
                              description,
                              global & 1);

      index = 0;
      while ((file_name = (gchar*) g_ptr_array_index (files, index++)))
        g_string_append_printf (format,
                                "%s%s",
                                file_name,
                                file_name + strlen (file_name) + 1);

      index = 0;
      while ((param
               = (create_report_format_param_t*) g_ptr_array_index (params,
                                                                    index++)))
        {
          g_string_append_printf (format,
                                  "%s%s%s",
                                  param->name,
                                  param->value,
                                  param->type);

          if (param->type_min)
            {
              long long int min;
              min = strtoll (param->type_min, NULL, 0);
              if (min == LLONG_MIN)
                return 6;
              g_string_append_printf (format, "%lli", min);
            }

          if (param->type_max)
            {
              long long int max;
              max = strtoll (param->type_max, NULL, 0);
              if (max == LLONG_MAX)
                return 6;
              g_string_append_printf (format, "%lli", max);
            }

          g_string_append_printf (format,
                                  "%s",
                                  param->fallback);

          {
            array_t *options;
            int option_index;
            gchar *option_value;

            options = (array_t*) g_ptr_array_index (params_options, index - 1);
            if (options == NULL)
              return -1;
            option_index = 0;
            while ((option_value = (gchar*) g_ptr_array_index (options,
                                                               option_index++)))
              g_string_append_printf (format, "%s", option_value);
          }
        }

      g_string_append_printf (format, "\n");

      if (signature == NULL)
        signature = (const char*) format_signature;

      if (verify_signature (format->str, format->len, signature,
                            strlen (signature), &format_trust))
        {
          g_free (format_signature);
          g_string_free (format, TRUE);
          return -1;
        }
      g_string_free (format, TRUE);

      g_free (format_signature);
    }

  sql ("BEGIN IMMEDIATE;");

  assert (current_credentials.uuid);
  assert (uuid);
  assert (name);
  assert (files);
  assert (params);

  if (sql_int (0, 0,
               "SELECT COUNT(*) FROM report_formats"
               " WHERE uuid = '%s'"
               " AND ((owner IS NULL) OR (owner ="
               " (SELECT users.ROWID FROM users WHERE users.uuid = '%s')));",
               uuid,
               current_credentials.uuid))
    {
      sql ("ROLLBACK;");
      return 1;
    }

  quoted_name = sql_quote (name);

  if (sql_int (0, 0,
               "SELECT COUNT(*) FROM report_formats"
               " WHERE name = '%s'"
               " AND ((owner IS NULL) OR (owner ="
               " (SELECT users.ROWID FROM users WHERE users.uuid = '%s')));",
               quoted_name,
               current_credentials.uuid))
    {
      g_free (quoted_name);
      sql ("ROLLBACK;");
      return 1;
    }

  /* Write files to disk. */

  if (global)
    dir = g_build_filename (OPENVAS_SYSCONF_DIR,
                            "openvasmd",
                            "global_report_formats",
                            uuid,
                            NULL);
  else
    {
      assert (current_credentials.uuid);
      dir = g_build_filename (OPENVAS_SYSCONF_DIR,
                              "openvasmd",
                              "report_formats",
                              current_credentials.uuid,
                              uuid,
                              NULL);
    }

  if (g_file_test (dir, G_FILE_TEST_EXISTS) && file_utils_rmdir_rf (dir))
    {
      g_warning ("%s: failed to remove dir %s", __FUNCTION__, dir);
      g_free (dir);
      g_free (quoted_name);
      sql ("ROLLBACK;");
      return -1;
    }

  if (g_mkdir_with_parents (dir, 0755 /* "rwxr-xr-x" */))
    {
      g_warning ("%s: failed to create dir %s", __FUNCTION__, dir);
      g_free (dir);
      g_free (quoted_name);
      sql ("ROLLBACK;");
      return -1;
    }

  index = 0;
  while ((file_name = (gchar*) g_ptr_array_index (files, index++)))
    {
      gchar *contents, *file, *full_file_name;
      gsize contents_size;
      GError *error;

      if (strlen (file_name) == 0)
        {
          file_utils_rmdir_rf (dir);
          g_free (dir);
          g_free (quoted_name);
          sql ("ROLLBACK;");
          return 2;
        }

      file = file_name + strlen (file_name) + 1;
      if (strlen (file))
        contents = (gchar*) g_base64_decode (file, &contents_size);
      else
        {
          contents = g_strdup ("");
          contents_size = 0;
        }

      full_file_name = g_build_filename (dir, file_name, NULL);

      error = NULL;
      g_file_set_contents (full_file_name, contents, contents_size, &error);
      g_free (contents);
      g_free (full_file_name);
      if (error)
        {
          g_warning ("%s: %s", __FUNCTION__, error->message);
          g_error_free (error);
          file_utils_rmdir_rf (dir);
          g_free (dir);
          g_free (quoted_name);
          sql ("ROLLBACK;");
          return -1;
        }
    }

  /* Add format to database. */

  quoted_summary = summary ? sql_quote (summary) : NULL;
  quoted_description = description ? sql_quote (description) : NULL;
  quoted_extension = extension ? sql_quote (extension) : NULL;
  quoted_content_type = content_type ? sql_quote (content_type) : NULL;
  quoted_signature = signature ? sql_quote (signature) : NULL;

  if (global)
    sql ("INSERT INTO report_formats"
         " (uuid, name, owner, summary, description, extension, content_type,"
         "  signature, trust, trust_time, flags)"
         " VALUES ('%s', '%s', NULL, '%s', '%s', '%s', '%s', '%s', %i, %i, 0);",
         uuid,
         quoted_name,
         quoted_summary ? quoted_summary : "",
         quoted_description ? quoted_description : "",
         quoted_extension ? quoted_extension : "",
         quoted_content_type ? quoted_content_type : "",
         quoted_signature ? quoted_signature : "",
         format_trust,
         time (NULL));
  else
    sql ("INSERT INTO report_formats"
         " (uuid, name, owner, summary, description, extension, content_type,"
         "  signature, trust, trust_time, flags)"
         " VALUES ('%s', '%s',"
         " (SELECT ROWID FROM users WHERE users.uuid = '%s'),"
         " '%s', '%s', '%s', '%s', '%s', %i, %i, 0);",
         uuid,
         quoted_name,
         current_credentials.uuid,
         quoted_summary ? quoted_summary : "",
         quoted_description ? quoted_description : "",
         quoted_extension ? quoted_extension : "",
         quoted_content_type ? quoted_content_type : "",
         quoted_signature ? quoted_signature : "",
         format_trust,
         time (NULL));

  g_free (quoted_summary);
  g_free (quoted_description);
  g_free (quoted_extension);
  g_free (quoted_content_type);
  g_free (quoted_signature);
  g_free (quoted_name);

  /* Add params to database. */

  report_format_rowid = sqlite3_last_insert_rowid (task_db);
  index = 0;
  while ((param = (create_report_format_param_t*) g_ptr_array_index (params,
                                                                     index++)))
    {
      gchar *quoted_param_name, *quoted_param_value, *quoted_param_fallback;
      rowid_t param_rowid;
      long long int min, max;

      if (param->type == NULL)
        {
          file_utils_rmdir_rf (dir);
          g_free (dir);
          sql ("ROLLBACK;");
          return 7;
        }

      if (report_format_param_type_from_name (param->type)
          == REPORT_FORMAT_PARAM_TYPE_ERROR)
        {
          file_utils_rmdir_rf (dir);
          g_free (dir);
          sql ("ROLLBACK;");
          return 9;
        }

      /* Param min and max are optional.  LLONG_MIN and LLONG_MAX mark in the db
       * that they were missing, so if the user gives LLONG_MIN or LLONG_MAX it
       * is an error.  This ensures that GPG verification works, because the
       * verification knows when to leave out min and max. */

      if (param->type_min)
        {
          min = strtoll (param->type_min, NULL, 0);
          if (min == LLONG_MIN)
            {
              file_utils_rmdir_rf (dir);
              g_free (dir);
              sql ("ROLLBACK;");
              return 6;
            }
        }
      else
        min = LLONG_MIN;

      if (param->type_max)
        {
          max = strtoll (param->type_max, NULL, 0);
          if (max == LLONG_MAX)
            {
              file_utils_rmdir_rf (dir);
              g_free (dir);
              sql ("ROLLBACK;");
              return 6;
            }
        }
      else
        max = LLONG_MAX;

      if (param->fallback == NULL)
        {
          file_utils_rmdir_rf (dir);
          g_free (dir);
          sql ("ROLLBACK;");
          return 5;
        }

      quoted_param_name = sql_quote (param->name);

      if (sql_int (0, 0,
                   "SELECT count(*) FROM report_format_params"
                   " WHERE name = '%s' AND report_format = %llu;",
                   quoted_param_name,
                   report_format_rowid))
        {
          g_free (quoted_param_name);
          file_utils_rmdir_rf (dir);
          g_free (dir);
          sql ("ROLLBACK;");
          return 8;
        }

      quoted_param_value = sql_quote (param->value);
      quoted_param_fallback = sql_quote (param->fallback);

      sql ("INSERT INTO report_format_params"
           " (report_format, name, type, value, type_min, type_max, type_regex,"
           "  fallback)"
           " VALUES (%llu, '%s', %u, '%s', %lli, %lli, '', '%s');",
           report_format_rowid,
           quoted_param_name,
           report_format_param_type_from_name (param->type),
           quoted_param_value,
           min,
           max,
           quoted_param_fallback);

      g_free (quoted_param_name);
      g_free (quoted_param_value);
      g_free (quoted_param_fallback);

      param_rowid = sqlite3_last_insert_rowid (task_db);

      {
        array_t *options;
        int option_index;
        gchar *option_value;

        options = (array_t*) g_ptr_array_index (params_options, index - 1);
        if (options == NULL)
          {
            file_utils_rmdir_rf (dir);
            g_free (dir);
            sql ("ROLLBACK;");
            return -1;
          }
        option_index = 0;
        while ((option_value = (gchar*) g_ptr_array_index (options,
                                                           option_index++)))
          {
            gchar *quoted_option_value = sql_quote (option_value);
            sql ("INSERT INTO report_format_param_options"
                 " (report_format_param, value)"
                 " VALUES (%llu, '%s');",
                 param_rowid,
                 quoted_option_value);
            g_free (quoted_option_value);
          }
      }

      if (validate_param_value (report_format_rowid, param_rowid, param->name,
                                param->value))
        {
          file_utils_rmdir_rf (dir);
          g_free (dir);
          sql ("ROLLBACK;");
          return 3;
        }

      if (validate_param_value (report_format_rowid, param_rowid, param->name,
                                param->fallback))
        {
          file_utils_rmdir_rf (dir);
          g_free (dir);
          sql ("ROLLBACK;");
          return 4;
        }
    }

  if (report_format)
    *report_format = report_format_rowid;

  g_free (dir);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Delete a report format.
 *
 * @param[in]  report_format  Report format.
 *
 * @return 0 success, -1 error.
 */
int
delete_report_format (report_format_t report_format)
{
  char *uuid;
  gchar *dir;

  sql ("BEGIN IMMEDIATE;");

  uuid = report_format_uuid (report_format);
  if (uuid == NULL)
    {
      sql ("ROLLBACK;");
      return -1;
    }

  if (report_format_global (report_format))
    dir = g_build_filename (OPENVAS_SYSCONF_DIR,
                            "openvasmd",
                            "global_report_formats",
                            uuid,
                            NULL);
  else
    dir = g_build_filename (OPENVAS_SYSCONF_DIR,
                            "openvasmd",
                            "report_formats",
                            current_credentials.uuid,
                            uuid,
                            NULL);
  free (uuid);
  if (g_file_test (dir, G_FILE_TEST_EXISTS) && file_utils_rmdir_rf (dir))
    {
      g_free (dir);
      sql ("ROLLBACK;");
      return -1;
    }
  g_free (dir);

  sql ("DELETE FROM report_formats WHERE ROWID = %llu;", report_format);
  sql ("DELETE FROM report_format_param_options WHERE report_format_param"
       " IN (SELECT ROWID from report_format_params WHERE report_format = %llu);",
       report_format);
  sql ("DELETE FROM report_format_params WHERE report_format = %llu;",
       report_format);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Verify a report format.
 *
 * @param[in]  report_format  Report format.
 *
 * @return 0 success, -1 error.
 */
int
verify_report_format (report_format_t report_format)
{
  int format_trust = TRUST_UNKNOWN;
  iterator_t formats;

  sql ("BEGIN IMMEDIATE;");

  init_report_format_iterator (&formats, report_format, 1, NULL);
  if (next (&formats))
    {
      const char *signature;
      gchar *format_signature = NULL;
      gsize format_signature_size;

      signature = report_format_iterator_signature (&formats);

      find_signature ("report_formats",
                      report_format_iterator_uuid (&formats),
                      &format_signature,
                      &format_signature_size);

      if ((signature && strlen (signature))
          || format_signature)
        {
          GString *format;
          file_iterator_t files;
          iterator_t params;
          report_format_t report_format;

          format = g_string_new ("");

          g_string_append_printf
           (format,
            "%s%s%s%s%s%s%i",
            report_format_iterator_uuid (&formats),
            report_format_iterator_name (&formats),
            report_format_iterator_extension (&formats),
            report_format_iterator_content_type (&formats),
            report_format_iterator_summary (&formats),
            report_format_iterator_description (&formats),
            report_format_iterator_global (&formats) & 1);

          report_format = report_format_iterator_report_format (&formats);

          init_report_format_file_iterator (&files, report_format);
          while (next_file (&files))
            {
              gchar *content = file_iterator_content_64 (&files);
              g_string_append_printf (format,
                                      "%s%s",
                                      file_iterator_name (&files),
                                      content);
              g_free (content);
            }
          cleanup_file_iterator (&files);

          init_report_format_param_iterator (&params,
                                             report_format,
                                             1,
                                             NULL);
          while (next (&params))
            {
              g_string_append_printf
               (format,
                "%s%s%s",
                report_format_param_iterator_name (&params),
                report_format_param_iterator_value (&params),
                report_format_param_iterator_type_name (&params));

              if (report_format_param_iterator_type_min (&params) > LLONG_MIN)
                g_string_append_printf
                 (format,
                  "%lli",
                  report_format_param_iterator_type_min (&params));

              if (report_format_param_iterator_type_max (&params) < LLONG_MAX)
                g_string_append_printf
                 (format,
                  "%lli",
                  report_format_param_iterator_type_max (&params));

              g_string_append_printf
               (format,
                "%s%s",
                report_format_param_iterator_type_regex (&params),
                report_format_param_iterator_fallback (&params));

              {
                iterator_t options;
                init_param_option_iterator
                 (&options,
                  report_format_param_iterator_param (&params),
                  1,
                  NULL);
                while (next (&options))
                  if (param_option_iterator_value (&options))
                    g_string_append_printf
                     (format,
                      "%s",
                      param_option_iterator_value (&options));
              }
            }
          cleanup_iterator (&params);

          g_string_append_printf (format, "\n");

          if (signature && strlen (signature))
            {
              /* Try the signature from the database. */
              if (verify_signature (format->str, format->len, signature,
                                    strlen (signature), &format_trust))
                {
                  cleanup_iterator (&formats);
                  g_free (format_signature);
                  sql ("ROLLBACK;");
                  g_string_free (format, TRUE);
                  return -1;
                }
            }

          /* If the database signature is empty or the database
           * signature is bad, and there is a feed signature, then
           * try the feed signature. */
          if (((format_trust == TRUST_NO)
               || (format_trust == TRUST_UNKNOWN))
              && format_signature)
            {
              if (verify_signature (format->str, format->len, format_signature,
                                    strlen (format_signature), &format_trust))
                {
                  cleanup_iterator (&formats);
                  g_free (format_signature);
                  sql ("ROLLBACK;");
                  g_string_free (format, TRUE);
                  return -1;
                }

              if (format_trust == TRUST_YES)
                {
                  gchar *quoted_signature;
                  quoted_signature = sql_quote (format_signature);
                  sql ("UPDATE report_formats SET signature = '%s'"
                       " WHERE ROWID = %llu;",
                       quoted_signature,
                       report_format);
                  g_free (quoted_signature);
                }
            }
          g_free (format_signature);
          g_string_free (format, TRUE);
        }
    }
  else
    {
      sql ("ROLLBACK;");
      return -1;
    }
  cleanup_iterator (&formats);

  sql ("UPDATE report_formats SET trust = %i, trust_time = %i"
       " WHERE ROWID = %llu;",
       format_trust,
       time (NULL),
       report_format);
  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Return the UUID of a report format.
 *
 * @param[in]  report_format  Report format.
 *
 * @return Newly allocated UUID.
 */
char *
report_format_uuid (report_format_t report_format)
{
  return sql_string (0, 0,
                     "SELECT uuid FROM report_formats WHERE ROWID = %llu;",
                     report_format);
}

/**
 * @brief Set the active flag of a report format.
 *
 * @param[in]  report_format  The report format.
 * @param[in]  active         Active flag.
 */
void
set_report_format_active (report_format_t report_format, int active)
{
  if (active)
    sql ("UPDATE report_formats SET flags = (flags | %llu) WHERE ROWID = %llu;",
         (long long int) REPORT_FORMAT_FLAG_ACTIVE,
         report_format);
  else
    sql ("UPDATE report_formats SET flags = (flags & ~ %llu) WHERE ROWID = %llu;",
         (long long int) REPORT_FORMAT_FLAG_ACTIVE,
         report_format);
}

/**
 * @brief Return the name of a report format.
 *
 * @param[in]  report_format  Report format.
 *
 * @return Newly allocated name.
 */
char *
report_format_name (report_format_t report_format)
{
  return sql_string (0, 0,
                     "SELECT name FROM report_formats WHERE ROWID = %llu;",
                     report_format);
}

/**
 * @brief Return the content type of a report format.
 *
 * @param[in]  report_format  Report format.
 *
 * @return Newly allocated content type.
 */
char *
report_format_content_type (report_format_t report_format)
{
  return sql_string (0, 0,
                     "SELECT content_type FROM report_formats WHERE ROWID = %llu;",
                     report_format);
}


/**
 * @brief Return the extension of a report format.
 *
 * @param[in]  report_format  Report format.
 *
 * @return Newly allocated extension.
 */
char *
report_format_extension (report_format_t report_format)
{
  return sql_string (0, 0,
                     "SELECT extension FROM report_formats WHERE ROWID = %llu;",
                     report_format);
}

/**
 * @brief Set the name of the report format.
 *
 * @param[in]  report_format  The report format.
 * @param[in]  name           Name.
 */
void
set_report_format_name (report_format_t report_format, const char *name)
{
  gchar *quoted_name = sql_quote (name);
  sql ("UPDATE report_formats SET name = '%s' WHERE ROWID = %llu;",
       quoted_name,
       report_format);
  g_free (quoted_name);
}

/**
 * @brief Return whether a report format is global.
 *
 * @param[in]  report_format  Report format.
 *
 * @return 1 if global, else 0.
 */
int
report_format_global (report_format_t report_format)
{
  return sql_int (0, 0,
                  "SELECT owner is NULL FROM report_formats"
                  " WHERE ROWID = %llu;",
                  report_format);
}

/**
 * @brief Return whether a report format is active.
 *
 * @param[in]  report_format  Report format.
 *
 * @return -1 on error, 1 if active, else 0.
 */
int
report_format_active (report_format_t report_format)
{
  long long int flag;
  switch (sql_int64 (&flag, 0, 0,
                     "SELECT flags & %llu FROM report_formats"
                     " WHERE ROWID = %llu;",
                     (long long int) REPORT_FORMAT_FLAG_ACTIVE,
                     report_format))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        return 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        return -1;
        break;
    }
  return flag ? 1 : 0;
}

/**
 * @brief Set the summary of the report format.
 *
 * @param[in]  report_format  The report format.
 * @param[in]  summary        Summary.
 */
void
set_report_format_summary (report_format_t report_format, const char *summary)
{
  gchar *quoted_summary = sql_quote (summary);
  sql ("UPDATE report_formats SET summary = '%s' WHERE ROWID = %llu;",
       quoted_summary,
       report_format);
  g_free (quoted_summary);
}

/**
 * @brief Return the type max of a report format param.
 *
 * @param[in]  report_format  Report format.
 * @param[in]  name           Name of param.
 *
 * @return Param type.
 */
static report_format_param_type_t
report_format_param_type (report_format_t report_format, const char *name)
{
  report_format_param_type_t type;
  gchar *quoted_name = sql_quote (name);
  type = (report_format_param_type_t)
         sql_int (0, 0,
                  "SELECT type FROM report_format_params"
                  " WHERE report_format = %llu AND name = '%s';",
                  report_format,
                  quoted_name);
  g_free (quoted_name);
  return type;
}

/**
 * @brief Return the type max of a report format param.
 *
 * @param[in]  report_format  Report format.
 * @param[in]  name           Name of param.
 *
 * @return Max.
 */
static long long int
report_format_param_type_max (report_format_t report_format, const char *name)
{
  long long int max = 0;
  gchar *quoted_name = sql_quote (name);
  /* Assume it's there. */
  sql_int64 (&max, 0, 0,
             "SELECT type_max FROM report_format_params"
             " WHERE report_format = %llu AND name = '%s';",
             report_format,
             quoted_name);
  g_free (quoted_name);
  return max;
}

/**
 * @brief Return the type min of a report format param.
 *
 * @param[in]  report_format  Report format.
 * @param[in]  name           Name of param.
 *
 * @return Min.
 */
static long long int
report_format_param_type_min (report_format_t report_format, const char *name)
{
  long long int min = 0;
  gchar *quoted_name = sql_quote (name);
  /* Assume it's there. */
  sql_int64 (&min, 0, 0,
             "SELECT type_min FROM report_format_params"
             " WHERE report_format = %llu AND name = '%s';",
             report_format,
             quoted_name);
  g_free (quoted_name);
  return min;
}


/**
 * @brief Validate a value for a report format param.
 *
 * @param[in]  report_format  Report format.
 * @param[in]  param          Param.
 * @param[in]  name           Name of param.
 * @param[in]  value          Potential value of param.
 *
 * @return 0 success, 1 fail.
 */
static int
validate_param_value (report_format_t report_format,
                      report_format_param_t param, const char *name,
                      const char *value)
{
  switch (report_format_param_type (report_format, name))
    {
      case REPORT_FORMAT_PARAM_TYPE_INTEGER:
        {
          long long int min, max, actual;
          min = report_format_param_type_min (report_format, name);
          /* Simply truncate out of range values. */
          actual = strtoll (value, NULL, 0);
          if (actual < min)
            return 1;
          max = report_format_param_type_max (report_format, name);
          if (actual > max)
            return 1;
        }
        break;
      case REPORT_FORMAT_PARAM_TYPE_SELECTION:
        {
          iterator_t options;
          int found = 0;

          init_param_option_iterator (&options, param, 1, NULL);
          while (next (&options))
            if (param_option_iterator_value (&options)
                && (strcmp (param_option_iterator_value (&options), value)
                    == 0))
              {
                found = 1;
                break;
              }
          cleanup_iterator (&options);
          if (found)
            break;
          return 1;
        }
      case REPORT_FORMAT_PARAM_TYPE_STRING:
      case REPORT_FORMAT_PARAM_TYPE_TEXT:
        {
          long long int min, max, actual;
          min = report_format_param_type_min (report_format, name);
          actual = strlen (value);
          if (actual < min)
            return 1;
          max = report_format_param_type_max (report_format, name);
          if (actual > max)
            return 1;
        }
        break;
      default:
        break;
    }
  return 0;
}

/**
 * @brief Set the value of the report format param.
 *
 * @param[in]  report_format  The report format.
 * @param[in]  name           Param name.
 * @param[in]  value_64       Param value in base64.
 *
 * @return 0 success, 1 failed to find param, 2 validation of value failed,
 *         -1 error.
 */
int
set_report_format_param (report_format_t report_format, const char *name,
                         const char *value_64)
{
  gchar *quoted_name, *quoted_value, *value;
  gsize value_size;
  report_format_param_t param;

  quoted_name = sql_quote (name);

  sql ("BEGIN IMMEDIATE;");

  /* Ensure the param exists. */

  switch (sql_int64 (&param, 0, 0,
                     "SELECT ROWID FROM report_format_params"
                     " WHERE name = '%s';",
                     quoted_name))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        g_free (quoted_name);
        sql ("ROLLBACK;");
        return 1;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        g_free (quoted_name);
        sql ("ROLLBACK;");
        return -1;
        break;
    }

  /* Translate the value. */

  if (value_64 && strlen (value_64))
    value = (gchar*) g_base64_decode (value_64, &value_size);
  else
    {
      value = g_strdup ("");
      value_size = 0;
    }

  /* Validate the value. */

  if (validate_param_value (report_format, param, name, value))
    {
      sql ("ROLLBACK;");
      g_free (quoted_name);
      return 2;
    }

  quoted_value = sql_quote (value);
  g_free (value);

  /* Update the database. */

  sql ("UPDATE report_format_params SET value = '%s'"
       " WHERE report_format = %llu AND name = '%s';",
       quoted_value,
       report_format,
       quoted_name);

  g_free (quoted_name);
  g_free (quoted_value);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Initialise a report format iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  report_format  Single report_format to iterate over, or 0 for all.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for "ROWID".
 */
void
init_report_format_iterator (iterator_t* iterator, report_format_t report_format,
                             int ascending, const char* sort_field)
{
  if (report_format)
    init_iterator (iterator,
                   "SELECT ROWID, uuid, name, extension, content_type,"
                   " summary, description, owner IS NULL, signature, trust,"
                   " trust_time, flags"
                   " FROM report_formats"
                   " WHERE ROWID = %llu"
                   " AND ((owner IS NULL) OR (owner ="
                   " (SELECT ROWID FROM users WHERE users.uuid = '%s')))"
                   " ORDER BY %s %s;",
                   report_format,
                   current_credentials.uuid,
                   sort_field ? sort_field : "ROWID",
                   ascending ? "ASC" : "DESC");
  else
    init_iterator (iterator,
                   "SELECT ROWID, uuid, name, extension, content_type,"
                   " summary, description, owner is NULL, signature, trust,"
                   " trust_time, flags"
                   " FROM report_formats"
                   " WHERE ((owner IS NULL) OR (owner ="
                   " (SELECT ROWID FROM users WHERE users.uuid = '%s')))"
                   " ORDER BY %s %s;",
                   current_credentials.uuid,
                   sort_field ? sort_field : "ROWID",
                   ascending ? "ASC" : "DESC");
}

/**
 * @brief Get the report format from a report format iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Report_Format.
 */
report_format_t
report_format_iterator_report_format (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return (report_format_t) sqlite3_column_int64 (iterator->stmt, 0);
}

/**
 * @brief Get the UUID from a report format iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return UUID, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (report_format_iterator_uuid, 1);

/**
 * @brief Get the name from a report format iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (report_format_iterator_name, 2);

/**
 * @brief Get the extension from a report format iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Extension, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (report_format_iterator_extension, 3);

/**
 * @brief Get the content type from a report format iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Content type, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (report_format_iterator_content_type, 4);

/**
 * @brief Get the summary from a report format iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Summary, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (report_format_iterator_summary, 5);

/**
 * @brief Get the description from a report format iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Description, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (report_format_iterator_description, 6);

/**
 * @brief Get the global state from a report format iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Global flag, or -1 if iteration is complete.
 */
int
report_format_iterator_global (iterator_t* iterator)
{
  if (iterator->done) return -1;
  return sqlite3_column_int (iterator->stmt, 7);
}

/**
 * @brief Get the signature from a report format iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Signature, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (report_format_iterator_signature, 8);

/**
 * @brief Get the trust value from a report format iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Trust value.
 */
const char*
report_format_iterator_trust (iterator_t* iterator)
{
  if (iterator->done) return NULL;
  switch (sqlite3_column_int (iterator->stmt, 9))
    {
      case 1:  return "yes";
      case 2:  return "no";
      case 3:  return "unknown";
      default: return NULL;
    }
}

/**
 * @brief Get the trust time from a report format iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Time report format was verified.
 */
time_t
report_format_iterator_trust_time (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (time_t) sqlite3_column_int (iterator->stmt, 10);
  return ret;
}

/**
 * @brief Get the active flag from a report format iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Active flag, or -1 if iteration is complete.
 */
int
report_format_iterator_active (iterator_t* iterator)
{
  if (iterator->done) return -1;
  return (sqlite3_column_int64 (iterator->stmt, 11) & REPORT_FORMAT_FLAG_ACTIVE)
          ? 1 : 0;
}

/**
 * @brief Initialise a report format iterator.
 *
 * @param[in]  iterator       Iterator.
 * @param[in]  report_format  Single report_format to iterate over, or 0 for all.
 * @param[in]  ascending      Whether to sort ascending or descending.
 * @param[in]  sort_field     Field to sort on, or NULL for "ROWID".
 */
void
init_report_format_param_iterator (iterator_t* iterator, report_format_t report_format,
                                   int ascending, const char* sort_field)
{
  if (report_format)
    init_iterator (iterator,
                   "SELECT ROWID, name, value, type, type_min, type_max,"
                   " type_regex, fallback"
                   " FROM report_format_params"
                   " WHERE report_format = %llu"
                   " ORDER BY %s %s;",
                   report_format,
                   sort_field ? sort_field : "ROWID",
                   ascending ? "ASC" : "DESC");
  else
    init_iterator (iterator,
                   "SELECT ROWID, name, value, type, type_min, type_max,"
                   " type_regex, fallback"
                   " FROM report_format_params"
                   " ORDER BY %s %s;",
                   sort_field ? sort_field : "ROWID",
                   ascending ? "ASC" : "DESC");
}

/**
 * @brief Get the report format param from a report format param iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Report format param.
 */
report_format_param_t
report_format_param_iterator_param (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return (report_format_param_t) sqlite3_column_int64 (iterator->stmt, 0);
}

/**
 * @brief Get the name from a report format param iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (report_format_param_iterator_name, 1);

/**
 * @brief Get the value from a report format param iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (report_format_param_iterator_value, 2);

/**
 * @brief Get the name of the type of a report format param iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Static string naming type, or NULL if iteration is complete.
 */
const char *
report_format_param_iterator_type_name (iterator_t* iterator)
{
  if (iterator->done) return NULL;
  return report_format_param_type_name (sqlite3_column_int (iterator->stmt, 3));
}

/**
 * @brief Get the type from a report format param iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Type.
 */
report_format_param_type_t
report_format_param_iterator_type (iterator_t* iterator)
{
  if (iterator->done) return -1;
  return sqlite3_column_int (iterator->stmt, 3);
}

/**
 * @brief Get the type min from a report format param iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Type min.
 */
long long int
report_format_param_iterator_type_min (iterator_t* iterator)
{
  if (iterator->done) return -1;
  return sqlite3_column_int64 (iterator->stmt, 4);
}

/**
 * @brief Get the type max from a report format param iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Type max.
 */
long long int
report_format_param_iterator_type_max (iterator_t* iterator)
{
  if (iterator->done) return -1;
  return sqlite3_column_int64 (iterator->stmt, 5);
}

/**
 * @brief Get the type regex from a report format param iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Type regex, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (report_format_param_iterator_type_regex, 6);

/**
 * @brief Get the default from a report format param iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Default, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (report_format_param_iterator_fallback, 7);

/**
 * @brief Initialise a report format param option iterator.
 *
 * @param[in]  iterator             Iterator.
 * @param[in]  report_format_param  Param whose options to iterate over.
 * @param[in]  ascending            Whether to sort ascending or descending.
 * @param[in]  sort_field           Field to sort on, or NULL for "ROWID".
 */
void
init_param_option_iterator (iterator_t* iterator,
                            report_format_param_t report_format_param,
                            int ascending, const char *sort_field)
{
  init_iterator (iterator,
                 "SELECT ROWID, value"
                 " FROM report_format_param_options"
                 " WHERE report_format_param = %llu"
                 " ORDER BY %s %s;",
                 report_format_param,
                 sort_field ? sort_field : "ROWID",
                 ascending ? "ASC" : "DESC");
}

/**
 * @brief Get the value from a report format param option iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Value, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (param_option_iterator_value, 1);


/* Slaves. */

/**
 * @brief Find a slave given a UUID.
 *
 * @param[in]   uuid   UUID of slave.
 * @param[out]  slave  Slave return, 0 if succesfully failed to find slave.
 *
 * @return FALSE on success (including if failed to find slave), TRUE on error.
 */
gboolean
find_slave (const char* uuid, slave_t* slave)
{
  gchar *quoted_uuid = sql_quote (uuid);
  if (user_owns_uuid ("slave", quoted_uuid) == 0)
    {
      g_free (quoted_uuid);
      *slave = 0;
      return FALSE;
    }
  switch (sql_int64 (slave, 0, 0,
                     "SELECT ROWID FROM slaves WHERE uuid = '%s';",
                     quoted_uuid))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *slave = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        g_free (quoted_uuid);
        return TRUE;
        break;
    }

  g_free (quoted_uuid);
  return FALSE;
}

/**
 * @brief Create a slave.
 *
 * @param[in]   name            Name of slave.
 * @param[in]   comment         Comment on slave.
 * @param[in]   host            Host of slave.
 * @param[in]   port            Port on host.
 * @param[in]   login           Host login name.
 * @param[in]   password        Password for \p login.
 * @param[out]  slave           NULL, or address for created slave.
 *
 * @return 0 success, 1 slave exists already, -1 error.
 */
int
create_slave (const char* name, const char* comment, const char* host,
              const char* port, const char* login, const char* password,
              slave_t* slave)
{
  gchar *quoted_name, *quoted_host, *quoted_port, *quoted_login;
  gchar *quoted_password;

  assert (name);
  assert (host);
  assert (port);
  assert (login);
  assert (password);

  quoted_name = sql_quote (name);

  sql ("BEGIN IMMEDIATE;");

  assert (current_credentials.uuid);

  /* Check whether a slave with the same name exists already. */
  if (sql_int (0, 0,
               "SELECT COUNT(*) FROM slaves"
               " WHERE name = '%s'"
               " AND ((owner IS NULL) OR (owner ="
               " (SELECT users.ROWID FROM users WHERE users.uuid = '%s')));",
               quoted_name,
               current_credentials.uuid))
    {
      g_free (quoted_name);
      sql ("ROLLBACK;");
      return 1;
    }

  quoted_host = sql_quote (host);
  quoted_port = sql_quote (port);
  quoted_login = sql_quote (login);
  quoted_password = sql_quote (password);

  if (comment)
    {
      gchar *quoted_comment = sql_quote (comment);
      sql ("INSERT INTO slaves"
           " (uuid, name, owner, comment, host, port, login, password)"
           " VALUES (make_uuid (), '%s',"
           " (SELECT ROWID FROM users WHERE users.uuid = '%s'),"
           " '%s', '%s', '%s', '%s', '%s');",
           quoted_name, current_credentials.uuid, quoted_comment, quoted_host,
           quoted_port, quoted_login, quoted_password);
      g_free (quoted_comment);
    }
  else
    sql ("INSERT INTO slaves"
         " (uuid, name, owner, comment, host, port, login, password)"
         " VALUES (make_uuid (), '%s',"
         " (SELECT ROWID FROM users WHERE users.uuid = '%s'),"
         " '%s', '', '%s', '%s', '%s');",
         quoted_name, current_credentials.uuid, quoted_host, quoted_port,
         quoted_login, quoted_password);

  if (slave)
    *slave = sqlite3_last_insert_rowid (task_db);

  g_free (quoted_name);
  g_free (quoted_host);
  g_free (quoted_port);
  g_free (quoted_login);
  g_free (quoted_password);

  sql ("COMMIT;");

  return 0;
}

/**
 * @brief Delete a slave.
 *
 * @param[in]  slave  Slave.
 *
 * @return 0 success, 1 fail because a task refers to the slave, -1 error.
 */
int
delete_slave (slave_t slave)
{
  sql ("BEGIN IMMEDIATE;");
  if (sql_int (0, 0,
               "SELECT count(*) FROM tasks WHERE slave = %llu;",
               slave))
    {
      sql ("ROLLBACK;");
      return 1;
    }
  sql ("DELETE FROM slaves WHERE ROWID = %llu;", slave);
  sql ("COMMIT;");
  return 0;
}

/**
 * @brief Initialise a slave iterator.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  slave       Slave to limit iteration to.  0 for all.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for "ROWID".
 */
void
init_slave_iterator (iterator_t* iterator, slave_t slave, int ascending,
                     const char* sort_field)
{
  assert (current_credentials.uuid);

  if (slave)
    init_iterator (iterator,
                   "SELECT ROWID, uuid, name, comment, host, port, login,"
                   " password"
                   " FROM slaves"
                   " WHERE ROWID = %llu"
                   " AND ((owner IS NULL) OR (owner ="
                   " (SELECT ROWID FROM users WHERE users.uuid = '%s')))"
                   " ORDER BY %s %s;",
                   slave,
                   current_credentials.uuid,
                   sort_field ? sort_field : "ROWID",
                   ascending ? "ASC" : "DESC");
  else
    init_iterator (iterator,
                   "SELECT ROWID, uuid, name, comment, host, port, login,"
                   " password"
                   " FROM slaves"
                   " WHERE ((owner IS NULL) OR (owner ="
                   " (SELECT ROWID FROM users WHERE users.uuid = '%s')))"
                   " ORDER BY %s %s;",
                   current_credentials.uuid,
                   sort_field ? sort_field : "ROWID",
                   ascending ? "ASC" : "DESC");
}

/**
 * @brief Get the slave from a slave iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Slave.
 */
slave_t
slave_iterator_slave (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return (slave_t) sqlite3_column_int64 (iterator->stmt, 0);
}

/**
 * @brief Get the UUID of the slave from a slave iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return UUID of the slave or NULL if iteration is complete.
 */
DEF_ACCESS (slave_iterator_uuid, 1);

/**
 * @brief Get the name of the slave from a slave iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name of the slave or NULL if iteration is complete.
 */
DEF_ACCESS (slave_iterator_name, 2);

/**
 * @brief Get the comment from a slave iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Comment.
 */
const char*
slave_iterator_comment (iterator_t* iterator)
{
  const char *ret;
  if (iterator->done) return "";
  ret = (const char*) sqlite3_column_text (iterator->stmt, 3);
  return ret ? ret : "";
}

/**
 * @brief Get the host of the slave from a slave iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Host of the slave or NULL if iteration is complete.
 */
DEF_ACCESS (slave_iterator_host, 4);

/**
 * @brief Get the port of the slave from a slave iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Port of the slave or NULL if iteration is complete.
 */
DEF_ACCESS (slave_iterator_port, 5);

/**
 * @brief Get the login of the slave from a slave iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Login of the slave or NULL if iteration is complete.
 */
DEF_ACCESS (slave_iterator_login, 6);

/**
 * @brief Get the password of the slave from a slave iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Password of the slave or NULL if iteration is complete.
 */
DEF_ACCESS (slave_iterator_password, 7);

/**
 * @brief Return the UUID of a slave.
 *
 * @param[in]  slave  Slave.
 *
 * @return Newly allocated UUID if available, else NULL.
 */
char*
slave_uuid (slave_t slave)
{
  return sql_string (0, 0,
                     "SELECT uuid FROM slaves WHERE ROWID = %llu;",
                     slave);
}

/**
 * @brief Return the name of a slave.
 *
 * @param[in]  slave  Slave.
 *
 * @return Newly allocated name if available, else NULL.
 */
char*
slave_name (slave_t slave)
{
  return sql_string (0, 0,
                     "SELECT name FROM slaves WHERE ROWID = %llu;",
                     slave);
}

/**
 * @brief Return the host associated with a slave.
 *
 * @param[in]  slave  Slave.
 *
 * @return Newly allocated host if available, else NULL.
 */
char*
slave_host (slave_t slave)
{
  return sql_string (0, 0,
                     "SELECT host FROM slaves WHERE ROWID = %llu;",
                     slave);
}

/**
 * @brief Return the login associated with a slave.
 *
 * @param[in]  slave  Slave.
 *
 * @return Newly allocated login if available, else NULL.
 */
char*
slave_login (slave_t slave)
{
  return sql_string (0, 0,
                     "SELECT login FROM slaves WHERE ROWID = %llu;",
                     slave);
}

/**
 * @brief Return the password associated with a slave.
 *
 * @param[in]  slave  Slave.
 *
 * @return Newly allocated password if available, else NULL.
 */
char*
slave_password (slave_t slave)
{
  return sql_string (0, 0,
                     "SELECT password FROM slaves WHERE ROWID = %llu;",
                     slave);
}

/**
 * @brief Return the port associated with a slave.
 *
 * @param[in]  slave  Slave.
 *
 * @return Port number on success; -1 on error.
 */
int
slave_port (slave_t slave)
{
  int ret;
  char *port = sql_string (0, 0,
                           "SELECT port FROM slaves WHERE ROWID = %llu;",
                           slave);
  if (port == NULL)
    return -1;
  ret = atoi (port);
  free (port);
  return ret;
}

/**
 * @brief Set the host associated with a slave.
 *
 * @param[in]  slave  Slave.
 * @param[in]  host   New value for host.
 */
void
set_slave_host (slave_t slave, const char *host)
{
  gchar* quoted_host;

  assert (host);

  quoted_host = sql_quote (host);
  sql ("UPDATE slaves SET host = '%s' WHERE ROWID = %llu;",
       quoted_host, slave);
  g_free (quoted_host);
}

/**
 * @brief Return whether a slave is referenced by a task
 *
 * @param[in]  slave  Slave.
 *
 * @return 1 if in use, else 0.
 */
int
slave_in_use (slave_t slave)
{
  return sql_int (0, 0,
                  "SELECT count(*) FROM tasks WHERE slave = %llu;",
                  slave);
}

/**
 * @brief Initialise a slave task iterator.
 *
 * Iterates over all tasks that use the slave.
 *
 * @param[in]  iterator   Iterator.
 * @param[in]  slave      Slave.
 * @param[in]  ascending  Whether to sort ascending or descending.
 */
void
init_slave_task_iterator (iterator_t* iterator, slave_t slave, int ascending)
{
  assert (current_credentials.uuid);

  init_iterator (iterator,
                 "SELECT name, uuid FROM tasks"
                 " WHERE slave = %llu"
                 " AND hidden = 0"
                 " AND ((owner IS NULL) OR (owner ="
                 " (SELECT ROWID FROM users WHERE users.uuid = '%s')))"
                 " ORDER BY name %s;",
                 slave,
                 current_credentials.uuid,
                 ascending ? "ASC" : "DESC");
}

/**
 * @brief Get the name from a slave task iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The name of the host, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (slave_task_iterator_name, 0);

/**
 * @brief Get the uuid from a slave task iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The uuid of the host, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (slave_task_iterator_uuid, 1);


/* Schema. */

/**
 * @brief Generate the OMP schema.
 *
 * @param[in]  format         Name of schema format, "XML" or NULL for XML.
 * @param[out] output_return  NULL or location for output.
 * @param[out] output_length  NULL or location for length of output.
 * @param[out] extension      NULL or location for report format extension.
 * @param[out] content_type   NULL or location for report format content type.
 *
 * @return 0 success, 1 failed to find schema format, -1 error.
 */
int
manage_schema (gchar *format, gchar **output_return, gsize *output_length,
               gchar **extension, gchar **content_type)
{
  /* Pass the XML file to the report format generate script, sending the output
   * to a file. */

  {
    gchar *script, *script_dir;
    gchar *uuid_format;
    char output_dir[] = "/tmp/openvasmd_schema_XXXXXX";

    if (mkdtemp (output_dir) == NULL)
      {
        g_warning ("%s: mkdtemp failed\n", __FUNCTION__);
        return -1;
      }

    /* Setup file names. */

    if (format == NULL)
      {
        if (extension)
          *extension = g_strdup ("xml");
        if (content_type)
          *content_type = g_strdup ("text/xml");
        uuid_format = "18e826fc-dab6-11df-b913-002264764cea";
      }
    else if (strcasecmp (format, "HTML") == 0)
      {
        if (extension)
          *extension = g_strdup ("html");
        if (content_type)
          *content_type = g_strdup ("text/html");
        uuid_format = "02052818-dab6-11df-9be4-002264764cea";
      }
    else if (strcasecmp (format, "RNC") == 0)
      {
        if (extension)
          *extension = g_strdup ("rnc");
        if (content_type)
          *content_type = g_strdup ("text/x-rnc");
        uuid_format = "787a4a18-dabc-11df-9486-002264764cea";
      }
    else if (strcasecmp (format, "XML") == 0)
      {
        if (extension)
          *extension = g_strdup ("xml");
        if (content_type)
          *content_type = g_strdup ("text/xml");
        uuid_format = "18e826fc-dab6-11df-b913-002264764cea";
      }
    else
      return 1;

    script_dir = g_build_filename (OPENVAS_SYSCONF_DIR,
                                   "openvasmd",
                                   "global_schema_formats",
                                   uuid_format,
                                   NULL);

    script = g_build_filename (script_dir, "generate", NULL);

    if (!g_file_test (script, G_FILE_TEST_EXISTS))
      {
        g_free (script);
        g_free (script_dir);
        if (extension) g_free (*extension);
        if (content_type) g_free (*content_type);
        return -1;
      }

    {
      gchar *output_file, *command;
      char *previous_dir;
      int ret;

      /* Change into the script directory. */

      /** @todo NULL arg is glibc extension. */
      previous_dir = getcwd (NULL, 0);
      if (previous_dir == NULL)
        {
          g_warning ("%s: Failed to getcwd: %s\n",
                     __FUNCTION__,
                     strerror (errno));
          g_free (previous_dir);
          g_free (script);
          g_free (script_dir);
          if (extension) g_free (*extension);
          if (content_type) g_free (*content_type);
          return -1;
        }

      if (chdir (script_dir))
        {
          g_warning ("%s: Failed to chdir: %s\n",
                     __FUNCTION__,
                     strerror (errno));
          g_free (previous_dir);
          g_free (script);
          g_free (script_dir);
          if (extension) g_free (*extension);
          if (content_type) g_free (*content_type);
          return -1;
        }
      g_free (script_dir);

      output_file = g_strdup_printf ("%s/report.out", output_dir);

      /* Call the script. */

      command = g_strdup_printf ("/bin/sh %s " OPENVAS_SYSCONF_DIR
                                 "/openvasmd/global_schema_formats"
                                 "/18e826fc-dab6-11df-b913-002264764cea/OMP.xml"
                                 " > %s"
                                 " 2> /dev/null",
                                 script,
                                 output_file);
      g_free (script);

      g_debug ("   command: %s\n", command);

      /* RATS: ignore, command is defined above. */
      if (ret = system (command),
          /** @todo ret is always -1. */
          0 && ((ret) == -1
                || WEXITSTATUS (ret)))
        {
          g_warning ("%s: system failed with ret %i, %i, %s\n",
                     __FUNCTION__,
                     ret,
                     WEXITSTATUS (ret),
                     command);
          if (chdir (previous_dir))
            g_warning ("%s: and chdir failed\n",
                       __FUNCTION__);
          g_free (previous_dir);
          g_free (command);
          g_free (output_file);
          if (extension) g_free (*extension);
          if (content_type) g_free (*content_type);
          return -1;
        }

      {
        GError *get_error;
        gchar *output;
        gsize output_len;

        g_free (command);

        /* Change back to the previous directory. */

        if (chdir (previous_dir))
          {
            g_warning ("%s: Failed to chdir back: %s\n",
                       __FUNCTION__,
                       strerror (errno));
            g_free (previous_dir);
            if (extension) g_free (*extension);
            if (content_type) g_free (*content_type);
            return -1;
          }
        g_free (previous_dir);

        /* Read the script output from file. */

        get_error = NULL;
        g_file_get_contents (output_file,
                             &output,
                             &output_len,
                             &get_error);
        g_free (output_file);
        if (get_error)
          {
            g_warning ("%s: Failed to get output: %s\n",
                       __FUNCTION__,
                       get_error->message);
            g_error_free (get_error);
            if (extension) g_free (*extension);
            if (content_type) g_free (*content_type);
            return -1;
          }

        /* Remove the output directory. */

        file_utils_rmdir_rf (output_dir);

        /* Return the output. */

        if (output_length) *output_length = output_len;

        if (output_return) *output_return = output;
        return 0;
      }
    }
  }
}



#undef DEF_ACCESS
