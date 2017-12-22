/* OpenVAS Manager
 * $Id$
 * Description: Manager Manage library: SQLite specific Manage facilities.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2014 Greenbone Networks GmbH
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

#define _XOPEN_SOURCE /* Glibc2 needs this for strptime. */

#include "sql.h"
#include "manage.h"
#include "manage_utils.h"
#include "manage_acl.h"

#include <sqlite3.h>
#include <time.h>
#include <unistd.h>

#include <openvas/misc/openvas_uuid.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"


/* Variables */

extern sqlite3 *
task_db;


/* Headers of manage_sql.c functions also used here. */

gchar*
clean_hosts (const char *, int *);

char *
iso_time (time_t *);

int
days_from_now (time_t *);

long
current_offset (const char *);

int
user_can_everything (const char *);

int
user_owns (const char *, resource_t, int);

int
resource_name (const char *, const char *, int, gchar **);

int
resource_exists (const char *, resource_t, int);

int
parse_time (const gchar *, int *);

gchar *
tag_value (const gchar *tags, const gchar *tag);


/* Session. */

/**
 * @brief Setup session.
 *
 * @param[in]  uuid  User UUID.
 */
void
manage_session_init (const char *uuid)
{
  sql ("CREATE TEMPORARY TABLE IF NOT EXISTS current_credentials"
       " (id INTEGER PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  tz_override text);");
  sql ("DELETE FROM current_credentials;");
  if (uuid)
    sql ("INSERT INTO current_credentials (uuid) VALUES ('%s');", uuid);
}

/**
 * @brief Setup session timezone.
 *
 * @param[in]  timezone  Timezone.
 */
void
manage_session_set_timezone (const char *timezone)
{
  return;
}


/* Helpers. */

/**
 * @brief Check whether database is empty.
 *
 * @return 1 if empty, else 0;
 */
int
manage_db_empty ()
{
  return sql_int ("SELECT count (*) FROM main.sqlite_master"
                  " WHERE type = 'table'"
                  " AND name = 'meta';")
         == 0;
}


/* SQL functions. */

/**
 * @brief Return 1.
 *
 * This is a callback for a scalar SQL function of zero arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_t (sqlite3_context *context, int argc, sqlite3_value** argv)
{
  assert (argc == 0);

  sqlite3_result_int (context, 1);
}

/**
 * @brief Get position of a substring like the strpos function in PostgreSQL.
 *
 * This is a callback for a scalar SQL function of two arguments.
 * The SQLite function instr could be used as replacement, but is only
 *  available in versions >= 3.7.15.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_strpos (sqlite3_context *context, int argc,
            sqlite3_value** argv)
{
  const unsigned char *str, *substr, *substr_in_str;

  assert (argc == 2);

  str = sqlite3_value_text (argv[0]);
  substr = sqlite3_value_text (argv[1]);

  if (str == NULL)
    {
      sqlite3_result_error (context, "Failed to get string argument", -1);
      return;
    }

  if (substr == NULL)
    {
      sqlite3_result_error (context, "Failed to get substring argument", -1);
      return;
    }

  substr_in_str = (const unsigned char *)g_strrstr ((const gchar*)str,
                                                    (const gchar*)substr);

  sqlite3_result_int (context,
                      substr_in_str ? substr_in_str - str + 1 : 0);
}

/**
 * @brief Convert an IP address into a sortable form.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_order_inet (sqlite3_context *context, int argc, sqlite3_value** argv)
{
  const char *ip;
  unsigned int one, two, three, four;
  one = two = three = four = 0;
  gchar *ip_expanded;

  assert (argc == 1);

  ip = (const char *) sqlite3_value_text (argv[0]);
  if (ip == NULL)
    sqlite3_result_int (context, 0);
  else
    {
      if (g_regex_match_simple ("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$",
                                ip, 0, 0)
          && sscanf (ip, "%u.%u.%u.%u", &one, &two, &three, &four) == 4)
        {
          ip_expanded = g_strdup_printf ("%03u.%03u.%03u.%03u",
                                         one, two, three, four);
          sqlite3_result_text (context,
                               ip_expanded,
                               -1, SQLITE_TRANSIENT);
          g_free (ip_expanded);
        }
      else
        sqlite3_result_text (context, ip, -1, SQLITE_TRANSIENT);
    }
}

/**
 * @brief Convert a message type into an integer for sorting.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_order_message_type (sqlite3_context *context, int argc,
                        sqlite3_value** argv)
{
  const char *type;

  assert (argc == 1);

  type = (const char *) sqlite3_value_text (argv[0]);
  if (type == NULL)
    sqlite3_result_int (context, 8);
  else if (strcmp (type, "Security Hole") == 0)
    sqlite3_result_int (context, 1);
  else if (strcmp (type, "Security Warning") == 0)
    sqlite3_result_int (context, 2);
  else if (strcmp (type, "Security Note") == 0)
    sqlite3_result_int (context, 3);
  else if (strcmp (type, "Log Message") == 0)
    sqlite3_result_int (context, 4);
  else if (strcmp (type, "Debug Message") == 0)
    sqlite3_result_int (context, 5);
  else if (strcmp (type, "Error Message") == 0)
    sqlite3_result_int (context, 6);
  else
    sqlite3_result_int (context, 7);
}

/**
 * @brief Convert a port into an integer for sorting.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_order_port (sqlite3_context *context, int argc, sqlite3_value** argv)
{
  const char *port;
  int port_num;

  assert (argc == 1);

  port = (const char *) sqlite3_value_text (argv[0]);

  port_num = atoi (port);
  if (port_num > 0)
    sqlite3_result_int (context, port_num);
  else if (sscanf (port, "%*s (%i/%*s)", &port_num) == 1)
    sqlite3_result_int (context, port_num);
  else
    sqlite3_result_int (context, 0);
}

/**
 * @brief Convert a role for sorting.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_order_role (sqlite3_context *context, int argc, sqlite3_value** argv)
{
  const char *name;

  assert (argc == 1);

  name = (const char *) sqlite3_value_text (argv[0]);
  if (name == NULL)
    sqlite3_result_text (context, "", -1, SQLITE_TRANSIENT);
  else if (strcmp (name, "Admin") == 0)
    sqlite3_result_text (context, " !", -1, SQLITE_TRANSIENT);
  else
    sqlite3_result_text (context, name, -1, SQLITE_TRANSIENT);
}

/**
 * @brief Convert a threat into an integer for sorting.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_order_threat (sqlite3_context *context, int argc, sqlite3_value** argv)
{
  const char *type;

  assert (argc == 1);

  type = (const char *) sqlite3_value_text (argv[0]);
  if (type == NULL)
    sqlite3_result_int (context, 9);
  else if (strcmp (type, "High") == 0)
    sqlite3_result_int (context, 1);
  else if (strcmp (type, "Medium") == 0)
    sqlite3_result_int (context, 2);
  else if (strcmp (type, "Low") == 0)
    sqlite3_result_int (context, 3);
  else if (strcmp (type, "Log") == 0)
    sqlite3_result_int (context, 4);
  else if (strcmp (type, "Debug") == 0)
    sqlite3_result_int (context, 5);
  else if (strcmp (type, "False Positive") == 0)
    sqlite3_result_int (context, 6);
  else if (strcmp (type, "None") == 0)
    sqlite3_result_int (context, 7);
  else
    sqlite3_result_int (context, 8);
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
void
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
void
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
 * @brief Clean a host list.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_clean_hosts (sqlite3_context *context, int argc, sqlite3_value** argv)
{
  const unsigned char *hosts;
  gchar *clean;

  assert (argc == 1);

  hosts = sqlite3_value_text (argv[0]);
  if (hosts == NULL)
    {
      sqlite3_result_error (context, "Failed to get hosts argument", -1);
      return;
    }

  clean = clean_hosts ((gchar*) hosts, NULL);
  sqlite3_result_text (context, clean, -1, SQLITE_TRANSIENT);
  g_free (clean);
}

/**
 * @brief Make a name unique.
 *
 * This is a callback for a scalar SQL function of four argument.
 *
 * It's up to the caller to ensure there is a read-only transaction.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_uniquify (sqlite3_context *context, int argc, sqlite3_value** argv)
{
  const unsigned char *proposed_name, *type, *suffix;
  gchar *candidate_name, *quoted_candidate_name;
  unsigned int number;
  sqlite3_int64 owner;

  assert (argc == 4);

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

  suffix = sqlite3_value_text (argv[3]);
  if (suffix == NULL)
    {
      sqlite3_result_error (context,
                            "Failed to get suffix argument",
                            -1);
      return;
    }

  number = 0;
  candidate_name = g_strdup_printf ("%s%s%c%i", proposed_name, suffix,
                                    strcmp ((char*) type, "user") ? ' ' : '_',
                                    ++number);
  quoted_candidate_name = sql_quote (candidate_name);

  while (sql_int ("SELECT COUNT (*) FROM %ss WHERE name = '%s'"
                   " AND ((owner IS NULL) OR (owner = %llu));",
                  type,
                  quoted_candidate_name,
                  owner))
    {
      g_free (candidate_name);
      g_free (quoted_candidate_name);
      candidate_name = g_strdup_printf ("%s%s%c%u", proposed_name, suffix,
                                        strcmp ((char*) type, "user")
                                          ? ' '
                                          : '_',
                                        ++number);
      quoted_candidate_name = sql_quote (candidate_name);
    }

  g_free (quoted_candidate_name);

  sqlite3_result_text (context, candidate_name, -1, SQLITE_TRANSIENT);
  g_free (candidate_name);
}

/**
 * @brief Convert an epoch time into a string in ISO format.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_iso_time (sqlite3_context *context, int argc, sqlite3_value** argv)
{
  time_t epoch_time;

  assert (argc == 1);

  epoch_time = sqlite3_value_int (argv[0]);
  if (epoch_time == 0)
    sqlite3_result_text (context, "", -1, SQLITE_TRANSIENT);
  else
    {
      const char *iso;

      iso = iso_time (&epoch_time);
      if (iso)
        sqlite3_result_text (context, iso, -1, SQLITE_TRANSIENT);
      else
        sqlite3_result_error (context, "Failed to format time", -1);
    }
}

/**
 * @brief Calculate difference between now and epoch time in days
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_days_from_now (sqlite3_context *context, int argc, sqlite3_value** argv)
{
  time_t epoch_time;

  assert (argc == 1);

  epoch_time = sqlite3_value_int (argv[0]);
  if (epoch_time == 0)
    sqlite3_result_int (context, -2);
  else
    {
      int days;

      days = days_from_now (&epoch_time);
      sqlite3_result_int (context, days);
    }
}

/**
 * @brief Try convert an OTP NVT tag time string into epoch time.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * This is only used by the SQLite backend, in the SQL of some older migrators.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_parse_time (sqlite3_context *context, int argc, sqlite3_value** argv)
{
  const gchar *string;
  int epoch_time;

  assert (argc == 1);

  string = (const gchar *) sqlite3_value_text (argv[0]);

  switch (parse_time (string, &epoch_time))
    {
      case -1:
        g_warning ("%s: Failed to parse time: %s", __FUNCTION__, string);
        sqlite3_result_int (context, 0);
        break;
      case -2:
        g_warning ("%s: Failed to make time: %s", __FUNCTION__, string);
        sqlite3_result_int (context, 0);
        break;
      case -3:
        g_warning ("%s: Failed to parse timezone offset: %s",
                   __FUNCTION__,
                   string);
        sqlite3_result_int (context, 0);
        break;
      default:
        sqlite3_result_int (context, epoch_time);
    }
}

/**
 * @brief Calculate the next time from now given a start time and a period.
 *
 * This is a callback for a scalar SQL function of three to five arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_next_time (sqlite3_context *context, int argc, sqlite3_value** argv)
{
  time_t first;
  time_t period;
  int period_months, periods_offset;
  const char *timezone;

  assert (argc == 3 || argc == 4 || argc == 5);

  first = sqlite3_value_int (argv[0]);
  period = sqlite3_value_int (argv[1]);
  period_months = sqlite3_value_int (argv[2]);
  if (argc < 4 || sqlite3_value_type (argv[3]) == SQLITE_NULL)
    timezone = NULL;
  else
    timezone = (char*) sqlite3_value_text (argv[3]);

  if (argc < 5 || sqlite3_value_type (argv[4]) == SQLITE_NULL)
    periods_offset = 0;
  else
    periods_offset = sqlite3_value_int (argv[4]);

  sqlite3_result_int (context,
                      next_time (first, period, period_months, timezone,
                                 periods_offset));
}

/**
 * @brief Get the current time as an epoch integer.
 *
 * This is a callback for a scalar SQL function of zero arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_now (sqlite3_context *context, int argc, sqlite3_value** argv)
{
  assert (argc == 0);
  sqlite3_result_int (context, time (NULL));
}

/**
 * @brief Extract a tag from an OTP tag list.
 *
 * This is a callback for a scalar SQL function of two arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_tag (sqlite3_context *context, int argc, sqlite3_value** argv)
{
  const char *tags, *tag;
  gchar *value;

  assert (argc == 2);

  tags = (char*) sqlite3_value_text (argv[0]);
  if (tags == NULL)
    {
      sqlite3_result_error (context, "Failed to get tags argument", -1);
      return;
    }

  tag = (char*) sqlite3_value_text (argv[1]);
  if (tag == NULL)
    {
      sqlite3_result_error (context, "Failed to get tag argument", -1);
      return;
    }

  value = tag_value (tags, tag);
  sqlite3_result_text (context, value, -1, SQLITE_TRANSIENT);
  g_free (value);

  return;
}

/**
 * @brief Return number of hosts.
 *
 * This is a callback for a scalar SQL function of two arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_max_hosts (sqlite3_context *context, int argc, sqlite3_value** argv)
{
  const unsigned char *hosts, *exclude_hosts;
  gchar *max;

  assert (argc == 2);

  hosts = sqlite3_value_text (argv[0]);
  if (hosts == NULL)
    {
      /* Seems this happens when the query result is empty. */
      sqlite3_result_text (context, "0", -1, SQLITE_TRANSIENT);
      return;
    }
  exclude_hosts = sqlite3_value_text (argv[1]);

  max = g_strdup_printf ("%i", manage_count_hosts ((gchar*) hosts,
                                                   (gchar *) exclude_hosts));
  sqlite3_result_text (context, max, -1, SQLITE_TRANSIENT);
  g_free (max);
}

/**
 * @brief Move data from a table to a new table, heeding column rename.
 *
 * @param[in]  old_table  Existing table.
 * @param[in]  new_table  New empty table with renamed column.
 * @param[in]  old_name   Name of column in old table.
 * @param[in]  new_name   Name of column in new table.
 */
void
sql_rename_column (const char *old_table, const char *new_table,
                   const char *old_name, const char *new_name)
{
  iterator_t rows;

  /* Get a row with all columns. */

  init_iterator (&rows, "SELECT * FROM %s LIMIT 1;", old_table);
  if (next (&rows))
    {
      GString *one, *two;
      int end, column, first;

      /* Build the INSERT query from the column names in the row. */

      one = g_string_new ("");
      g_string_append_printf (one, "INSERT INTO %s (", new_table);

      two = g_string_new (") SELECT ");

      end = iterator_column_count (&rows);
      first = 1;
      for (column = 0; column < end; column++)
        {
          const char *name;
          name = iterator_column_name (&rows, column);
          g_string_append_printf (one, "%s%s",
                                  (first ? "" : ", "),
                                  (strcmp (name, old_name) == 0
                                    ? new_name
                                    : name));
          if (first)
            first = 0;
          else
            g_string_append (two, ", ");
          g_string_append (two, name);
        }
      cleanup_iterator (&rows);

      g_string_append_printf (one, "%s FROM %s;", two->str, old_table);

      /* Run the INSERT query. */

      sql (one->str);

      g_string_free (one, TRUE);
      g_string_free (two, TRUE);
    }
  else
    cleanup_iterator (&rows);
}

/**
 * @brief Check if two CVE lists contain a common CVE.
 *
 * This is a callback for a scalar SQL function of two arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_common_cve (sqlite3_context *context, int argc, sqlite3_value** argv)
{
  gchar **split_1, **split_2, **point_1, **point_2;
  const unsigned char *cve1, *cve2;

  assert (argc == 2);

  g_debug ("   %s: top\n", __FUNCTION__);

  cve1 = sqlite3_value_text (argv[0]);
  if (cve1 == NULL)
    {
      sqlite3_result_error (context, "Failed to get first CVE argument", -1);
      return;
    }

  cve2 = sqlite3_value_text (argv[1]);
  if (cve2 == NULL)
    {
      sqlite3_result_error (context, "Failed to get second CVE argument", -1);
      return;
    }

  split_1 = g_strsplit ((gchar*) cve1, ",", 0);
  split_2 = g_strsplit ((gchar*) cve2, ",", 0);
  point_1 = split_1;
  point_2 = split_2;
  while (*point_1)
    {
      while (*point_2)
        {
          g_debug ("   %s: %s vs %s\n", __FUNCTION__, g_strstrip (*point_1), g_strstrip (*point_2));
          if (strcmp (g_strstrip (*point_1), g_strstrip (*point_2)) == 0)
            {
              g_strfreev (split_1);
              g_strfreev (split_2);
              sqlite3_result_int (context, 1);
              return;
            }
          point_2++;
        }
      point_1++;
    }
  g_strfreev (split_1);
  g_strfreev (split_2);

  sqlite3_result_int (context, 0);
}

/**
 * @brief Check if two CVE lists contain a common CVE.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_cpe_title (sqlite3_context *context, int argc, sqlite3_value** argv)
{
  const unsigned char *cpe_id;
  gchar *quoted_cpe_id;
  char *cpe_title;

  assert (argc == 1);

  cpe_id = sqlite3_value_text (argv[0]);

  if (manage_scap_loaded ()
      && sqlite3_value_type(argv[0]) != SQLITE_NULL)
    {
      quoted_cpe_id = sql_quote ((gchar*) cpe_id);
      cpe_title = sql_string ("SELECT title FROM scap.cpes"
                              " WHERE uuid = '%s';",
                              quoted_cpe_id);
      g_free (quoted_cpe_id);

      if (cpe_title)
        {
          sqlite3_result_text (context, cpe_title, -1, SQLITE_TRANSIENT);
          g_free (cpe_title);
        }
      else
        {
          sqlite3_result_null (context);
        }
    }
  else
    {
      sqlite3_result_null (context);
    }
}

/**
 * @brief Get a value from the data of a credential.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_credential_value (sqlite3_context *context, int argc, sqlite3_value** argv)
{
  credential_t credential;
  int trash;
  const unsigned char* type;
  gchar *quoted_type, *result;

  assert (argc == 3);

  credential = sqlite3_value_int64 (argv[0]);
  trash = sqlite3_value_int (argv[1]);
  type = sqlite3_value_text (argv[2]);

  quoted_type = sql_quote ((const char*) type);
  if (trash)
    {
      result = sql_string ("SELECT value FROM credentials_trash_data"
                           " WHERE credential = %llu AND type = '%s';",
                           credential, quoted_type);
    }
  else
    {
      result = sql_string ("SELECT value FROM credentials_data"
                           " WHERE credential = %llu AND type = '%s';",
                           credential, quoted_type);
    }

  if (result)
    sqlite3_result_text (context, result, -1, SQLITE_TRANSIENT);
  else
    sqlite3_result_null (context);

  g_free (result);
}

/**
 * @brief Get the offset from UTC of the current time for a timezone.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_current_offset (sqlite3_context *context, int argc, sqlite3_value** argv)
{
  assert (argc == 1);
  sqlite3_result_int
   (context,
    (int) current_offset ((const char *) sqlite3_value_text (argv[0])));
}

/**
 * @brief Calculate the trend of a task.
 *
 * This is a callback for a scalar SQL function of two argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_task_trend (sqlite3_context *context, int argc, sqlite3_value** argv)
{
  unsigned int overrides;
  int min_qod;
  task_t task;

  assert (argc == 3);

  task = sqlite3_value_int64 (argv[0]);
  if (task == 0)
    {
      sqlite3_result_text (context, "", -1, SQLITE_TRANSIENT);
      return;
    }

  overrides = sqlite3_value_int (argv[1]);

  if (sqlite3_value_type (argv[2]) == SQLITE_NULL)
    min_qod = MIN_QOD_DEFAULT;
  else
    min_qod = sqlite3_value_int (argv[2]);

  sqlite3_result_text (context, task_trend (task, overrides, min_qod), -1,
                       SQLITE_TRANSIENT);
}

/**
 * @brief Severity.
 */
typedef struct
{
  task_t task;                ///< Task.
  gchar *severity;            ///< Severity.
  task_t overrides_task;      ///< Task.
  gchar *overrides_severity;  ///< Severity.
  int min_qod;                ///< Minimum QoD.
} sql_severity_t;

/**
 * @brief Get task severity, looking in cache.
 *
 * @param[in]  cache_arg  Cache.
 */
static void
clear_cache (void *cache_arg)
{
  sql_severity_t *cache;

  cache = (sql_severity_t*) cache_arg;
  g_debug ("   %s: %llu, %llu\n", __FUNCTION__, cache->task, cache->overrides_task);
  cache->task = 0;
  cache->overrides_task = 0;
  free (cache->severity);
  cache->severity = NULL;
  free (cache->overrides_severity);
  cache->overrides_severity = NULL;
  cache->min_qod = -1;
}

/**
 * @brief Get task severity, looking in cache.
 *
 * Cache a single severity value because task_threat and task_severity both
 * do the same expensive severity calculation for each row in the task
 * iterator.  Use auxdata on the overrides arg to pass the cache between
 * calls with a single statement.
 *
 * @param[in]  context    SQL context.
 * @param[in]  task       Task.
 * @param[in]  overrides  Overrides flag.
 * @param[in]  min_qod    Minimum QoD of report results to count.
 *
 * @return Severity.
 */
static char *
cached_task_severity (sqlite3_context *context, task_t task, int overrides,
                      int min_qod)
{
  static sql_severity_t static_cache = { .task = 0, .severity = NULL,
                                         .min_qod = MIN_QOD_DEFAULT,
                                         .overrides_task = 0,
                                         .overrides_severity = NULL };
  sql_severity_t *cache;
  char *severity;

  cache = sqlite3_get_auxdata (context, 1);
  if (cache)
    {
      if (overrides)
        {
          if (cache->overrides_task == task && cache->min_qod == min_qod)
            return cache->overrides_severity;
          /* Replace the cached severity. */
          cache->overrides_task = task;
          free (cache->overrides_severity);
          cache->overrides_severity = task_severity (task, 1, min_qod, 0);
          return cache->overrides_severity;
        }
      else
        {
          if (cache->task == task && cache->min_qod == min_qod)
            return cache->severity;
          /* Replace the cached severity. */
          cache->task = task;
          free (cache->severity);
          cache->severity = task_severity (task, 0, min_qod, 0);
          return cache->severity;
        }
    }
  severity = task_severity (task, overrides, min_qod, 0);
  /* Setup the cached severity. */
  cache = &static_cache;
  if (overrides)
    {
      cache->overrides_task = task;
      cache->overrides_severity = severity;
    }
  else
    {
      cache->task = task;
      cache->severity = severity;
    }
  sqlite3_set_auxdata (context, 1, cache, clear_cache);
  return severity;
}

/**
 * @brief Calculate the threat level of a task.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_task_threat_level (sqlite3_context *context, int argc, sqlite3_value** argv)
{
  task_t task;
  report_t last_report;
  const char *threat;
  unsigned int overrides;
  int min_qod;
  char* severity;
  double severity_dbl;

  assert (argc == 3);

  task = sqlite3_value_int64 (argv[0]);
  if (task == 0)
    {
      sqlite3_result_text (context, "", -1, SQLITE_TRANSIENT);
      return;
    }

  overrides = sqlite3_value_int (argv[1]);

  if (sqlite3_value_type (argv[2]) == SQLITE_NULL)
    min_qod = MIN_QOD_DEFAULT;
  else
    min_qod = sqlite3_value_int (argv[2]);

  severity = cached_task_severity (context, task, overrides, min_qod);

  if (severity == NULL
      || sscanf (severity, "%lf", &severity_dbl) != 1)
    threat = NULL;
  else
    threat = severity_to_level (severity_dbl, 0);

  g_debug ("   %s: %llu: %s\n", __FUNCTION__, task, threat);
  if (threat)
    {
      sqlite3_result_text (context, threat, -1, SQLITE_TRANSIENT);
      return;
    }

  task_last_report (task, &last_report);
  if (last_report == 0)
    {
      sqlite3_result_text (context, "", -1, SQLITE_TRANSIENT);
      return;
    }

  sqlite3_result_text (context, "None", -1, SQLITE_TRANSIENT);
  return;
}

/**
 * @brief Calculate the progress of a report.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_report_progress (sqlite3_context *context, int argc, sqlite3_value** argv)
{
  report_t report;
  task_t task;

  assert (argc == 1);

  report = sqlite3_value_int64 (argv[0]);
  if (report == 0)
    {
      sqlite3_result_int (context, -1);
      return;
    }

  if (report_task (report, &task))
    {
      sqlite3_result_int (context, -1);
      return;
    }

  sqlite3_result_int (context, report_progress (report, task, NULL));
  return;
}

/**
 * @brief Calculate the severity of a report.
 *
 * This is a callback for a scalar SQL function of three arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_report_severity (sqlite3_context *context, int argc, sqlite3_value** argv)
{
  report_t report;
  double severity;
  unsigned int overrides;
  int min_qod;

  assert (argc == 3);

  report = sqlite3_value_int64 (argv[0]);
  if (report == 0)
    {
      sqlite3_result_text (context, "", -1, SQLITE_TRANSIENT);
      return;
    }

  overrides = sqlite3_value_int (argv[1]);

  if (sqlite3_value_type (argv[2]) == SQLITE_NULL)
    min_qod = MIN_QOD_DEFAULT;
  else
    min_qod = sqlite3_value_int (argv[2]);

  severity = report_severity (report, overrides, min_qod);

  sqlite3_result_double (context, severity);
  return;
}

/**
 * @brief Get the number of results of a given severity level in a report.
 *
 * @param[in] report     The report to count the results of.
 * @param[in] overrides  Whether to apply overrides.
 * @param[in] min_qod    Minimum QoD of results to count.
 * @param[in] level      Severity level of which to count results.
 *
 * @return    The number of results.
 */
static int
report_severity_count (report_t report, int overrides, int min_qod,
                       char *level)
{
  int debugs, false_positives, logs, lows, mediums, highs;
  get_data_t *get;

  if (current_credentials.uuid == NULL
      || strcmp (current_credentials.uuid, "") == 0)
    return 0;
  get = report_results_get_data (1   /* first */,
                                 -1, /* rows */
                                 overrides,
                                 0,  /* autofp */
                                 min_qod);
  report_counts_id (report, &debugs, &highs, &lows, &logs, &mediums,
                    &false_positives, NULL, get, NULL);
  get_data_reset (get);
  g_free (get);

  if (strcasecmp (level, "Debug") == 0)
    return debugs;
  if (strcasecmp (level, "False Positive") == 0)
    return false_positives;
  else if (strcasecmp (level, "Log") == 0)
    return logs;
  else if (strcasecmp (level, "Low") == 0)
    return lows;
  else if (strcasecmp (level, "Medium") == 0)
    return mediums;
  else if (strcasecmp (level, "High") == 0)
    return highs;
  else
    return 0;
}

/**
 * @brief Get the number of results of a given severity level in a report.
 *
 * This is a callback for a scalar SQL function of four arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_report_severity_count (sqlite3_context *context, int argc,
                           sqlite3_value** argv)
{
  report_t report;
  unsigned int overrides;
  int min_qod;
  char* level;
  int count;

  assert (argc == 4);

  report = sqlite3_value_int64 (argv[0]);
  if (report == 0)
    {
      sqlite3_result_text (context, "", -1, SQLITE_TRANSIENT);
      return;
    }

  overrides = sqlite3_value_int (argv[1]);

  if (sqlite3_value_type (argv[2]) == SQLITE_NULL)
    min_qod = MIN_QOD_DEFAULT;
  else
    min_qod = sqlite3_value_int (argv[2]);

  level = (char*) sqlite3_value_text (argv[3]);
  if (level == 0)
    {
      sqlite3_result_text (context, "", -1, SQLITE_TRANSIENT);
      return;
    }

  count = report_severity_count (report, overrides, min_qod, level);

  sqlite3_result_int (context, count);
  return;
}

/**
 * @brief Count the number of hosts of a report.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_report_host_count (sqlite3_context *context,
                       int argc, sqlite3_value** argv)
{
  report_t report;
  int host_count;

  assert (argc == 1);

  report = sqlite3_value_int64 (argv[0]);
  if (report == 0)
    {
      sqlite3_result_text (context, "", -1, SQLITE_TRANSIENT);
      return;
    }

  host_count = report_host_count (report);

  sqlite3_result_int (context, host_count);
  return;
}

/**
 * @brief Count the number of hosts of a report with results.
 *
 * This is a callback for a scalar SQL function of two arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_report_result_host_count (sqlite3_context *context,
                              int argc, sqlite3_value** argv)
{
  report_t report;
  int min_qod;
  int host_count;

  assert (argc == 2);

  report = sqlite3_value_int64 (argv[0]);
  if (report == 0)
    {
      sqlite3_result_text (context, "", -1, SQLITE_TRANSIENT);
      return;
    }

  if (sqlite3_value_type (argv[1]) == SQLITE_NULL)
    min_qod = MIN_QOD_DEFAULT;
  else
    min_qod = sqlite3_value_int (argv[1]);

  host_count = report_result_host_count (report, min_qod);

  sqlite3_result_int (context, host_count);
  return;
}

/**
 * @brief Calculate the severity of a task.
 *
 * This is a callback for a scalar SQL function of two arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_task_severity (sqlite3_context *context, int argc, sqlite3_value** argv)
{
  task_t task;
  report_t last_report;
  char *severity;
  double severity_double;
  unsigned int overrides;
  int min_qod;

  assert (argc == 3);

  task = sqlite3_value_int64 (argv[0]);
  if (task == 0)
    {
      sqlite3_result_text (context, "", -1, SQLITE_TRANSIENT);
      return;
    }

  overrides = sqlite3_value_int (argv[1]);

  if (sqlite3_value_type (argv[2]) == SQLITE_NULL)
    min_qod = MIN_QOD_DEFAULT;
  else
    min_qod = sqlite3_value_int (argv[2]);

  severity = cached_task_severity (context, task, overrides, min_qod);
  severity_double = severity ? g_strtod (severity, 0) : 0.0;
  g_debug ("   %s: %llu: %s\n", __FUNCTION__, task, severity);
  if (severity)
    {
      sqlite3_result_double (context, severity_double);
      return;
    }

  task_last_report (task, &last_report);
  if (last_report == 0)
    {
      sqlite3_result_null (context);
      return;
    }

  sqlite3_result_null (context);
  return;
}

/**
 * @brief Get the last report of a task.
 *
 * This is a callback for a scalar SQL function of two arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_task_last_report (sqlite3_context *context, int argc, sqlite3_value** argv)
{
  task_t task;
  report_t report;

  task = sqlite3_value_int64 (argv[0]);
  if (task == 0)
    sqlite3_result_int64 (context, 0);
  else if (task_last_report (task, &report))
    sqlite3_result_int64 (context, 0);
  else
    sqlite3_result_int64 (context, report);
}

/**
 * @brief Test if a severity score matches an override's severity.
 *
 * This is a callback for a scalar SQL function of two arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_severity_matches_ov (sqlite3_context *context, int argc,
                         sqlite3_value** argv)
{
  double severity, ov_severity;

  assert (argc == 2);

  if (sqlite3_value_type (argv[0]) == SQLITE_NULL)
    {
      sqlite3_result_int (context, 0);
      return;
    }

  if (sqlite3_value_type (argv[1]) == SQLITE_NULL
      || strcmp ((const char*) (sqlite3_value_text (argv[1])), "") == 0)
    {
      sqlite3_result_int (context, 1);
      return;
    }
  else
    {
      severity = sqlite3_value_double (argv[0]);
      ov_severity = sqlite3_value_double (argv[1]);

      sqlite3_result_int (context,
                          severity_matches_ov (severity, ov_severity));
      return;
    }
}

/**
 * @brief Get the threat level matching a severity score.
 *
 * This is a callback for a scalar SQL function of two arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_severity_to_level (sqlite3_context *context, int argc,
                       sqlite3_value** argv)
{
  double severity;
  int mode;

  assert (argc == 2);

  if (sqlite3_value_type (argv[0]) == SQLITE_NULL
      || strcmp ((const char*)(sqlite3_value_text (argv[0])), "") == 0)
    {
      sqlite3_result_null (context);
      return;
    }

  mode = sqlite3_value_int (argv[1]);

  severity = sqlite3_value_double (argv[0]);

  sqlite3_result_text (context, severity_to_level (severity, mode),
                       -1, SQLITE_TRANSIENT);
  return;
}

/**
 * @brief Get the message type matching a severity score.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_severity_to_type (sqlite3_context *context, int argc,
                      sqlite3_value** argv)
{
  double severity;

  assert (argc == 1);

  if (sqlite3_value_type (argv[0]) == SQLITE_NULL
      || strcmp ((const char*)(sqlite3_value_text (argv[0])), "") == 0)
    {
      sqlite3_result_null (context);
      return;
    }

  severity = sqlite3_value_double (argv[0]);

  sqlite3_result_text (context, severity_to_type (severity),
                       -1, SQLITE_TRANSIENT);
  return;
}

/**
 * @brief Do a regexp match.  Implements SQL REGEXP.
 *
 * This is a callback for a scalar SQL function of two arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_regexp (sqlite3_context *context, int argc, sqlite3_value** argv)
{
  const unsigned char *string, *regexp;

  assert (argc == 2);

  regexp = sqlite3_value_text (argv[0]);
  if (regexp == NULL)
    {
      /* Seems this happens when the query result is empty. */
      sqlite3_result_int (context, 0);
      return;
    }

  string = sqlite3_value_text (argv[1]);
  if (string == NULL)
    {
      /* Seems this happens when the query result is empty. */
      sqlite3_result_int (context, 0);
      return;
    }

  if (g_regex_match_simple ((gchar *) regexp, (gchar *) string, 0, 0))
    {
      sqlite3_result_int (context, 1);
      return;
    }
  sqlite3_result_int (context, 0);
}

/**
 * @brief Get the name of a task run status.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_run_status_name (sqlite3_context *context, int argc, sqlite3_value** argv)
{
  const char *name;
  int status;

  assert (argc == 1);

  status = sqlite3_value_int (argv[0]);

  name = run_status_name (status);
  sqlite3_result_text (context, name ? name : "", -1, SQLITE_TRANSIENT);
  return;
}

/**
 * @brief Get if a resource exists by its type and ID.
 *
 * This is a callback for a scalar SQL function of three arguments.
 *
 * Used by migrate_119_to_120 to check if a permission refers to a resource
 * that has been removed.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_resource_exists (sqlite3_context *context, int argc, sqlite3_value** argv)
{
  const char *type;
  resource_t resource;
  int location, exists;

  assert (argc == 3);

  type = (char*) sqlite3_value_text (argv[0]);
  if (type == NULL)
    {
      sqlite3_result_int (context, 0);
      return;
    }
  if (valid_db_resource_type ((char*) type) == 0)
    {
      sqlite3_result_error (context, "Invalid resource type argument", -1);
      return;
    }

  resource = sqlite3_value_int64 (argv[1]);
  if (resource == 0)
    {
      sqlite3_result_int (context, 0);
      return;
    }

  location = sqlite3_value_int (argv[2]);

  exists = resource_exists (type, resource, location);
  if (exists == -1)
    {
      gchar *msg;
      msg = g_strdup_printf ("Invalid resource type argument: %s", type);
      sqlite3_result_error (context, msg, -1);
      g_free (msg);
      return;
    }
  sqlite3_result_int (context, exists);
  return;
}

/**
 * @brief Get the name of a resource by its type and ID.
 *
 * This is a callback for a scalar SQL function of three arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_resource_name (sqlite3_context *context, int argc, sqlite3_value** argv)
{
  const char *type, *id;
  int location;
  char *name;

  assert (argc == 3);

  type = (char*) sqlite3_value_text (argv[0]);
  if (type == NULL)
    {
      sqlite3_result_null (context);
      return;
    }

  id = (char*) sqlite3_value_text (argv[1]);
  if (id == NULL)
    {
      sqlite3_result_null (context);
      return;
    }

  location = sqlite3_value_int (argv[2]);

  if (resource_name (type, id, location, &name))
    {
      gchar *msg;
      msg = g_strdup_printf ("Invalid resource type argument: %s", type);
      sqlite3_result_error (context, msg, -1);
      g_free (msg);
      return;
    }

  if (name)
    sqlite3_result_text (context, name, -1, SQLITE_TRANSIENT);
  else
    sqlite3_result_text (context, "", -1, SQLITE_TRANSIENT);

  free (name);

  return;
}

/**
 * @brief Check whether a severity falls within a threat level.
 *
 * This is a callback for a scalar SQL function of two arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_severity_in_level (sqlite3_context *context, int argc, sqlite3_value** argv)
{
  double severity;
  const char *threat;

  assert (argc == 2);

  severity = sqlite3_value_double (argv[0]);

  threat = (char*) sqlite3_value_text (argv[1]);
  if (threat == NULL)
    {
      sqlite3_result_null (context);
      return;
    }

  sqlite3_result_int (context, severity_in_level (severity, threat));

  return;
}

/**
 * @brief Get a target credential.
 *
 * This is a callback for a scalar SQL function of two arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_target_credential (sqlite3_context *context, int argc, sqlite3_value** argv)
{
  target_t target;
  int trash;
  const char *type;

  assert (argc == 3);

  target = sqlite3_value_int64 (argv[0]);
  trash = sqlite3_value_int (argv[1]);
  type = (char*) sqlite3_value_text (argv[2]);

  if (type == NULL)
    {
      sqlite3_result_null (context);
      return;
    }

  if (trash)
    sqlite3_result_int64 (context, trash_target_credential (target, type));
  else
    sqlite3_result_int64 (context, target_credential (target, type));

  return;
}

/**
 * @brief Get the location of a trash target credential.
 *
 * This is a callback for a scalar SQL function of two arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_trash_target_credential_location (sqlite3_context *context,
                                      int argc, sqlite3_value** argv)
{
  target_t target;
  const char *type;

  assert (argc == 2);

  target = sqlite3_value_int64 (argv[0]);
  type = (char*) sqlite3_value_text (argv[1]);

  if (type == NULL)
    {
      sqlite3_result_null (context);
      return;
    }

  sqlite3_result_int (context, trash_target_credential_location (target, type));

  return;
}

/**
 * @brief Get a target port.
 *
 * This is a callback for a scalar SQL function of two arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_target_login_port (sqlite3_context *context, int argc, sqlite3_value** argv)
{
  target_t target;
  int trash;
  const char *type;

  assert (argc == 3);

  target = sqlite3_value_int64 (argv[0]);
  trash = sqlite3_value_int (argv[1]);
  type = (char*) sqlite3_value_text (argv[2]);

  if (type == NULL)
    {
      sqlite3_result_null (context);
      return;
    }

  if (trash)
    sqlite3_result_int64 (context,
                          trash_target_login_port (target, type));
  else
    sqlite3_result_int64 (context, target_login_port (target, type));

  return;
}

/**
 * @brief Check if a user can do anything.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_user_can_everything (sqlite3_context *context, int argc,
                         sqlite3_value** argv)
{
  const unsigned char *uuid;

  assert (argc == 1);

  uuid = sqlite3_value_text (argv[0]);
  if (uuid == NULL)
    {
      sqlite3_result_error (context, "Failed to get uuid argument", -1);
      return;
    }

  sqlite3_result_int (context, acl_user_can_everything ((char *) uuid));
}

/**
 * @brief Check if a user owns or effectively owns a resource.
 *
 * This is a callback for a scalar SQL function of two arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_user_owns (sqlite3_context *context, int argc,
               sqlite3_value** argv)
{
  const unsigned char *type;
  resource_t resource;

  assert (argc == 2);

  type = sqlite3_value_text (argv[0]);
  if (type == NULL)
    {
      sqlite3_result_error (context, "Failed to get type argument", -1);
      return;
    }

  resource = sqlite3_value_int64 (argv[1]);
  if (resource == 0)
    {
      sqlite3_result_int (context, 0);
      return;
    }

  sqlite3_result_int (context, acl_user_owns ((char *) type, resource, 0));
}

/**
 * @brief Create functions.
 *
 * @return 0 success, -1 error.
 */
int
manage_create_sql_functions ()
{
  if (sqlite3_create_function (task_db,
                               "t",
                               0,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_t,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to t", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "strpos",
                               2,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_strpos,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create strpos", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "order_inet",
                               1,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_order_inet,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create order_inet", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "order_message_type",
                               1,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_order_message_type,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create order_message_type", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "order_port",
                               1,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_order_port,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create order_port", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "order_role",
                               1,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_order_role,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create order_role", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "order_threat",
                               1,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_order_threat,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create order_threat", __FUNCTION__);
      return -1;
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
      return -1;
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
      g_warning ("%s: failed to create hosts_contains", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "clean_hosts",
                               1,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_clean_hosts,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create clean_hosts", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "iso_time",
                               1,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_iso_time,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create iso_time", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "days_from_now",
                               1,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_days_from_now,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create days_from_now", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "parse_time",
                               1,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_parse_time,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create parse_time", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "tag",
                               2,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_tag,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create tag", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "uniquify",
                               4,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_uniquify,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create uniquify", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "next_time",
                               3,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_next_time,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create next_time", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "next_time",
                               4,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_next_time,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create next_time", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "next_time",
                               5,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_next_time,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create next_time", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "m_now",
                               0,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_now,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create m_now", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "max_hosts",
                               2,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_max_hosts,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create max_hosts", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "common_cve",
                               2,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_common_cve,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create common_cve", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "cpe_title",
                               1,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_cpe_title,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create cpe_title", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "credential_value",
                               3,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_credential_value,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create credential_value", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "current_offset",
                               1,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_current_offset,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create current_offset", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "task_trend",
                               3,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_task_trend,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create task_trend", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "task_threat_level",
                               3,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_task_threat_level,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create task_threat_level", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "report_progress",
                               1,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_report_progress,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create report_progress", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "report_severity",
                               3,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_report_severity,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create report_severity", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "report_severity_count",
                               4,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_report_severity_count,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create report_severity_count", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "report_host_count",
                               1,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_report_host_count,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create report_result_host_count", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "report_result_host_count",
                               2,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_report_result_host_count,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create report_result_host_count", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "task_severity",
                               3,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_task_severity,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create task_severity", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "task_last_report",
                               1,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_task_last_report,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create task_last_report", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "severity_matches_ov",
                               2,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_severity_matches_ov,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create severity_matches_ov", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "severity_to_level",
                               1,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_severity_to_level,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create severity_to_level", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "severity_to_level",
                               2,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_severity_to_level,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create severity_to_level", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "severity_to_type",
                               1,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_severity_to_type,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create severity_to_type", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "run_status_name",
                               1,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_run_status_name,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create run_status_name", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "resource_exists",
                               3,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_resource_exists,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create resource_exists", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "regexp",
                               2,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_regexp,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create regexp", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "resource_name",
                               3,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_resource_name,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create resource_name", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "severity_in_level",
                               2,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_severity_in_level,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create severity_in_level", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "target_credential",
                               3,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_target_credential,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create target_login_data", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "trash_target_credential_location",
                               2,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_trash_target_credential_location,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create target_login_data", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "target_login_port",
                               3,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_target_login_port,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create target_login_data", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "user_can_everything",
                               1,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_user_can_everything,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create user_can_everything", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (task_db,
                               "user_owns",
                               2,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               sql_user_owns,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create user_owns", __FUNCTION__);
      return -1;
    }

  return 0;
}


/* Creation. */

/**
 * @brief Create all tables.
 */
void
create_tables ()
{
  gchar *owned_clause;

  sql ("CREATE TABLE IF NOT EXISTS agents"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  installer TEXT, installer_64 TEXT, installer_filename,"
       "  installer_signature_64 TEXT, installer_trust INTEGER,"
       "  installer_trust_time, howto_install TEXT, howto_use TEXT,"
       "  creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS agents_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  installer TEXT, installer_64 TEXT, installer_filename,"
       "  installer_signature_64 TEXT, installer_trust INTEGER,"
       "  installer_trust_time, howto_install TEXT, howto_use TEXT,"
       "  creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS config_preferences"
       " (id INTEGER PRIMARY KEY, config INTEGER, type, name, value,"
       "  default_value, hr_name TEXT);");
  sql ("CREATE TABLE IF NOT EXISTS config_preferences_trash"
       " (id INTEGER PRIMARY KEY, config INTEGER, type, name, value,"
       "  default_value, hr_name TEXT);");
  sql ("CREATE TABLE IF NOT EXISTS configs"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name,"
       "  nvt_selector, comment, family_count INTEGER, nvt_count INTEGER,"
       "  families_growing INTEGER, nvts_growing INTEGER, type, scanner,"
       "  creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS configs_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name,"
       "  nvt_selector, comment, family_count INTEGER, nvt_count INTEGER,"
       "  families_growing INTEGER, nvts_growing INTEGER, type, scanner,"
       "  creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS alert_condition_data"
       " (id INTEGER PRIMARY KEY, alert INTEGER, name, data);");
  sql ("CREATE TABLE IF NOT EXISTS alert_condition_data_trash"
       " (id INTEGER PRIMARY KEY, alert INTEGER, name, data);");
  sql ("CREATE TABLE IF NOT EXISTS alert_event_data"
       " (id INTEGER PRIMARY KEY, alert INTEGER, name, data);");
  sql ("CREATE TABLE IF NOT EXISTS alert_event_data_trash"
       " (id INTEGER PRIMARY KEY, alert INTEGER, name, data);");
  sql ("CREATE TABLE IF NOT EXISTS alert_method_data"
       " (id INTEGER PRIMARY KEY, alert INTEGER, name, data);");
  sql ("CREATE TABLE IF NOT EXISTS alert_method_data_trash"
       " (id INTEGER PRIMARY KEY, alert INTEGER, name, data);");
  sql ("CREATE TABLE IF NOT EXISTS alerts"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  event INTEGER, condition INTEGER, method INTEGER, filter INTEGER,"
       "  creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS alerts_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  event INTEGER, condition INTEGER, method INTEGER, filter INTEGER,"
       "  filter_location INTEGER, creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS credentials"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  creation_time, modification_time, type TEXT,"
       "  allow_insecure integer);");
  sql ("CREATE TABLE IF NOT EXISTS credentials_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  creation_time, modification_time, type TEXT,"
       "  allow_insecure integer);");
  sql ("CREATE TABLE IF NOT EXISTS credentials_data"
       " (id INTEGER PRIMARY KEY, credential INTEGER, type TEXT, value TEXT);");
  sql ("CREATE TABLE IF NOT EXISTS credentials_trash_data"
       " (id INTEGER PRIMARY KEY, credential INTEGER, type TEXT, value TEXT);");
  sql ("CREATE TABLE IF NOT EXISTS filters"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  type, term, creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS filters_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  type, term, creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS groups"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS groups_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  type, term, creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS group_users"
       " (id INTEGER PRIMARY KEY, `group` INTEGER, user INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS group_users_trash"
       " (id INTEGER PRIMARY KEY, `group` INTEGER, user INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS hosts"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS host_identifiers"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, host INTEGER, owner INTEGER, name,"
       "  comment, value, source_type, source_id, source_data, creation_time,"
       "  modification_time);");
  sql ("CREATE INDEX IF NOT EXISTS host_identifiers_by_host"
       " ON host_identifiers (host);");
  sql ("CREATE INDEX IF NOT EXISTS host_identifiers_by_value"
       " ON host_identifiers (value);");
  sql ("CREATE TABLE IF NOT EXISTS oss"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS host_oss"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, host INTEGER, owner INTEGER,"
       "  name, comment, os INTEGER, source_type, source_id, source_data,"
       "  creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS host_max_severities"
       " (id INTEGER PRIMARY KEY, host INTEGER, severity REAL, source_type,"
       "  source_id, creation_time);");
  sql ("CREATE TABLE IF NOT EXISTS host_details"
       " (id INTEGER PRIMARY KEY, host INTEGER,"
       /* The report that the host detail came from. */
       "  source_type,"
       "  source_id,"
       /* The original source of the host detail, from the scanner. */
       "  detail_source_type,"
       "  detail_source_name,"
       "  detail_source_description,"
       "  name,"
       "  value);");
  sql ("CREATE INDEX IF NOT EXISTS host_details_by_host"
       " ON host_details (host);");
  sql ("CREATE TABLE IF NOT EXISTS auth_cache"
       " (id INTEGER PRIMARY KEY, username, hash, method, creation_time);");
  sql ("CREATE TABLE IF NOT EXISTS meta"
       " (id INTEGER PRIMARY KEY, name UNIQUE, value);");
  sql ("CREATE TABLE IF NOT EXISTS notes"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, nvt,"
       "  creation_time, modification_time, text, hosts, port, severity,"
       "  task INTEGER, result INTEGER, end_time);");
  sql ("CREATE TABLE IF NOT EXISTS notes_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, nvt,"
       "  creation_time, modification_time, text, hosts, port, severity,"
       "  task INTEGER, result INTEGER, end_time);");
  sql ("CREATE TABLE IF NOT EXISTS nvt_preferences"
       " (id INTEGER PRIMARY KEY, name, value);");
  /* nvt_selectors types: 0 all, 1 family, 2 NVT
   * (NVT_SELECTOR_TYPE_* in manage.h). */
  sql ("CREATE TABLE IF NOT EXISTS nvt_selectors"
       " (id INTEGER PRIMARY KEY, name, exclude INTEGER, type INTEGER,"
       "  family_or_nvt, family);");
  sql ("CREATE INDEX IF NOT EXISTS nvt_selectors_by_name"
       " ON nvt_selectors (name);");
  sql ("CREATE INDEX IF NOT EXISTS nvt_selectors_by_family_or_nvt"
       " ON nvt_selectors (type, family_or_nvt);");
  sql ("CREATE TABLE IF NOT EXISTS nvts"
       " (id INTEGER PRIMARY KEY, uuid, oid, version, name, comment,"
       "  copyright, cve, bid, xref, tag, category INTEGER, family, cvss_base,"
       "  creation_time, modification_time, solution_type TEXT, qod INTEGER,"
       "  qod_type TEXT);");
  sql ("CREATE INDEX IF NOT EXISTS nvts_by_oid"
       " ON nvts (oid);");
  sql ("CREATE INDEX IF NOT EXISTS nvts_by_name"
       " ON nvts (name);");
  sql ("CREATE INDEX IF NOT EXISTS nvts_by_family"
       " ON nvts (family);");
  sql ("CREATE TABLE IF NOT EXISTS nvt_cves"
       " (nvt, oid, cve_name)");
  sql ("CREATE INDEX IF NOT EXISTS nvts_by_creation_time"
       " ON nvts (creation_time);");
  sql ("CREATE INDEX IF NOT EXISTS nvts_by_modification_time"
       " ON nvts (modification_time);");
  sql ("CREATE INDEX IF NOT EXISTS nvts_by_cvss_base"
       " ON nvts (cvss_base);");
  sql ("CREATE INDEX IF NOT EXISTS nvts_by_solution_type"
       " ON nvts (solution_type);");
  sql ("CREATE INDEX IF NOT EXISTS nvt_cves_by_oid"
       " ON nvt_cves (oid);");
  sql ("CREATE TABLE IF NOT EXISTS overrides"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, nvt,"
       "  creation_time, modification_time, text, hosts, port, severity,"
       "  new_severity, task INTEGER, result INTEGER, end_time);");
  sql ("CREATE TABLE IF NOT EXISTS overrides_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, nvt,"
       "  creation_time, modification_time, text, hosts, port, severity,"
       "  new_severity, task INTEGER, result INTEGER, end_time);");
  sql ("CREATE TABLE IF NOT EXISTS permissions"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner, name, comment,"
       "  resource_type, resource, resource_uuid, resource_location,"
       "  subject_type, subject, subject_location,"
       "  creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS permissions_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner, name, comment,"
       "  resource_type, resource, resource_uuid, resource_location,"
       "  subject_type, subject, subject_location,"
       "  creation_time, modification_time);");
  /* Overlapping port ranges will cause problems, at least for the port
   * counting.  OMP CREATE_PORT_LIST and CREATE_PORT_RANGE check for this,
   * but whoever creates a predefined port list must check this manually. */
  sql ("CREATE TABLE IF NOT EXISTS port_lists"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS port_lists_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS port_names"
       " (id INTEGER PRIMARY KEY, number INTEGER, protocol, name,"
       "  UNIQUE (number, protocol) ON CONFLICT REPLACE);");
  sql ("CREATE TABLE IF NOT EXISTS port_ranges"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, port_list INTEGER, type, start,"
       "  end, comment, exclude);");
  sql ("CREATE TABLE IF NOT EXISTS port_ranges_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, port_list INTEGER, type, start,"
       "  end, comment, exclude);");
  sql ("CREATE TABLE IF NOT EXISTS report_host_details"
       " (id INTEGER PRIMARY KEY, report_host INTEGER, source_type, source_name,"
       "  source_description, name, value);");
  sql ("CREATE INDEX IF NOT EXISTS"
       " report_host_details_by_report_host_and_name_and_value"
       " ON report_host_details (report_host, name, value);");
  sql ("CREATE TABLE IF NOT EXISTS report_hosts"
       " (id INTEGER PRIMARY KEY, report INTEGER, host, start_time, end_time,"
       "  current_port, max_port);");
  sql ("CREATE INDEX IF NOT EXISTS report_hosts_by_host"
       " ON report_hosts (host);");
  sql ("CREATE INDEX IF NOT EXISTS report_hosts_by_report"
       " ON report_hosts (report);");
  sql ("CREATE TABLE IF NOT EXISTS report_format_param_options"
       " (id INTEGER PRIMARY KEY, report_format_param, value);");
  sql ("CREATE TABLE IF NOT EXISTS report_format_param_options_trash"
       " (id INTEGER PRIMARY KEY, report_format_param, value);");
  sql ("CREATE TABLE IF NOT EXISTS report_format_params"
       " (id INTEGER PRIMARY KEY, report_format, name, type INTEGER, value,"
       "  type_min, type_max, type_regex, fallback);");
  sql ("CREATE TABLE IF NOT EXISTS report_format_params_trash"
       " (id INTEGER PRIMARY KEY, report_format, name, type INTEGER, value,"
       "  type_min, type_max, type_regex, fallback);");
  sql ("CREATE TABLE IF NOT EXISTS report_formats"
       " (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, extension,"
       "  content_type, summary, description, signature, trust INTEGER,"
       "  trust_time, flags INTEGER, creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS report_formats_trash"
       " (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, extension,"
       "  content_type, summary, description, signature, trust INTEGER,"
       "  trust_time, flags INTEGER, original_uuid, creation_time,"
       "  modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS reports"
       " (id INTEGER PRIMARY KEY, uuid, owner INTEGER, hidden INTEGER,"
       "  task INTEGER, date INTEGER, start_time, end_time, nbefile, comment,"
       "  scan_run_status INTEGER, slave_progress, slave_task_uuid,"
       "  slave_uuid, slave_name, slave_host, slave_port, source_iface,"
       "  flags INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS report_counts"
       " (id INTEGER PRIMARY KEY, report INTEGER, user INTEGER,"
       "  severity, count, override, end_time INTEGER, min_qod INTEGER);");
  sql ("CREATE INDEX IF NOT EXISTS report_counts_by_report_and_override"
       " ON report_counts (report, override);");
  sql ("CREATE TABLE IF NOT EXISTS resources_predefined"
       " (id INTEGER PRIMARY KEY, resource_type, resource INTEGER)");
  sql ("CREATE TABLE IF NOT EXISTS results"
       " (id INTEGER PRIMARY KEY, uuid, task INTEGER, host, port, nvt,"
       "  type, description, report, nvt_version, severity REAL,"
       "  qod INTEGER, qod_type TEXT, owner INTEGER, date INTEGER)");
  sql ("CREATE INDEX IF NOT EXISTS results_by_uuid"
       " ON results (uuid);");
  sql ("CREATE INDEX IF NOT EXISTS results_by_host"
       " ON results (host);");
  sql ("CREATE INDEX IF NOT EXISTS results_by_host_and_qod"
       " ON results(host, qod);");
  sql ("CREATE INDEX IF NOT EXISTS results_by_nvt"
       " ON results (nvt);");
  sql ("CREATE INDEX IF NOT EXISTS results_by_report"
       " ON results (report);");
  sql ("CREATE INDEX IF NOT EXISTS results_by_report_host"
       " ON results (report, host);");
  sql ("CREATE INDEX IF NOT EXISTS results_by_task"
       " ON results (task);");
  sql ("CREATE INDEX IF NOT EXISTS results_by_task_qod_severity"
       " ON results (task, qod, severity);");
  sql ("CREATE INDEX IF NOT EXISTS results_by_type"
       " ON results (type);");
  sql ("CREATE TABLE IF NOT EXISTS roles"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS roles_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS role_users"
       " (id INTEGER PRIMARY KEY, role INTEGER, user INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS role_users_trash"
       " (id INTEGER PRIMARY KEY, role INTEGER, user INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS scanners"
       " (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, comment,"
       "  host, port, type, ca_pub, credential INTEGER,"
       "  creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS scanners_trash"
       " (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, comment,"
       "  host, port, type, ca_pub, credential INTEGER,"
       "  credential_location INTEGER, creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS schedules"
       " (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, comment,"
       "  first_time, period, period_months, duration, timezone,"
       "  initial_offset, creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS schedules_trash"
       " (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, comment,"
       "  first_time, period, period_months, duration, timezone,"
       "  initial_offset, creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS settings"
       " (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, comment, value);");
  sql ("CREATE TABLE IF NOT EXISTS tags"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner, name, comment,"
       "  creation_time, modification_time, resource_type, resource,"
       "  resource_uuid, resource_location, active, value);");
  sql ("CREATE INDEX IF NOT EXISTS tags_by_resource"
       " ON tags (resource_type, resource);");
  sql ("CREATE INDEX IF NOT EXISTS tags_by_name"
       " ON tags (name);");
  sql ("CREATE UNIQUE INDEX IF NOT EXISTS tags_by_uuid"
       " ON tags (uuid);");
  sql ("CREATE TABLE IF NOT EXISTS tags_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner, name, comment,"
       "  creation_time, modification_time, resource_type, resource,"
       "  resource_uuid, resource_location, active, value);");
  sql ("CREATE TABLE IF NOT EXISTS targets"
       " (id INTEGER PRIMARY KEY, uuid text UNIQUE NOT NULL,"
       "  owner integer, name text NOT NULL,"
       "  hosts text, exclude_hosts text,"
       "  reverse_lookup_only integer, reverse_lookup_unify integer,"
       "  comment text, port_list integer, alive_test integer,"
       "  creation_time integer, modification_time integer);");
  sql ("CREATE TABLE IF NOT EXISTS targets_trash"
       " (id INTEGER PRIMARY KEY, uuid text UNIQUE NOT NULL,"
       "  owner integer, name text NOT NULL,"
       "  hosts text, exclude_hosts text,"
       "  reverse_lookup_only integer, reverse_lookup_unify integer,"
       "  comment text, port_list integer, port_list_location integer,"
       "  alive_test integer,"
       "  creation_time integer, modification_time integer);");
  sql ("CREATE TABLE IF NOT EXISTS targets_login_data"
       " (id INTEGER PRIMARY KEY, target INTEGER, type TEXT,"
       "  credential INTEGER, port INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS targets_trash_login_data"
       " (id INTEGER PRIMARY KEY, target INTEGER, type TEXT,"
       "  credential INTEGER, port INTEGER, credential_location INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS task_files"
       " (id INTEGER PRIMARY KEY, task INTEGER, name, content);");
  sql ("CREATE TABLE IF NOT EXISTS task_alerts"
       " (id INTEGER PRIMARY KEY, task INTEGER, alert INTEGER,"
       "  alert_location INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS task_preferences"
       " (id INTEGER PRIMARY KEY, task INTEGER, name, value);");
  sql ("CREATE TABLE IF NOT EXISTS tasks"
       " (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, hidden INTEGER,"
       "  comment, run_status INTEGER, start_time, end_time,"
       "  config INTEGER, target INTEGER, schedule INTEGER, schedule_next_time,"
       "  schedule_periods INTEGER, config_location INTEGER,"
       "  target_location INTEGER, schedule_location INTEGER,"
       "  scanner_location INTEGER, upload_result_count INTEGER,"
       "  hosts_ordering, scanner, alterable, creation_time,"
       "  modification_time);");
  /* Field password contains the hash. */
  /* Field hosts_allow: 0 deny, 1 allow. */
  /* Field ifaces_allow: 0 deny, 1 allow. */
  sql ("CREATE TABLE IF NOT EXISTS users"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  password, timezone, hosts, hosts_allow, ifaces, ifaces_allow,"
       "  method, creation_time, modification_time);");

  /* Result views */

  owned_clause = acl_where_owned_for_get ("override", "users.id");

  sql ("DROP VIEW IF EXISTS result_overrides;");
  sql ("CREATE VIEW result_overrides AS"
       " SELECT users.id AS user,"
       "        results.id as result,"
       "        overrides.id AS override,"
       "        overrides.severity AS ov_old_severity,"
       "        overrides.new_severity AS ov_new_severity"
       " FROM users, results, overrides"
       " WHERE overrides.nvt = results.nvt"
       "   AND (overrides.result = 0 OR overrides.result = results.id)"
       "   AND %s"
       " AND ((overrides.end_time = 0)"
       "      OR (overrides.end_time >= m_now ()))"
       " AND (overrides.task ="
       "      (SELECT reports.task FROM reports"
       "       WHERE results.report = reports.id)"
       "      OR overrides.task = 0)"
       " AND (overrides.result = results.id"
       "      OR overrides.result = 0)"
       " AND (overrides.hosts is NULL"
       "      OR overrides.hosts = ''"
       "      OR hosts_contains (overrides.hosts, results.host))"
       " AND (overrides.port is NULL"
       "      OR overrides.port = ''"
       "      OR overrides.port = results.port)"
       " ORDER BY overrides.result DESC, overrides.task DESC,"
       " overrides.port DESC, overrides.severity ASC,"
       " overrides.creation_time DESC",
       owned_clause);

  g_free (owned_clause);

  sql ("DROP VIEW IF EXISTS result_new_severities;");
  sql ("CREATE VIEW result_new_severities AS"
       "  SELECT results.id as result, users.id as user, dynamic, override,"
       "    CASE WHEN dynamic THEN"
       "      CASE WHEN override THEN"
       "        coalesce ((SELECT ov_new_severity FROM result_overrides"
       "                   WHERE result = results.id"
       "                     AND result_overrides.user = users.id"
       "                     AND severity_matches_ov"
       "                           (coalesce ((CASE WHEN results.severity"
       "                                                 > " G_STRINGIFY
                                                              (SEVERITY_LOG)
       "                                       THEN (SELECT cvss_base"
       "                                             FROM nvts"
       "                                             WHERE nvts.oid = results.nvt)"
       "                                       ELSE results.severity"
       "                                       END),"
       "                                      results.severity),"
       "                            ov_old_severity)),"
       "                  coalesce ((CASE WHEN results.severity"
       "                                       > " G_STRINGIFY (SEVERITY_LOG)
       "                             THEN (SELECT cvss_base"
       "                                   FROM nvts"
       "                                   WHERE nvts.oid = results.nvt)"
       "                             ELSE results.severity"
       "                             END),"
       "                            results.severity))"
       "      ELSE"
       "        coalesce ((CASE WHEN results.severity"
       "                             > " G_STRINGIFY (SEVERITY_LOG)
       "                   THEN (SELECT cvss_base"
       "                         FROM nvts"
       "                         WHERE nvts.oid = results.nvt)"
       "                   ELSE results.severity"
       "                   END),"
       "                  results.severity)"
       "      END"
       "    ELSE"
       "      CASE WHEN override THEN"
       "        coalesce ((SELECT ov_new_severity FROM result_overrides"
       "                   WHERE result = results.id"
       "                     AND result_overrides.user = users.id"
       "                     AND severity_matches_ov"
       "                           (results.severity,"
       "                            ov_old_severity)),"
       "                   results.severity)"
       "      ELSE"
       "        results.severity"
       "      END"
       "    END AS new_severity"
       "  FROM results, users"
       "  JOIN (SELECT 0 AS override UNION SELECT 1 AS override_opts)"
       "  JOIN (SELECT 0 AS dynamic UNION SELECT 1 AS dynamic_opts);");

  sql ("DROP VIEW IF EXISTS results_autofp;");
  sql ("CREATE VIEW results_autofp AS"
       " SELECT results.id as result, autofp_selection,"
       "        (CASE autofp_selection"
       "         WHEN 1 THEN"
       "          (CASE WHEN"
       "           (((SELECT family FROM nvts WHERE oid = results.nvt)"
       "              IN (" LSC_FAMILY_LIST "))"
       "            OR results.nvt = '0'" /* Open ports previously had 0 NVT. */
       "            OR EXISTS"
       "              (SELECT id FROM nvts"
       "               WHERE oid = results.nvt"
       "               AND"
       "               (cve = 'NOCVE'"
       "                 OR cve NOT IN (SELECT cve FROM nvts"
       "                                WHERE oid IN (SELECT source_name"
       "                                    FROM report_host_details"
       "                                    WHERE report_host"
       "                                    = (SELECT id"
       "                                       FROM report_hosts"
       "                                       WHERE report = %llu"
       "                                       AND host = results.host)"
       "                                    AND name = 'EXIT_CODE'"
       "                                    AND value = 'EXIT_NOTVULN')"
       "                                AND family IN (" LSC_FAMILY_LIST ")))))"
       "           THEN NULL"
       "           WHEN severity = " G_STRINGIFY (SEVERITY_ERROR) " THEN NULL"
       "           ELSE 1 END)"
       "         WHEN 2 THEN"
       "          (CASE WHEN"
       "            (((SELECT family FROM nvts WHERE oid = results.nvt)"
       "              IN (" LSC_FAMILY_LIST "))"
       "             OR results.nvt = '0'" /* Open ports previously had 0 NVT.*/
       "             OR EXISTS"
       "             (SELECT id FROM nvts AS outer_nvts"
       "              WHERE oid = results.nvt"
       "              AND"
       "              (cve = 'NOCVE'"
       "               OR NOT EXISTS"
       "                  (SELECT cve FROM nvts"
       "                   WHERE oid IN (SELECT source_name"
       "                                 FROM report_host_details"
       "                                 WHERE report_host"
       "                                 = (SELECT id"
       "                                    FROM report_hosts"
       "                                    WHERE report = results.report"
       "                                    AND host = results.host)"
       "                                 AND name = 'EXIT_CODE'"
       "                                 AND value = 'EXIT_NOTVULN')"
       "                   AND family IN (" LSC_FAMILY_LIST ")"
       /* The CVE of the result NVT is outer_nvts.cve.  The CVE of the
        * NVT that has registered the "closed" host detail is nvts.cve.
        * Either can be a list of CVEs. */
       "                   AND common_cve (nvts.cve, outer_nvts.cve)))))"
       "           THEN NULL"
       "           WHEN severity = " G_STRINGIFY (SEVERITY_ERROR) " THEN NULL"
       "           ELSE 1 END)"
       "         ELSE 0 END) AS autofp"
       " FROM results,"
       "  (SELECT 0 AS autofp_selection"
       "   UNION SELECT 1 AS autofp_selection"
       "   UNION SELECT 2 AS autofp_selection) AS autofp_opts;");
}

/**
 * @brief Ensure sequences for automatic ids are in a consistent state.
 */
void
check_db_sequences ()
{
  // Do nothing because this is only relevant for PostgreSQL.
}


/* SecInfo. */

/**
 * @brief Attach external databases.
 */
void
manage_attach_databases ()
{
  /* Attach the SCAP database. */

  if (access (OPENVAS_SCAP_DATA_DIR "/scap.db", R_OK))
    switch (errno)
      {
        case ENOENT:
          break;
        default:
          g_warning ("%s: failed to stat SCAP database: %s\n",
                     __FUNCTION__,
                     strerror (errno));
          break;
      }
  else
    sql_error ("ATTACH DATABASE '" OPENVAS_SCAP_DATA_DIR "/scap.db'"
               " AS scap;");

  /* Attach the CERT database. */

  if (access (OPENVAS_CERT_DATA_DIR "/cert.db", R_OK))
    switch (errno)
      {
        case ENOENT:
          break;
        default:
          g_warning ("%s: failed to stat CERT database: %s\n",
                     __FUNCTION__,
                     strerror (errno));
          break;
      }
  else
    sql_error ("ATTACH DATABASE '" OPENVAS_CERT_DATA_DIR "/cert.db'"
               " AS cert;");
}

/**
 * @brief Check whether CERT is available.
 *
 * @return 1 if CERT database is loaded, else 0.
 */
int
manage_cert_loaded ()
{
  static int loaded = 0;

  if (loaded)
    return 1;

  if (access (OPENVAS_CERT_DATA_DIR "/cert.db", R_OK))
    switch (errno)
      {
        case ENOENT:
          return 0;
          break;
        default:
          g_warning ("%s: failed to stat CERT database: %s\n",
                     __FUNCTION__,
                     strerror (errno));
          return 0;
      }

  if (sql_error ("SELECT count(*) FROM cert.sqlite_master"
                 " WHERE type = 'table' AND name = 'dfn_cert_advs';"))
    /* There was an error, so probably the initial ATTACH failed. */
    return 0;

  loaded = !!sql_int ("SELECT count(*) FROM cert.sqlite_master"
                      " WHERE type = 'table' AND name = 'dfn_cert_advs';");
  return loaded;
}

/**
 * @brief Check whether SCAP is available.
 *
 * @return 1 if SCAP database is loaded, else 0.
 */
int
manage_scap_loaded ()
{
  static int loaded = 0;

  if (loaded)
    return 1;

  if (access (OPENVAS_SCAP_DATA_DIR "/scap.db", R_OK))
    switch (errno)
      {
        case ENOENT:
          return 0;
          break;
        default:
          g_warning ("%s: failed to stat SCAP database: %s\n",
                     __FUNCTION__,
                     strerror (errno));
          return 0;
      }

  if (sql_error ("SELECT count(*) FROM scap.sqlite_master"
                 " WHERE type = 'table' AND name = 'cves';"))
    /* There was an error, so probably the initial ATTACH failed. */
    return 0;

  loaded = !!sql_int ("SELECT count(*) FROM scap.sqlite_master"
                      " WHERE type = 'table' AND name = 'cves';");
  return loaded;
}


/* Backup. */

/**
 * @brief Backup the database to a file.
 *
 * @param[in]   database         Database to backup.
 * @param[out]  backup_file_arg  Location for freshly allocated name of backup
 *                               file, or NULL.  Only set on success.
 *
 * @return 0 success, -1 error.
 */
static int
backup_db (const gchar *database, gchar **backup_file_arg)
{
  gchar *backup_file;
  sqlite3 *backup_db, *actual_task_db;
  sqlite3_backup *backup;

  backup_file = g_strdup_printf ("%s.bak", database);

  if (sqlite3_open (backup_file, &backup_db) != SQLITE_OK)
    {
      g_warning ("%s: sqlite3_open failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      goto fail;
    }

  /* Turn off WAL for the backup db. */
  actual_task_db = task_db;
  task_db = backup_db;
  sql ("PRAGMA journal_mode=DELETE;");
  task_db = actual_task_db;

  backup = sqlite3_backup_init (backup_db, "main", task_db, "main");
  if (backup == NULL)
    {
      g_warning ("%s: sqlite3_backup_init failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (backup_db));
      goto fail;
    }

  while (1)
    {
      int ret;

      ret = sqlite3_backup_step (backup, 20 /* pages */);
      if (ret == SQLITE_DONE)
        break;
      if (ret == SQLITE_OK)
        continue;
      if (ret == SQLITE_BUSY || ret == SQLITE_LOCKED)
        {
          sqlite3_sleep (250);
          continue;
        }
      g_warning ("%s: sqlite3_backup_step failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (backup_db));
      sqlite3_backup_finish (backup);
      goto fail;
    }
  sqlite3_backup_finish (backup);
  sqlite3_close (backup_db);

  if (backup_file_arg)
    *backup_file_arg = backup_file;
  else
    g_free (backup_file);
  return 0;

 fail:
  sqlite3_close (backup_db);
  g_free (backup_file);
  return -1;
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
  const gchar *db = database ? database : sql_default_database ();

  init_manage_process (0, db);

  ret = backup_db (db, NULL);

  cleanup_manage_process (TRUE);

  return ret;
}


/* Migrator helper. */

/**
 * @brief Convert a UTC text time to an integer time since the Epoch.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
migrate_51_to_52_sql_convert (sqlite3_context *context, int argc,
                              sqlite3_value** argv)
{
  const unsigned char *text_time;
  int epoch_time;
  struct tm tm;

  assert (argc == 1);

  text_time = sqlite3_value_text (argv[0]);
  if (text_time)
    {
      /* Scanner uses ctime: "Wed Jun 30 21:49:08 1993".
       *
       * The dates being converted are in the timezone that the Scanner was using.
       *
       * As a special case for this migrator, openvasmd.c uses the timezone
       * from the environment, instead of forcing UTC.  This allows the user
       * to set the timezone to be the same as the Scanner timezone, so
       * that these dates are converted from the Scanner timezone.  Even if
       * the user just leaves the timezone as is, it is likely to be the same
       * timezone she/he is running the Scanner under.
       */
      if (text_time && (strlen ((char*) text_time) > 0))
        {
          memset (&tm, 0, sizeof (struct tm));
          if (strptime ((char*) text_time, "%a %b %d %H:%M:%S %Y", &tm) == NULL)
            {
              sqlite3_result_error (context, "Failed to parse time", -1);
              return;
            }
          epoch_time = mktime (&tm);
          if (epoch_time == -1)
            {
              sqlite3_result_error (context, "Failed to make time", -1);
              return;
            }
        }
      else
        epoch_time = 0;
    }
  else
    epoch_time = 0;
  sqlite3_result_int (context, epoch_time);
}

/**
 * @brief Setup SQL function for migrate_51_to_52.
 *
 * @return 0 success, -1 error.
 */
int
manage_create_migrate_51_to_52_convert ()
{
  if (sqlite3_create_function (task_db,
                               "convert",
                               1,               /* Number of args. */
                               SQLITE_UTF8,
                               NULL,            /* Callback data. */
                               migrate_51_to_52_sql_convert,
                               NULL,            /* xStep. */
                               NULL)            /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create convert", __FUNCTION__);
      return -1;
    }
  return 0;
}
