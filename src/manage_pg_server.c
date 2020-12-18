/* Copyright (C) 2014-2018 Greenbone Networks GmbH
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

/**
 * @file  manage_pg_server.c
 * @brief GVM management layer: Postgres server-side functions.
 *
 * This file contains a server-side module for Postgres, that defines SQL
 * functions for the management layer that need to be implemented in C.
 */

#include "manage_utils.h"

#include "postgres.h"
#include "fmgr.h"
#include "executor/spi.h"
#include "glib.h"

#include <gvm/base/hosts.h>

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif

/**
 * @brief Create a string from a portion of text.
 *
 * @param[in]  text_arg  Text.
 * @param[in]  length    Length to create.
 *
 * @return Freshly allocated string.
 */
static char *
textndup (text *text_arg, int length)
{
  char *ret;
  ret = palloc (length + 1);
  memcpy (ret, VARDATA (text_arg), length);
  ret[length] = 0;
  return ret;
}

/**
 * @brief Get the maximum number of hosts.
 *
 * @return The maximum number of hosts.
 */
static int
get_max_hosts ()
{
  int ret;
  int max_hosts = 4095;
  SPI_connect ();
  ret = SPI_exec ("SELECT coalesce ((SELECT value FROM meta"
                  "                  WHERE name = 'max_hosts'),"
                  "                 '4095');", /* Same as MANAGE_MAX_HOSTS. */
                  1); /* Max 1 row returned. */
  if (SPI_processed > 0 && ret > 0 && SPI_tuptable != NULL)
    {
      char *cell;

      cell = SPI_getvalue (SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);
      elog (DEBUG1, "cell: %s", cell);
      if (cell)
        max_hosts = atoi (cell);
    }
  elog (DEBUG1, "done");
  SPI_finish ();

  return max_hosts;
}

/**
 * @brief Define function for Postgres.
 */
PG_FUNCTION_INFO_V1 (sql_hosts_contains);

/**
 * @brief Return if argument 1 matches regular expression in argument 2.
 *
 * This is a callback for a SQL function of two arguments.
 *
 * @return Postgres Datum.
 */
Datum
sql_hosts_contains (PG_FUNCTION_ARGS)
{
  if (PG_ARGISNULL (0) || PG_ARGISNULL (1))
    PG_RETURN_BOOL (0);
  else
    {
      text *hosts_arg, *find_host_arg;
      char *hosts, *find_host;
      int max_hosts, ret;

      hosts_arg = PG_GETARG_TEXT_P(0);
      hosts = textndup (hosts_arg, VARSIZE (hosts_arg) - VARHDRSZ);

      find_host_arg = PG_GETARG_TEXT_P(1);
      find_host = textndup (find_host_arg, VARSIZE (find_host_arg) - VARHDRSZ);

      max_hosts = get_max_hosts ();

      if (hosts_str_contains ((gchar *) hosts, (gchar *) find_host,
                              max_hosts))
        ret = 1;
      else
        ret = 0;

      pfree (hosts);
      pfree (find_host);
      PG_RETURN_BOOL (ret);
    }
}

/**
 * @brief Define function for Postgres.
 */
PG_FUNCTION_INFO_V1 (sql_level_max_severity);

/**
 * @brief Dummy function to allow restoring gvmd-9.0 dumps.
 *
 * @deprecated This function will be removed once direct migration
 *             compatibility with gvmd 9.0 is no longer required
 *
 * @return Postgres NULL Datum.
 */
 __attribute__((deprecated))
Datum
sql_level_max_severity (PG_FUNCTION_ARGS)
{
  PG_RETURN_NULL ();
}

/**
 * @brief Define function for Postgres.
 */
PG_FUNCTION_INFO_V1 (sql_level_min_severity);

/**
 * @brief Dummy function to allow restoring gvmd-9.0 dumps.
 *
 * @deprecated This function will be removed once direct migration
 *             compatibility with gvmd 9.0 is no longer required
 *
 * @return Postgres NULL Datum.
 */
 __attribute__((deprecated))
Datum
sql_level_min_severity (PG_FUNCTION_ARGS)
{
  PG_RETURN_NULL ();
}

/**
 * @brief Define function for Postgres.
 */
PG_FUNCTION_INFO_V1 (sql_next_time);

/**
 * @brief Dummy function to allow restoring gvmd-9.0 dumps.
 *
 * @deprecated This function will be removed once direct migration
 *             compatibility with gvmd 9.0 is no longer required
 *
 * @return Postgres NULL Datum.
 */
 __attribute__((deprecated))
Datum
sql_next_time (PG_FUNCTION_ARGS)
{
  PG_RETURN_NULL ();
}

/**
 * @brief Define function for Postgres.
 */
PG_FUNCTION_INFO_V1 (sql_next_time_ical);

/**
 * @brief Get the next time given schedule times.
 *
 * This is a callback for a SQL function of one to three arguments.
 *
 * @return Postgres Datum.
 */
Datum
sql_next_time_ical (PG_FUNCTION_ARGS)
{
  char *ical_string, *zone;
  int periods_offset;
  int32 ret;

  if (PG_NARGS() < 1 || PG_ARGISNULL (0))
    {
      PG_RETURN_NULL ();
    }
  else
    {
      text* ical_string_arg;
      ical_string_arg = PG_GETARG_TEXT_P (0);
      ical_string = textndup (ical_string_arg,
                              VARSIZE (ical_string_arg) - VARHDRSZ);
    }

  if (PG_NARGS() < 2 || PG_ARGISNULL (1))
    zone = NULL;
  else
    {
      text* timezone_arg;
      timezone_arg = PG_GETARG_TEXT_P (1);
      zone = textndup (timezone_arg, VARSIZE (timezone_arg) - VARHDRSZ);
    }

  if (PG_NARGS() < 3)
    periods_offset = 0;
  else
    periods_offset = PG_GETARG_INT32 (2);

  ret = icalendar_next_time_from_string (ical_string, zone,
                                         periods_offset);
  if (ical_string)
    pfree (ical_string);
  if (zone)
    pfree (zone);
  PG_RETURN_INT32 (ret);
}

/**
 * @brief Define function for Postgres.
 */
PG_FUNCTION_INFO_V1 (sql_max_hosts);

/**
 * @brief Return number of hosts.
 *
 * This is a callback for a SQL function of two arguments.
 *
 * @return Postgres Datum.
 */
Datum
sql_max_hosts (PG_FUNCTION_ARGS)
{
  if (PG_ARGISNULL (0))
    PG_RETURN_INT32 (0);
  else
    {
      text *hosts_arg;
      char *hosts, *exclude, *clean_hosts, *clean_exclude;
      int ret, max_hosts;

      hosts_arg = PG_GETARG_TEXT_P (0);
      hosts = textndup (hosts_arg, VARSIZE (hosts_arg) - VARHDRSZ);
      clean_hosts = clean_hosts_string (hosts);

      if (PG_ARGISNULL (1))
        {
          exclude = palloc (1);
          exclude[0] = 0;
          clean_exclude = NULL;
        }
      else
        {
          text *exclude_arg;
          exclude_arg = PG_GETARG_TEXT_P (1);
          exclude = textndup (exclude_arg, VARSIZE (exclude_arg) - VARHDRSZ);
          clean_exclude = clean_hosts_string (exclude);
        }

      max_hosts = get_max_hosts ();
      ret = manage_count_hosts_max (clean_hosts, clean_exclude, max_hosts);
      pfree (hosts);
      pfree (exclude);
      g_free (clean_hosts);
      g_free (clean_exclude);
      PG_RETURN_INT32 (ret);
    }
}

/**
 * @brief Define function for Postgres.
 */
PG_FUNCTION_INFO_V1 (sql_severity_matches_ov);

/**
 * @brief Return max severity of level.
 *
 * This is a callback for a SQL function of one argument.
 *
 * @return Postgres Datum.
 */
 __attribute__((deprecated))
Datum
sql_severity_matches_ov (PG_FUNCTION_ARGS)
{
  PG_RETURN_NULL ();
}

/**
 * @brief Define function for Postgres.
 */
PG_FUNCTION_INFO_V1 (sql_regexp);

/**
 * @brief Return if argument 1 matches regular expression in argument 2.
 *
 * This is a callback for a SQL function of two arguments.
 *
 * @return Postgres Datum.
 */
Datum
sql_regexp (PG_FUNCTION_ARGS)
{
  if (PG_ARGISNULL (0) || PG_ARGISNULL (1))
    PG_RETURN_BOOL (0);
  else
    {
      text *string_arg, *regexp_arg;
      char *string, *regexp;
      int ret;

      regexp_arg = PG_GETARG_TEXT_P(1);
      regexp = textndup (regexp_arg, VARSIZE (regexp_arg) - VARHDRSZ);

      string_arg = PG_GETARG_TEXT_P(0);
      string = textndup (string_arg, VARSIZE (string_arg) - VARHDRSZ);

      if (g_regex_match_simple ((gchar *) regexp, (gchar *) string, 0, 0))
        ret = 1;
      else
        ret = 0;

      pfree (string);
      pfree (regexp);
      PG_RETURN_BOOL (ret);
    }
}

/**
 * @brief Define function for Postgres.
 */
PG_FUNCTION_INFO_V1 (sql_valid_db_resource_type);

/**
 * @brief Dummy function to allow restoring gvmd-9.0 dumps.
 *
 * @deprecated This function will be removed once direct migration
 *             compatibility with gvmd 9.0 is no longer required
 *
 * @return Postgres NULL Datum.
 */
 __attribute__((deprecated))
Datum
sql_valid_db_resource_type (PG_FUNCTION_ARGS)
{
  PG_RETURN_NULL ();
}
