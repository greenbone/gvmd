/* OpenVAS Manager
 * $Id$
 * Description: Manager Manage library: Postgres server-side functions.
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

#include "manage_utils.h"

#include "postgres.h"
#include "fmgr.h"
#include "executor/spi.h"

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif

/**
 * @brief Create a string from a portion of text.
 *
 * @param[in]  text_arg  Text.
 * @param[in]  length    Length to create.
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

PG_FUNCTION_INFO_V1 (sql_next_time);

/**
 * @brief Get the next time given schedule times.
 *
 * This is a callback for a SQL function of three to four arguments.
 */
Datum
sql_next_time (PG_FUNCTION_ARGS)
{
  int32 first, period, period_months;
  char *timezone;
  int32 ret;

  first = PG_GETARG_INT32 (0);
  period = PG_GETARG_INT32 (1);
  period_months = PG_GETARG_INT32 (2);

  if (PG_NARGS() < 4 || PG_ARGISNULL (3))
    timezone = NULL;
  else
    {
      text* timezone_arg;
      timezone_arg = PG_GETARG_TEXT_P (3);
      timezone = textndup (timezone_arg, VARSIZE (timezone_arg) - VARHDRSZ);
    }

  ret = next_time (first, period, period_months, timezone, 0);
  if (PG_NARGS() >= 4)
    pfree (timezone);
  PG_RETURN_INT32 (ret);
}

PG_FUNCTION_INFO_V1 (sql_max_hosts);

/**
 * @brief Return number of hosts.
 *
 * This is a callback for a SQL function of two arguments.
 */
Datum
sql_max_hosts (PG_FUNCTION_ARGS)
{
  if (PG_ARGISNULL (0))
    PG_RETURN_INT32 (0);
  else
    {
      text *hosts_arg;
      char *hosts, *exclude;
      int ret, max_hosts;

      hosts_arg = PG_GETARG_TEXT_P (0);
      hosts = textndup (hosts_arg, VARSIZE (hosts_arg) - VARHDRSZ);
      if (PG_ARGISNULL (1))
        {
          exclude = palloc (1);
          exclude[0] = 0;
        }
      else
        {
          text *exclude_arg;
          exclude_arg = PG_GETARG_TEXT_P (1);
          exclude = textndup (exclude_arg, VARSIZE (exclude_arg) - VARHDRSZ);
        }

      max_hosts = 4095;
      SPI_connect ();
      ret = SPI_exec ("SELECT coalesce ((SELECT value FROM meta"
                      "                  WHERE name = 'max_hosts'),"
                      "                 '4095');", /* Same as MANAGE_MAX_HOSTS. */
                      1); /* Max 1 row returned. */
      if (SPI_processed > 0 && ret > 0 && SPI_tuptable != NULL)
        {
          char *cell;

          cell = SPI_getvalue (SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);
          elog (INFO, "cell: %s", cell);
          if (cell)
            max_hosts = atoi (cell);
        }
      elog (INFO, "done");
      SPI_finish ();

      ret = manage_count_hosts_max (hosts, exclude, max_hosts);
      pfree (hosts);
      pfree (exclude);
      PG_RETURN_INT32 (ret);
    }
}

PG_FUNCTION_INFO_V1 (sql_level_min_severity);

/**
 * @brief Return min severity of level.
 *
 * This is a callback for a SQL function of two arguments.
 */
Datum
sql_level_min_severity (PG_FUNCTION_ARGS)
{
  if (PG_ARGISNULL (0))
    PG_RETURN_FLOAT8 (0.0);
  else
    {
      text *level_arg, *class_arg;
      char *level, *class;
      float8 severity;

      class_arg = PG_GETARG_TEXT_P (1);
      class = textndup (class_arg, VARSIZE (class_arg) - VARHDRSZ);

      level_arg = PG_GETARG_TEXT_P (0);
      level = textndup (level_arg, VARSIZE (level_arg) - VARHDRSZ);

      severity = level_min_severity (level, class);

      pfree (level);
      pfree (class);
      PG_RETURN_FLOAT8 (severity);
    }
}

PG_FUNCTION_INFO_V1 (sql_level_max_severity);

/**
 * @brief Return max severity of level.
 *
 * This is a callback for a SQL function of two arguments.
 */
Datum
sql_level_max_severity (PG_FUNCTION_ARGS)
{
  if (PG_ARGISNULL (0))
    PG_RETURN_FLOAT8 (0.0);
  else
    {
      text *level_arg, *class_arg;
      char *level, *class;
      float8 severity;

      class_arg = PG_GETARG_TEXT_P (1);
      class = textndup (class_arg, VARSIZE (class_arg) - VARHDRSZ);

      level_arg = PG_GETARG_TEXT_P (0);
      level = textndup (level_arg, VARSIZE (level_arg) - VARHDRSZ);

      severity = level_max_severity (level, class);

      pfree (level);
      pfree (class);
      PG_RETURN_FLOAT8 (severity);
    }
}

PG_FUNCTION_INFO_V1 (sql_valid_db_resource_type);

/**
 * @brief Return max severity of level.
 *
 * This is a callback for a SQL function of one argument.
 */
Datum
sql_valid_db_resource_type (PG_FUNCTION_ARGS)
{
  if (PG_ARGISNULL (0))
    PG_RETURN_BOOL (0);
  else
    {
      text *type_arg;
      char *type;
      int ret;

      type_arg = PG_GETARG_TEXT_P (0);
      type = textndup (type_arg, VARSIZE (type_arg) - VARHDRSZ);

      ret = valid_db_resource_type (type);

      pfree (type);
      PG_RETURN_BOOL (ret);
    }
}
