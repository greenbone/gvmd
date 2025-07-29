/* Copyright (C) 2014-2022 Greenbone AG
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
 * @file
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
 __attribute__((deprecated))
Datum
sql_hosts_contains (PG_FUNCTION_ARGS)
{
  PG_RETURN_NULL ();
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
 __attribute__((deprecated))
Datum
sql_next_time_ical (PG_FUNCTION_ARGS)
{
  PG_RETURN_NULL ();
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
 __attribute__((deprecated))
Datum
sql_max_hosts (PG_FUNCTION_ARGS)
{
  PG_RETURN_NULL ();
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
 __attribute__((deprecated))
Datum
sql_regexp (PG_FUNCTION_ARGS)
{
  PG_RETURN_NULL ();
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
