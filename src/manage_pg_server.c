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

#include "manage_utils.h"

#include "postgres.h"
#include "fmgr.h"
#include <string.h>

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif

PG_FUNCTION_INFO_V1 (next_time);

/**
 * @brief Get the name of a resource by its type and ID.
 *
 * This is a callback for a SQL function of three arguments.
 */
Datum
sql_next_time (PG_FUNCTION_ARGS)
{
  int32 first, period, period_months;

  first = PG_GETARG_INT32 (0);
  period = PG_GETARG_INT32 (1);
  period_months = PG_GETARG_INT32 (2);

  PG_RETURN_INT32 (next_time (first, period, period_months));
}
