/* Copyright (C) 2009-2025 Greenbone AG
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

#include "manage_sql_assets.h"
#include "sql.h"

/**
 * @brief Return the UUID of the asset associated with a result host.
 *
 * @param[in]  host    Host value from result.
 * @param[in]  result  Result.
 *
 * @return Asset UUID.
 */
char *
result_host_asset_id (const char *host, result_t result)
{
  gchar *quoted_host;
  char *asset_id;

  quoted_host = sql_quote (host);
  asset_id = sql_string ("SELECT uuid FROM hosts"
                         " WHERE id = (SELECT host FROM host_identifiers"
                         "             WHERE source_type = 'Report Host'"
                         "             AND name = 'ip'"
                         "             AND source_id"
                         "                 = (SELECT uuid"
                         "                    FROM reports"
                         "                    WHERE id = (SELECT report"
                         "                                FROM results"
                         "                                WHERE id = %llu))"
                         "             AND value = '%s'"
                         "             LIMIT 1);",
                         result,
                         quoted_host);
  g_free (quoted_host);
  return asset_id;
}
