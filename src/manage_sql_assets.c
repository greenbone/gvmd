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

/**
 * @brief Return the UUID of a host.
 *
 * @param[in]  host  Host.
 *
 * @return Host UUID.
 */
char*
host_uuid (resource_t host)
{
  return sql_string ("SELECT uuid FROM hosts WHERE id = %llu;",
                     host);
}

/**
 * @brief Add a report host.
 *
 * @param[in]  report   UUID of resource.
 * @param[in]  host     Host.
 * @param[in]  start    Start time.
 * @param[in]  end      End time.
 *
 * @return Report host.
 */
report_host_t
manage_report_host_add (report_t report, const char *host, time_t start,
                        time_t end)
{
  char *quoted_host = sql_quote (host);
  resource_t report_host;
  
  sql ("INSERT INTO report_hosts"
       " (report, host, start_time, end_time, current_port, max_port)"
       " SELECT %llu, '%s', %lld, %lld, 0, 0"
       " WHERE NOT EXISTS (SELECT 1 FROM report_hosts WHERE report = %llu"
       "                   AND host = '%s');",
       report, quoted_host, (long long) start, (long long) end, report,
       quoted_host);
  report_host = sql_int64_0 ("SELECT id FROM report_hosts"
                             " WHERE report = %llu AND host = '%s';",
                             report, quoted_host);
  g_free (quoted_host);
  return report_host;
}

/**
 * @brief Set end time of a report host.
 *
 * @param[in]  report_host  Report host.
 * @param[in]  end_time     End time.
 */
void
report_host_set_end_time (report_host_t report_host, time_t end_time)
{
  sql ("UPDATE report_hosts SET end_time = %lld WHERE id = %llu;",
       end_time, report_host);
}
