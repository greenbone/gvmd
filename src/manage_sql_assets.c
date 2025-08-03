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
#include "manage.h"
#include "manage_sql.h"
#include "sql.h"

#include <gvm/base/array.h>
#include <gvm/util/xmlutils.h>

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

// FIX Extern for now, until more code is moved in here.
extern array_t *
identifiers;

// FIX Extern for now, until more code is moved in here.
extern array_t *
identifier_hosts;

/**
 * @brief Add host details to a report host.
 *
 * @param[in]  report  UUID of resource.
 * @param[in]  ip      Host.
 * @param[in]  entity  XML entity containing details.
 * @param[in]  hashed_host_details  A GHashtable containing hashed host details.
 *
 * @return 0 success, -1 failed to parse XML.
 */
static int
manage_report_host_details (report_t report, const char *ip,
                            entity_t entity, GHashTable *hashed_host_details)
{
  int in_assets;
  entities_t details;
  entity_t detail;
  char *uuid;
  char *hash_value;

  in_assets = sql_int ("SELECT not(value = 'no') FROM task_preferences"
                       " WHERE task = (SELECT task FROM reports"
                       "                WHERE id = %llu)"
                       " AND name = 'in_assets';",
                       report);

  details = entity->entities;
  if (identifiers == NULL)
    identifiers = make_array ();
  if (identifier_hosts == NULL)
    identifier_hosts = make_array ();
  uuid = report_uuid (report);
  while ((detail = first_entity (details)))
    {
      if (strcmp (entity_name (detail), "detail") == 0)
        {
          entity_t source, source_type, source_name, source_desc, name, value;

          /* Parse host detail and add to report */
          source = entity_child (detail, "source");
          if (source == NULL)
            goto error;
          source_type = entity_child (source, "type");
          if (source_type == NULL)
            goto error;
          source_name = entity_child (source, "name");
          if (source_name == NULL)
            goto error;
          source_desc = entity_child (source, "description");
          if (source_desc == NULL)
            goto error;
          name = entity_child (detail, "name");
          if (name == NULL)
            goto error;
          value = entity_child (detail, "value");
          if (value == NULL)
            goto error;

          if (!check_host_detail_exists (report, ip, entity_text (source_type),
                                         entity_text (source_name),
                                         entity_text (source_desc),
                                         entity_text (name),
                                         entity_text (value),
                                         (char**) &hash_value,
                                         hashed_host_details))
            {
              insert_report_host_detail
               (report, ip, entity_text (source_type), entity_text (source_name),
                entity_text (source_desc), entity_text (name), entity_text (value),
                hash_value);
              g_free (hash_value);
            }
          else
            {
              g_free (hash_value);
              details = next_entities (details);
              continue;
            }

          /* Only add to assets if "Add to Assets" is set on the task. */
          if (in_assets)
            {
              if (strcmp (entity_text (name), "hostname") == 0)
                {
                  identifier_t *identifier;

                  identifier = g_malloc (sizeof (identifier_t));
                  identifier->ip = g_strdup (ip);
                  identifier->name = g_strdup ("hostname");
                  identifier->value = g_strdup (entity_text (value));
                  identifier->source_id = g_strdup (uuid);
                  identifier->source_type = g_strdup ("Report Host Detail");
                  identifier->source_data
                    = g_strdup (entity_text (source_name));
                  array_add (identifiers, identifier);
                  array_add_new_string (identifier_hosts, g_strdup (ip));
                }
              if (strcmp (entity_text (name), "MAC") == 0)
                {
                  identifier_t *identifier;

                  identifier = g_malloc (sizeof (identifier_t));
                  identifier->ip = g_strdup (ip);
                  identifier->name = g_strdup ("MAC");
                  identifier->value = g_strdup (entity_text (value));
                  identifier->source_id = g_strdup (uuid);
                  identifier->source_type = g_strdup ("Report Host Detail");
                  identifier->source_data
                    = g_strdup (entity_text (source_name));
                  array_add (identifiers, identifier);
                  array_add_new_string (identifier_hosts, g_strdup (ip));
                }
              if (strcmp (entity_text (name), "OS") == 0
                  && g_str_has_prefix (entity_text (value), "cpe:"))
                {
                  identifier_t *identifier;

                  identifier = g_malloc (sizeof (identifier_t));
                  identifier->ip = g_strdup (ip);
                  identifier->name = g_strdup ("OS");
                  identifier->value = g_strdup (entity_text (value));
                  identifier->source_id = g_strdup (uuid);
                  identifier->source_type = g_strdup ("Report Host Detail");
                  identifier->source_data
                    = g_strdup (entity_text (source_name));
                  array_add (identifiers, identifier);
                  array_add_new_string (identifier_hosts, g_strdup (ip));
                }
              if (strcmp (entity_text (name), "ssh-key") == 0)
                {
                  identifier_t *identifier;

                  identifier = g_malloc (sizeof (identifier_t));
                  identifier->ip = g_strdup (ip);
                  identifier->name = g_strdup ("ssh-key");
                  identifier->value = g_strdup (entity_text (value));
                  identifier->source_id = g_strdup (uuid);
                  identifier->source_type = g_strdup ("Report Host Detail");
                  identifier->source_data
                    = g_strdup (entity_text (source_name));
                  array_add (identifiers, identifier);
                  array_add_new_string (identifier_hosts, g_strdup (ip));
                }
            }
        }
      details = next_entities (details);
    }
  free (uuid);

  return 0;

 error:
  free (uuid);
  return -1;
}

/**
 * @brief Add a host detail to a report host.
 *
 * @param[in]  report  UUID of resource.
 * @param[in]  host    Host.
 * @param[in]  xml     Report host detail XML.
 * @param[in]  hashed_host_details  A GHashtable containing hashed host details.
 *
 * @return 0 success, -1 failed to parse XML, -2 host was NULL.
 */
int
manage_report_host_detail (report_t report, const char *host,
                           const char *xml, GHashTable *hashed_host_details)
{
  int ret;
  entity_t entity;

  if (host == NULL)
    return -2;

  entity = NULL;
  if (parse_entity (xml, &entity))
    return -1;

  ret = manage_report_host_details (report,
                                    host,
                                    entity,
                                    hashed_host_details);
  free_entity (entity);
  return ret;
}
