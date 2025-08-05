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
#include "manage_acl.h"
#include "manage_sql.h"
#include "sql.h"

#include <gvm/base/array.h>
#include <gvm/base/hosts.h>
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

/**
 * @brief Create a host asset.
 *
 * @param[in]  host_name    Host Name.
 * @param[in]  comment      Comment.
 * @param[out] host_return  Created asset.
 *
 * @return 0 success, 1 failed to find report, 2 host not an IP address,
 *         99 permission denied, -1 error.
 */
int
create_asset_host (const char *host_name, const char *comment,
                   resource_t* host_return)
{
  int host_type;
  resource_t host;
  gchar *quoted_host_name, *quoted_comment;

  if (host_name == NULL)
    return -1;

  sql_begin_immediate ();

  if (acl_user_may ("create_asset") == 0)
    {
      sql_rollback ();
      return 99;
    }

  host_type = gvm_get_host_type (host_name);
  if (host_type != HOST_TYPE_IPV4 && host_type != HOST_TYPE_IPV6)
    {
      sql_rollback ();
      return 2;
    }

  quoted_host_name = sql_quote (host_name);
  quoted_comment = sql_quote (comment ? comment : "");
  sql ("INSERT into hosts"
       " (uuid, owner, name, comment, creation_time, modification_time)"
       " VALUES"
       " (make_uuid (), (SELECT id FROM users WHERE uuid = '%s'), '%s', '%s',"
       "  m_now (), m_now ());",
       current_credentials.uuid,
       quoted_host_name,
       quoted_comment);
  g_free (quoted_comment);

  host = sql_last_insert_id ();

  sql ("INSERT into host_identifiers"
       " (uuid, host, owner, name, comment, value, source_type, source_id,"
       "  source_data, creation_time, modification_time)"
       " VALUES"
       " (make_uuid (), %llu, (SELECT id FROM users WHERE uuid = '%s'), 'ip',"
       "  '', '%s', 'User', '%s', '', m_now (), m_now ());",
       host,
       current_credentials.uuid,
       quoted_host_name,
       current_credentials.uuid);

  g_free (quoted_host_name);

  if (host_return)
    *host_return = host;

  sql_commit ();

  return 0;
}

/**
 * @brief Check whether a string is an identifier name.
 *
 * @param[in]  name  Possible identifier name.
 *
 * @return 1 if an identifier name, else 0.
 */
static int
identifier_name (const char *name)
{
  return (strcmp ("hostname", name) == 0)
         || (strcmp ("MAC", name) == 0)
         || (strcmp ("OS", name) == 0)
         || (strcmp ("ssh-key", name) == 0);
}

/**
 * @brief Create all available assets from a report.
 *
 * @param[in]  report_id  UUID of report.
 * @param[in]  term       Filter term, for min_qod and apply_overrides.
 *
 * @return 0 success, 1 failed to find report, 99 permission denied, -1 error.
 */
int
create_asset_report (const char *report_id, const char *term)
{
  resource_t report;
  iterator_t hosts;
  gchar *quoted_report_id;
  int apply_overrides, min_qod;

  if (report_id == NULL)
    return -1;

  sql_begin_immediate ();

  if (acl_user_may ("create_asset") == 0)
    {
      sql_rollback ();
      return 99;
    }

  report = 0;
  if (find_report_with_permission (report_id, &report, "get_reports"))
    {
      sql_rollback ();
      return -1;
    }

  if (report == 0)
    {
      sql_rollback ();
      return 1;
    }

  /* These are freed by hosts_set_identifiers. */
  if (identifiers == NULL)
    identifiers = make_array ();
  if (identifier_hosts == NULL)
    identifier_hosts = make_array ();

  quoted_report_id = sql_quote (report_id);
  sql ("DELETE FROM host_identifiers WHERE source_id = '%s';",
       quoted_report_id);
  sql ("DELETE FROM host_oss WHERE source_id = '%s';",
       quoted_report_id);
  sql ("DELETE FROM host_max_severities WHERE source_id = '%s';",
       quoted_report_id);
  sql ("DELETE FROM host_details WHERE source_id = '%s';",
       quoted_report_id);
  g_free (quoted_report_id);

  init_report_host_iterator (&hosts, report, NULL, 0);
  while (next (&hosts))
    {
      const char *host;
      report_host_t report_host;
      iterator_t details;

      host = host_iterator_host (&hosts);
      report_host = host_iterator_report_host (&hosts);

      if (report_host_dead (report_host)
          || report_host_result_count (report_host) == 0)
        continue;

      host_notice (host, "ip", host, "Report Host", report_id, 0, 0);

      init_report_host_details_iterator (&details, report_host);
      while (next (&details))
        {
          const char *name;

          name = report_host_details_iterator_name (&details);

          if (identifier_name (name))
            {
              const char *value;
              identifier_t *identifier;

              value = report_host_details_iterator_value (&details);

              if ((strcmp (name, "OS") == 0)
                  && (g_str_has_prefix (value, "cpe:") == 0))
                continue;

              identifier = g_malloc (sizeof (identifier_t));
              identifier->ip = g_strdup (host);
              identifier->name = g_strdup (name);
              identifier->value = g_strdup (value);
              identifier->source_id = g_strdup (report_id);
              identifier->source_type = g_strdup ("Report Host Detail");
              identifier->source_data
               = g_strdup (report_host_details_iterator_source_name (&details));

              array_add (identifiers, identifier);
              array_add_new_string (identifier_hosts, g_strdup (host));
            }
        }
      cleanup_iterator (&details);
    }
  cleanup_iterator (&hosts);
  hosts_set_identifiers (report);
  apply_overrides = filter_term_apply_overrides (term);
  min_qod = filter_term_min_qod (term);
  hosts_set_max_severity (report, &apply_overrides, &min_qod);
  hosts_set_details (report);

  sql_commit ();

  return 0;
}
