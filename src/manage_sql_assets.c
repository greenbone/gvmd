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
#include "manage_assets.h"
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

/**
 * @brief Host identifiers for the current scan.
 */
array_t *identifiers = NULL;

/**
 * @brief Unique hosts listed in host_identifiers.
 */
array_t *identifier_hosts = NULL;

/**
 * @brief Free an identifier.
 *
 * @param[in]  identifier  Identifier.
 */
static void
identifier_free (identifier_t *identifier)
{
  if (identifier)
    {
      g_free (identifier->ip);
      g_free (identifier->name);
      g_free (identifier->value);
      g_free (identifier->source_type);
      g_free (identifier->source_id);
      g_free (identifier->source_data);
    }
}

/**
 * @brief Setup hosts and their identifiers after a scan, from host details.
 *
 * At the end of a scan this revises the decision about which asset host to use
 * for each host that has identifiers.  The rules for this decision are described
 * in \ref asset_rules.  (The initial decision is made by \ref host_notice.)
 *
 * @param[in]  report  Report that the identifiers come from.
 */
void
hosts_set_identifiers (report_t report)
{
  if (identifier_hosts)
    {
      int host_index, index;
      gchar *ip;

      array_terminate (identifiers);
      array_terminate (identifier_hosts);

      host_index = 0;
      while ((ip = (gchar*) g_ptr_array_index (identifier_hosts, host_index)))
        {
          host_t host, host_new;
          gchar *quoted_host_name;
          identifier_t *identifier;
          GString *select;

          if (report_host_noticeable (report, ip) == 0)
            {
              host_index++;
              continue;
            }

          quoted_host_name = sql_quote (ip);

          select = g_string_new ("");

          /* Select the most recent host whose identifiers all match the given
           * identifiers, even if the host has fewer identifiers than given. */

          g_string_append_printf (select,
                                  "SELECT id FROM hosts"
                                  " WHERE name = '%s'"
                                  " AND owner = (SELECT id FROM users"
                                  "              WHERE uuid = '%s')",
                                  quoted_host_name,
                                  current_credentials.uuid);

          index = 0;
          while ((identifier = (identifier_t*) g_ptr_array_index (identifiers, index)))
            {
              gchar *quoted_identifier_name, *quoted_identifier_value;

              if (strcmp (identifier->ip, ip))
                {
                  index++;
                  continue;
                }

              quoted_identifier_name = sql_quote (identifier->name);
              quoted_identifier_value = sql_quote (identifier->value);

              g_string_append_printf (select,
                                      " AND (EXISTS (SELECT * FROM host_identifiers"
                                      "              WHERE host = hosts.id"
                                      "              AND owner = (SELECT id FROM users"
                                      "                           WHERE uuid = '%s')"
                                      "              AND name = '%s'"
                                      "              AND value = '%s')"
                                      "      OR NOT EXISTS (SELECT * FROM host_identifiers"
                                      "                     WHERE host = hosts.id"
                                      "                     AND owner = (SELECT id FROM users"
                                      "                                  WHERE uuid = '%s')"
                                      "                     AND name = '%s'))",
                                      current_credentials.uuid,
                                      quoted_identifier_name,
                                      quoted_identifier_value,
                                      current_credentials.uuid,
                                      quoted_identifier_name);

              g_free (quoted_identifier_name);
              g_free (quoted_identifier_value);

              index++;
            }

          g_string_append_printf (select,
                                  " ORDER BY creation_time DESC LIMIT 1;");

          switch (sql_int64 (&host, select->str))
            {
              case 0:
                break;
              case 1:        /* Too few rows in result of query. */
                host = 0;
                break;
              default:       /* Programming error. */
                assert (0);
              case -1:
                host = 0;
                break;
            }

          g_string_free (select, TRUE);

          if (host == 0)
            {
              /* Add the host. */

              sql ("INSERT into hosts"
                   " (uuid, owner, name, comment, creation_time, modification_time)"
                   " VALUES"
                   " (make_uuid (), (SELECT id FROM users WHERE uuid = '%s'), '%s', '',"
                   "  m_now (), m_now ());",
                   current_credentials.uuid,
                   quoted_host_name);

              host_new = host = sql_last_insert_id ();

              /* Make sure the Report Host identifiers added when the host was
               * first noticed now refer to the new host. */

              sql ("UPDATE host_identifiers SET host = %llu"
                   " WHERE source_id = (SELECT uuid FROM reports"
                   "                    WHERE id = %llu)"
                   " AND name = 'ip'"
                   " AND value = '%s';",
                   host_new,
                   report,
                   quoted_host_name);
            }
          else
            {
              /* Use the existing host. */

              host_new = 0;
            }

          /* Add the host identifiers. */

          index = 0;
          while ((identifier = (identifier_t*) g_ptr_array_index (identifiers,
                                                                  index)))
            {
              gchar *quoted_identifier_name, *quoted_identifier_value;
              gchar *quoted_source_id, *quoted_source_type, *quoted_source_data;

              if (strcmp (identifier->ip, ip))
                {
                  index++;
                  continue;
                }

              quoted_identifier_name = sql_quote (identifier->name);
              quoted_identifier_value = sql_quote (identifier->value);
              quoted_source_id = sql_quote (identifier->source_id);
              quoted_source_data = sql_quote (identifier->source_data);
              quoted_source_type = sql_quote (identifier->source_type);

              if (strcmp (identifier->name, "OS") == 0)
                {
                  resource_t os;

                  switch (sql_int64 (&os,
                                     "SELECT id FROM oss"
                                     " WHERE name = '%s'"
                                     " AND owner = (SELECT id FROM users"
                                     "              WHERE uuid = '%s');",
                                     quoted_identifier_value,
                                     current_credentials.uuid))
                    {
                      case 0:
                        break;
                      default:       /* Programming error. */
                        assert (0);
                      case -1:
                      case 1:        /* Too few rows in result of query. */
                        sql ("INSERT into oss"
                             " (uuid, owner, name, comment, creation_time,"
                             "  modification_time)"
                             " VALUES"
                             " (make_uuid (),"
                             "  (SELECT id FROM users WHERE uuid = '%s'),"
                             "  '%s', '', m_now (), m_now ());",
                             current_credentials.uuid,
                             quoted_identifier_value);
                        os = sql_last_insert_id ();
                        break;
                    }

                  sql ("INSERT into host_oss"
                       " (uuid, host, owner, name, comment, os, source_type,"
                       "  source_id, source_data, creation_time, modification_time)"
                       " VALUES"
                       " (make_uuid (), %llu,"
                       "  (SELECT id FROM users WHERE uuid = '%s'),"
                       "  '%s', '', %llu, '%s', '%s', '%s', m_now (), m_now ());",
                       host,
                       current_credentials.uuid,
                       quoted_identifier_name,
                       os,
                       quoted_source_type,
                       quoted_source_id,
                       quoted_source_data);

                  if (host_new == 0)
                    {
                      sql ("UPDATE hosts"
                           " SET modification_time = (SELECT modification_time"
                           "                          FROM host_oss"
                           "                          WHERE id = %llu)"
                           " WHERE id = %llu;",
                           sql_last_insert_id (),
                           host);

                      sql ("UPDATE oss"
                           " SET modification_time = (SELECT modification_time"
                           "                          FROM host_oss"
                           "                          WHERE id = %llu)"
                           " WHERE id = %llu;",
                           sql_last_insert_id (),
                           os);
                    }
                }
              else
                {
                  sql ("INSERT into host_identifiers"
                       " (uuid, host, owner, name, comment, value, source_type,"
                       "  source_id, source_data, creation_time, modification_time)"
                       " VALUES"
                       " (make_uuid (), %llu,"
                       "  (SELECT id FROM users WHERE uuid = '%s'),"
                       "  '%s', '', '%s', '%s', '%s', '%s', m_now (), m_now ());",
                       host,
                       current_credentials.uuid,
                       quoted_identifier_name,
                       quoted_identifier_value,
                       quoted_source_type,
                       quoted_source_id,
                       quoted_source_data);

                  if (host_new == 0)
                    sql ("UPDATE hosts"
                         " SET modification_time = (SELECT modification_time"
                         "                          FROM host_identifiers"
                         "                          WHERE id = %llu)"
                         " WHERE id = %llu;",
                         sql_last_insert_id (),
                         host);
                }

              g_free (quoted_source_type);
              g_free (quoted_source_id);
              g_free (quoted_source_data);
              g_free (quoted_identifier_name);
              g_free (quoted_identifier_value);

              index++;
            }

          g_free (quoted_host_name);
          host_index++;
        }

      index = 0;
      while (identifiers && (index < identifiers->len))
        identifier_free (g_ptr_array_index (identifiers, index++));
      array_free (identifiers);
      identifiers = NULL;

      array_free (identifier_hosts);
      identifier_hosts = NULL;
    }
}

/**
 * @brief Set the maximum severity of each host in a scan.
 *
 * @param[in]  report         The report associated with the scan.
 * @param[in]  overrides_arg  Whether override should be applied.
 * @param[in]  min_qod_arg    Min QOD to use.
 */
void
hosts_set_max_severity (report_t report, int *overrides_arg, int *min_qod_arg)
{
  gchar *new_severity_sql;
  int dynamic_severity, overrides, min_qod;

  if (overrides_arg)
    overrides = *overrides_arg;
  else
    {
      task_t task;
      /* Get "Assets Apply Overrides" task preference. */
      overrides = 1;
      if (report_task (report, &task) == 0)
        {
          char *value;
          value = task_preference_value (task, "assets_apply_overrides");
          if (value && (strcmp (value, "yes") == 0))
            overrides = 1;
          else
            overrides = 0;
          free (value);
        }
    }

  if (min_qod_arg)
    min_qod = *min_qod_arg;
  else
    {
      task_t task;
      /* Get "Assets Min QOD". */
      min_qod = MIN_QOD_DEFAULT;
      if (report_task (report, &task) == 0)
        {
          char *value;
          value = task_preference_value (task, "assets_min_qod");
          if (value)
            min_qod = atoi (value);
          free (value);
        }
    }

  dynamic_severity = setting_dynamic_severity_int ();
  new_severity_sql = new_severity_clause (overrides, dynamic_severity);

  sql ("INSERT INTO host_max_severities"
       " (host, severity, source_type, source_id, creation_time)"
       " SELECT asset_host,"
       "        coalesce ((SELECT max (%s) FROM results"
       "                   WHERE report = %llu"
       "                   AND qod >= %i"
       "                   AND host = (SELECT name FROM hosts"
       "                               WHERE id = asset_host)),"
       "                  0.0),"
       "        'Report',"
       "        (SELECT uuid FROM reports WHERE id = %llu),"
       "        m_now ()"
       " FROM (SELECT host AS asset_host"
       "       FROM host_identifiers"
       "       WHERE source_id = (SELECT uuid FROM reports WHERE id = %llu))"
       "      AS subquery;",
       new_severity_sql,
       report,
       min_qod,
       report,
       report);

  g_free (new_severity_sql);
}

/**
 * @brief Store certain host details in the assets after a scan.
 *
 * @param[in]  report  The report associated with the scan.
 */
void
hosts_set_details (report_t report)
{
  sql ("INSERT INTO host_details"
       " (detail_source_type, detail_source_name, detail_source_description,"
       "  name, value, source_type, source_id, host)"
       " SELECT source_type,"
       "        source_name,"
       "        source_description,"
       "        name,"
       "        value,"
       "        'Report',"
       "        (SELECT uuid FROM reports WHERE id = %llu),"
       "        (SELECT host"
       "         FROM host_identifiers"
       "         WHERE source_id = (SELECT uuid FROM reports"
       "                            WHERE id = %llu)"
       "         AND (SELECT name FROM hosts WHERE id = host)"
       "             = (SELECT host FROM report_hosts"
       "                WHERE id = report_host_details.report_host)"
       "         LIMIT 1)"
       " FROM report_host_details"
       " WHERE (SELECT report FROM report_hosts"
       "        WHERE id = report_host)"
       "       = %llu"
       /* Only if the task is included in the assets. */
       " AND (SELECT value = 'yes' FROM task_preferences"
       "      WHERE task = (SELECT task FROM reports WHERE id = %llu)"
       "      AND name = 'in_assets')"
       /* Ensure that every report host detail has a corresponding host
        *  in the assets. */
       " AND EXISTS (SELECT *"
       "               FROM host_identifiers"
       "              WHERE source_id = (SELECT uuid FROM reports"
       "                                 WHERE id = %llu)"
       "                AND (SELECT name FROM hosts WHERE id = host)"
       "                      = (SELECT host FROM report_hosts"
       "                         WHERE id = report_host_details.report_host))"
       " AND (name IN ('best_os_cpe', 'best_os_txt', 'traceroute'));",
       report,
       report,
       report,
       report,
       report);
}

/**
 * @brief Initialise a host identifier iterator.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  host        Host.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for type then start.
 */
void
init_host_identifier_iterator (iterator_t* iterator, host_t host,
                               int ascending, const char* sort_field)
{
  assert (current_credentials.uuid);

  if (host)
    init_iterator (iterator,
                   "SELECT id, uuid, name, comment, creation_time,"
                   "       modification_time, creation_time AS created,"
                   "       modification_time AS modified, owner, owner, value,"
                   "       source_type, source_id, source_data,"
                   "       (CASE WHEN source_type LIKE 'Report%%'"
                   "        THEN NOT EXISTS (SELECT * FROM reports"
                   "                         WHERE uuid = source_id)"
                   "        ELSE CAST (0 AS boolean)"
                   "        END),"
                   "       '', ''"
                   " FROM host_identifiers"
                   " WHERE host = %llu"
                   " UNION"
                   " SELECT id, uuid, name, comment, creation_time,"
                   "        modification_time, creation_time AS created,"
                   "        modification_time AS modified, owner, owner,"
                   "        (SELECT name FROM oss WHERE id = os),"
                   "        source_type, source_id, source_data,"
                   "        (CASE WHEN source_type LIKE 'Report%%'"
                   "         THEN NOT EXISTS (SELECT * FROM reports"
                   "                          WHERE uuid = source_id)"
                   "         ELSE CAST (0 AS boolean)"
                   "         END),"
                   "        (SELECT uuid FROM oss WHERE id = os),"
                   "        cpe_title ((SELECT name FROM oss WHERE id = os))"
                   " FROM host_oss"
                   " WHERE host = %llu"
                   " ORDER BY %s %s;",
                   host,
                   host,
                   sort_field ? sort_field : "creation_time",
                   ascending ? "ASC" : "DESC");
  else
    init_iterator (iterator,
                   "SELECT id, uuid, name, comment, creation_time,"
                   "       modification_time, creation_time AS created,"
                   "       modification_time AS modified, owner, owner, value,"
                   "       source_type, source_id, source_data, 0, '', ''"
                   " FROM host_identifiers"
                   " ORDER BY %s %s;",
                   sort_field ? sort_field : "creation_time",
                   ascending ? "ASC" : "DESC");
}

/**
 * @brief Get the value from a host identifier iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The value of the host identifier, or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (host_identifier_iterator_value, GET_ITERATOR_COLUMN_COUNT);

/**
 * @brief Get the source type from a host identifier iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The source type of the host identifier, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (host_identifier_iterator_source_type,
            GET_ITERATOR_COLUMN_COUNT + 1);

/**
 * @brief Get the source from a host identifier iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The source of the host identifier, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (host_identifier_iterator_source_id, GET_ITERATOR_COLUMN_COUNT + 2);

/**
 * @brief Get the source data from a host identifier iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The source data of the host identifier, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (host_identifier_iterator_source_data,
            GET_ITERATOR_COLUMN_COUNT + 3);

/**
 * @brief Get the source orphan state from a host identifier iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The source orphan state of the host identifier, or 0 if iteration is
 *         complete. Freed by cleanup_iterator.
 */
int
host_identifier_iterator_source_orphan (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 4);
}

/**
 * @brief Get the OS UUID from a host identifier iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The OS UUID of the host identifier, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (host_identifier_iterator_os_id,
            GET_ITERATOR_COLUMN_COUNT + 5);

/**
 * @brief Get the OS title from a host identifier iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The OS title of the host identifier, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (host_identifier_iterator_os_title,
            GET_ITERATOR_COLUMN_COUNT + 6);

/**
 * @brief Extra WHERE clause for host assets.
 *
 * @param[in]  filter  Filter term.
 *
 * @return WHERE clause.
 */
gchar*
asset_host_extra_where (const char *filter)
{
  gchar *ret, *os_id;

  os_id = filter_term_value (filter, "os_id");

  if (os_id)
    {
      gchar *quoted_os_id = os_id ? sql_quote (os_id) : NULL;
      ret = g_strdup_printf (" AND EXISTS"
                             "  (SELECT * FROM host_oss"
                             "   WHERE os = (SELECT id FROM oss"
                             "                WHERE uuid = '%s')"
                             "     AND host = hosts.id)",
                             quoted_os_id);
      g_free (quoted_os_id);
    }
  else
    ret = g_strdup ("");

  g_free (os_id);

  return ret;
}

/**
 * @brief Initialise a host iterator.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  get         GET data.
 *
 * @return 0 success, 1 failed to find host, 2 failed to find filter,
 *         -1 error.
 */
int
init_asset_host_iterator (iterator_t *iterator, const get_data_t *get)
{
  static const char *filter_columns[] = HOST_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = HOST_ITERATOR_COLUMNS;
  static column_t where_columns[] = HOST_ITERATOR_WHERE_COLUMNS;

  int ret;
  gchar *filter, *extra_where;

  // Get filter
  if (get->filt_id && strcmp (get->filt_id, FILT_ID_NONE))
    {
      if (get->filter_replacement)
        /* Replace the filter term with one given by the caller.  This is
         * used by GET_REPORTS to use the default filter with any task (when
         * given the special value of -3 in filt_id). */
        filter = g_strdup (get->filter_replacement);
      else
        filter = filter_term (get->filt_id);
      if (filter == NULL)
        {
          return 1;
        }
    }
  else
    filter = NULL;

  extra_where = asset_host_extra_where (filter ? filter : get->filter);

  ret = init_get_iterator2 (iterator,
                            "host",
                            get,
                            /* Columns. */
                            columns,
                            /* Columns for trashcan. */
                            NULL,
                            /* WHERE Columns. */
                            where_columns,
                            /* WHERE Columns for trashcan. */
                            NULL,
                            filter_columns,
                            0,
                            NULL,
                            extra_where,
                            NULL,
                            TRUE,
                            FALSE,
                            NULL);

  g_free (filter);
  g_free (extra_where);
  return ret;
}

/**
 * @brief Get the max severity from an asset host iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The maximum severity of the host, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (asset_host_iterator_severity, GET_ITERATOR_COLUMN_COUNT + 2);

/**
 * @brief Generate the extra_tables string for an OS iterator.
 *
 * @return Newly allocated string.
 */
gchar *
asset_os_iterator_opts_table ()
{
  assert (current_credentials.uuid);

  return g_strdup_printf (", (SELECT"
                          "   (SELECT id FROM users"
                          "    WHERE users.uuid = '%s')"
                          "   AS user_id,"
                          "   'host' AS type)"
                          "  AS opts",
                          current_credentials.uuid);
}

/**
 * @brief Initialise an OS iterator.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  get         GET data.
 *
 * @return 0 success, 1 failed to find os, 2 failed to find filter,
 *         -1 error.
 */
int
init_asset_os_iterator (iterator_t *iterator, const get_data_t *get)
{
  int ret;
  static const char *filter_columns[] = OS_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = OS_ITERATOR_COLUMNS;
  static column_t where_columns[] = OS_ITERATOR_WHERE_COLUMNS;
  gchar *extra_tables;

  extra_tables = asset_os_iterator_opts_table ();

  ret = init_get_iterator2_with (iterator,
                                 "os",
                                 get,
                                 /* Columns. */
                                 columns,
                                 /* Columns for trashcan. */
                                 NULL,
                                 /* WHERE Columns. */
                                 where_columns,
                                 /* WHERE Columns for trashcan. */
                                 NULL,
                                 filter_columns,
                                 0,
                                 extra_tables,
                                 NULL,
                                 NULL,
                                 TRUE,
                                 FALSE,
                                 NULL,
                                 NULL,
                                 0,
                                 0);

  g_free (extra_tables);

  return ret;
}

/**
 * @brief Get the title from an OS iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The title of the OS, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (asset_os_iterator_title, GET_ITERATOR_COLUMN_COUNT + 2);

/**
 * @brief Get the number of installs from an asset OS iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Number of hosts that have the OS.
 */
int
asset_os_iterator_installs (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 3);
}

/**
 * @brief Get the latest severity from an OS iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The severity of the OS, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (asset_os_iterator_latest_severity, GET_ITERATOR_COLUMN_COUNT + 4);

/**
 * @brief Get the highest severity from an OS iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The severity of the OS, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (asset_os_iterator_highest_severity, GET_ITERATOR_COLUMN_COUNT + 5);

/**
 * @brief Get the average severity from an OS iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The severity of the OS, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (asset_os_iterator_average_severity, GET_ITERATOR_COLUMN_COUNT + 6);

/**
 * @brief Get the number of all installs from an asset OS iterator.
 *
 * This includes hosts where the OS is not the best match.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Number of any hosts that have the OS not only as the best match.
 */
int
asset_os_iterator_all_installs (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 7);
}

/**
 * @brief Initialise an asset host detail iterator.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  host        Host.
 */
void
init_host_detail_iterator (iterator_t* iterator, resource_t host)
{
  assert (host);
  init_iterator (iterator,
                 "SELECT sub.id, name, value, source_type, source_id"
                 " FROM (SELECT max (id) AS id FROM host_details"
                 "       WHERE host = %llu"
                 "       GROUP BY name)"
                 "      AS sub,"
                 "      host_details"
                 " WHERE sub.id = host_details.id"
                 " ORDER BY name ASC;",
                 host);
}

/**
 * @brief Get the name from an asset host detail iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The name of the host detail, or NULL if iteration is
 *         complete.  Freed by cleanup_iterator.
 */
DEF_ACCESS (host_detail_iterator_name, 1);

/**
 * @brief Get the name from an asset host detail iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The name of the host detail, or NULL if iteration is
 *         complete.  Freed by cleanup_iterator.
 */
DEF_ACCESS (host_detail_iterator_value, 2);

/**
 * @brief Get the source type from an asset host detail iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The source type of the host detail, or NULL if iteration is
 *         complete.  Freed by cleanup_iterator.
 */
DEF_ACCESS (host_detail_iterator_source_type, 3);

/**
 * @brief Get the source ID from an asset host detail iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The source ID of the host detail, or NULL if iteration is
 *         complete.  Freed by cleanup_iterator.
 */
DEF_ACCESS (host_detail_iterator_source_id, 4);

/**
 * @brief Initialise an OS host iterator.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  os          OS.
 */
void
init_os_host_iterator (iterator_t* iterator, resource_t os)
{
  assert (os);
  init_iterator (iterator,
                 "SELECT id, uuid, name, comment, creation_time,"
                 "       modification_time, creation_time,"
                 "       modification_time, owner, owner,"
                 "       (SELECT round (CAST (severity AS numeric), 1)"
                 "        FROM host_max_severities"
                 "        WHERE host = hosts.id"
                 "        ORDER by creation_time DESC"
                 "        LIMIT 1)"
                 " FROM hosts"
                 " WHERE id IN (SELECT DISTINCT host FROM host_oss"
                 "              WHERE os = %llu)"
                 " ORDER BY modification_time DESC;",
                 os);
}

/**
 * @brief Get the severity from an OS host detail iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The severity of the OS host, or NULL if iteration is
 *         complete.  Freed by cleanup_iterator.
 */
DEF_ACCESS (os_host_iterator_severity, GET_ITERATOR_COLUMN_COUNT);

/**
 * @brief Initialise a host iterator for GET_RESOURCE_NAMES.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  get         GET data.
 *
 * @return 0 success, 1 failed to find host, 2 failed to find filter,
 *         -1 error.
 */
int
init_resource_names_host_iterator (iterator_t *iterator, get_data_t *get)
{
  static const char *filter_columns[] = { GET_ITERATOR_FILTER_COLUMNS };
  static column_t columns[] = { GET_ITERATOR_COLUMNS (hosts) };
  int ret;

  ret = init_get_iterator2 (iterator,
                            "host",
                            get,
                            /* Columns. */
                            columns,
                            /* Columns for trashcan. */
                            NULL,
                            /* WHERE Columns. */
                            NULL,
                            /* WHERE Columns for trashcan. */
                            NULL,
                            filter_columns,
                            0,
                            NULL,
                            NULL,
                            NULL,
                            TRUE,
                            FALSE,
                            NULL);

  return ret;
}

/**
 * @brief Initialise an OS iterator for GET_RESOURCE_NAMES.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  get         GET data.
 *
 * @return 0 success, 1 failed to find os, 2 failed to find filter,
 *         -1 error.
 */
int
init_resource_names_os_iterator (iterator_t *iterator, get_data_t *get)
{
  static const char *filter_columns[] = { GET_ITERATOR_FILTER_COLUMNS };
  static column_t columns[] = { GET_ITERATOR_COLUMNS (oss) };
  int ret;

  ret = init_get_iterator2_with (iterator,
                                 "os",
                                 get,
                                 /* Columns. */
                                 columns,
                                 /* Columns for trashcan. */
                                 NULL,
                                 /* WHERE Columns. */
                                 NULL,
                                 /* WHERE Columns for trashcan. */
                                 NULL,
                                 filter_columns,
                                 0,
                                 NULL,
                                 NULL,
                                 NULL,
                                 TRUE,
                                 FALSE,
                                 NULL,
                                 NULL,
                                 0,
                                 0);

  return ret;
}

/**
 * @brief Get the writable status from an asset iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return 1 if writable, else 0.
 */
int
asset_iterator_writable (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return iterator_int64 (iterator, GET_ITERATOR_COLUMN_COUNT);
}

/**
 * @brief Get the "in use" status from an asset iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return 1 if in use, else 0.
 */
int
asset_iterator_in_use (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return iterator_int64 (iterator, GET_ITERATOR_COLUMN_COUNT + 1);
}

/**
 * @brief Modify an asset.
 *
 * @param[in]   asset_id        UUID of asset.
 * @param[in]   comment         Comment on asset.
 *
 * @return 0 success, 1 failed to find asset, 3 asset_id required,
 *         99 permission denied, -1 internal error.
 */
int
modify_asset (const char *asset_id, const char *comment)
{
  gchar *quoted_asset_id, *quoted_comment;
  resource_t asset;

  if (asset_id == NULL)
    return 3;

  sql_begin_immediate ();

  if (acl_user_may ("modify_asset") == 0)
    {
      sql_rollback ();
      return 99;
    }

  /* Host. */

  quoted_asset_id = sql_quote (asset_id);
  switch (sql_int64 (&asset,
                     "SELECT id FROM hosts WHERE uuid = '%s';",
                     quoted_asset_id))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        asset = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        g_free (quoted_asset_id);
        sql_rollback ();
        return -1;
        break;
    }

  g_free (quoted_asset_id);

  if (asset == 0)
    {
      sql_rollback ();
      return 1;
    }

  quoted_comment = sql_quote (comment ?: "");

  sql ("UPDATE hosts SET"
       " comment = '%s',"
       " modification_time = m_now ()"
       " WHERE id = %llu;",
       quoted_comment, asset);

  g_free (quoted_comment);

  sql_commit ();

  return 0;
}

/**
 * @brief Find a host for a specific permission, given a UUID.
 *
 * @param[in]   uuid        UUID of host.
 * @param[out]  host      Host return, 0 if successfully failed to find host.
 * @param[in]   permission  Permission.
 *
 * @return FALSE on success (including if failed to find host), TRUE on error.
 */
static gboolean
find_host_with_permission (const char* uuid, host_t* host,
                           const char *permission)
{
  return find_resource_with_permission ("host", uuid, host, permission, 0);
}

/**
 * @brief Delete all asset that came from a report.
 *
 * Assume caller started a transaction.
 *
 * @param[in]  report_id  UUID of report.
 *
 * @return 0 success, 2 failed to find report, 4 UUID
 *         required, 99 permission denied, -1 error.
 */
static int
delete_report_assets (const char *report_id)
{
  resource_t report;
  gchar *quoted_report_id;

  report = 0;
  if (find_report_with_permission (report_id, &report, "delete_report"))
    {
      sql_rollback ();
      return -1;
    }

  if (report == 0)
    {
      sql_rollback ();
      return 1;
    }

  quoted_report_id = sql_quote (report_id);

  /* Delete the hosts and OSs identified by this report if they were only
   * identified by this report. */

  sql ("CREATE TEMPORARY TABLE delete_report_assets_hosts (host INTEGER);");

  /* Collect hosts that were only identified by the given source. */
  sql ("INSERT into delete_report_assets_hosts"
       " (host)"
       " SELECT id FROM hosts"
       " WHERE (EXISTS (SELECT * FROM host_identifiers"
       "                WHERE host = hosts.id"
       "                AND source_id = '%s')"
       "        OR EXISTS (SELECT * FROM host_oss"
       "                   WHERE host = hosts.id"
       "                   AND source_id = '%s'))"
       " AND NOT EXISTS (SELECT * FROM host_identifiers"
       "                 WHERE host = hosts.id"
       "                 AND source_id != '%s')"
       " AND NOT EXISTS (SELECT * FROM host_oss"
       "                 WHERE host = hosts.id"
       "                 AND source_id != '%s');",
      quoted_report_id,
      quoted_report_id,
      quoted_report_id,
      quoted_report_id);

  sql ("DELETE FROM host_identifiers WHERE source_id = '%s';",
       quoted_report_id);
  sql ("DELETE FROM host_oss WHERE source_id = '%s';",
       quoted_report_id);
  sql ("DELETE FROM host_max_severities WHERE source_id = '%s';",
       quoted_report_id);
  sql ("DELETE FROM host_details WHERE source_id = '%s';",
       quoted_report_id);

  g_free (quoted_report_id);

  /* The host may have details from sources that did not identify the host. */
  sql ("DELETE FROM host_details"
       " WHERE host in (SELECT host FROM delete_report_assets_hosts);");

  /* The host may have severities from sources that did not identify the
   * host. */
  sql ("DELETE FROM host_max_severities"
       " WHERE host in (SELECT host FROM delete_report_assets_hosts);");

  sql ("DELETE FROM hosts"
       " WHERE id in (SELECT host FROM delete_report_assets_hosts);");

  sql ("DROP TABLE delete_report_assets_hosts;");

  sql_commit ();
  return 0;
}

/**
 * @brief Delete an asset.
 *
 * @param[in]  asset_id   UUID of asset.
 * @param[in]  report_id  UUID of report from which to delete assets.
 *                        Overridden by asset_id.
 * @param[in]  dummy      Dummy arg to match other delete functions.
 *
 * @return 0 success, 1 asset is in use, 2 failed to find asset, 4 UUID
 *         required, 99 permission denied, -1 error.
 */
int
delete_asset (const char *asset_id, const char *report_id, int dummy)
{
  resource_t asset, parent;
  gchar *quoted_asset_id, *parent_id;

  asset = parent = 0;

  sql_begin_immediate ();

  if (acl_user_may ("delete_asset") == 0)
    {
      sql_rollback ();
      return 99;
    }

  if (asset_id == NULL)
    {
      if (report_id == NULL)
        {
          sql_rollback ();
          return 3;
        }
      return delete_report_assets (report_id);
    }

  /* Host identifier. */

  quoted_asset_id = sql_quote (asset_id);
  switch (sql_int64 (&asset,
                     "SELECT id FROM host_identifiers WHERE uuid = '%s';",
                     quoted_asset_id))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        asset = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        g_free (quoted_asset_id);
        sql_rollback ();
        return -1;
        break;
    }

  g_free (quoted_asset_id);

  if (asset)
    {
      parent_id = sql_string ("SELECT uuid FROM hosts"
                              " WHERE id = (SELECT host FROM host_identifiers"
                              "             WHERE id = %llu);",
                              asset);
      parent = 0;
      if (find_host_with_permission (parent_id, &parent, "delete_asset"))
        {
          sql_rollback ();
          return -1;
        }

      if (parent == 0)
        {
          sql_rollback ();
          return 99;
        }

      sql ("DELETE FROM host_identifiers WHERE id = %llu;", asset);
      sql_commit ();

      return 0;
    }

  /* Host OS. */

  quoted_asset_id = sql_quote (asset_id);
  switch (sql_int64 (&asset,
                     "SELECT id FROM host_oss WHERE uuid = '%s';",
                     quoted_asset_id))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        asset = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        g_free (quoted_asset_id);
        sql_rollback ();
        return -1;
        break;
    }

  g_free (quoted_asset_id);

  if (asset)
    {
      parent_id = sql_string ("SELECT uuid FROM hosts"
                              " WHERE id = (SELECT host FROM host_oss"
                              "             WHERE id = %llu);",
                              asset);
      parent = 0;
      if (find_host_with_permission (parent_id, &parent, "delete_asset"))
        {
          sql_rollback ();
          return -1;
        }

      if (parent == 0)
        {
          sql_rollback ();
          return 99;
        }

      sql ("DELETE FROM host_oss WHERE id = %llu;", asset);
      sql_commit ();

      return 0;
    }

  /* OS. */

  quoted_asset_id = sql_quote (asset_id);
  switch (sql_int64 (&asset,
                     "SELECT id FROM oss WHERE uuid = '%s';",
                     quoted_asset_id))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        asset = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        g_free (quoted_asset_id);
        sql_rollback ();
        return -1;
        break;
    }

  g_free (quoted_asset_id);

  if (asset)
    {
      if (sql_int ("SELECT count (*) FROM host_oss"
                   " WHERE os = %llu;",
                   asset))
        {
          sql_rollback ();
          return 1;
        }

      sql ("DELETE FROM oss WHERE id = %llu;", asset);
      permissions_set_orphans ("os", asset, LOCATION_TABLE);
      tags_remove_resource ("os", asset, LOCATION_TABLE);
      sql_commit ();

      return 0;
    }

  /* Host. */

  quoted_asset_id = sql_quote (asset_id);
  switch (sql_int64 (&asset,
                     "SELECT id FROM hosts WHERE uuid = '%s';",
                     quoted_asset_id))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        asset = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        g_free (quoted_asset_id);
        sql_rollback ();
        return -1;
        break;
    }

  g_free (quoted_asset_id);

  if (asset)
    {
      sql ("DELETE FROM host_identifiers WHERE host = %llu;", asset);
      sql ("DELETE FROM host_oss WHERE host = %llu;", asset);
      sql ("DELETE FROM host_max_severities WHERE host = %llu;", asset);
      sql ("DELETE FROM host_details WHERE host = %llu;", asset);
      sql ("DELETE FROM hosts WHERE id = %llu;", asset);
      permissions_set_orphans ("host", asset, LOCATION_TABLE);
      tags_remove_resource ("host", asset, LOCATION_TABLE);
      sql_commit ();

      return 0;
    }

  sql_rollback ();
  return 2;
}

/**
 * @brief Tests if a report host is marked as dead.
 *
 * @param[in]  report_host  Report host.
 *
 * @return 1 if the host is marked as dead, 0 otherwise.
 */
int
report_host_dead (report_host_t report_host)
{
  return sql_int ("SELECT count(*) != 0 FROM report_host_details"
                  " WHERE report_host = %llu"
                  "   AND name = 'Host dead'"
                  "   AND value != '0';",
                  report_host);
}
