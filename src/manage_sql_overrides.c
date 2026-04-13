/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_overrides.h"
#include "manage_acl.h"
#include "manage_sql_permissions.h"
#include "manage_sql_resources.h"
#include "manage_sql_settings.h"
#include "manage_sql_tags.h"

#include <ctype.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Create an override.
 *
 * @param[in]  active      NULL or -1 on, 0 off, n on for n days.
 * @param[in]  nvt         OID of overridden NVT.
 * @param[in]  text        Override text.
 * @param[in]  hosts       Hosts to apply override to, NULL for any host.
 * @param[in]  port        Port to apply override to, NULL for any port.
 * @param[in]  threat      Threat to apply override to, "" or NULL for any threat.
 * @param[in]  new_threat  Threat to override result to.
 * @param[in]  severity    Severity to apply override to, "" or NULL for any.
 * @param[in]  new_severity Severity score to override "Alarm" type results to.
 * @param[in]  task        Task to apply override to, 0 for any task.
 * @param[in]  result      Result to apply override to, 0 for any result.
 * @param[out] override    Created override.
 *
 * @return 0 success, 1 failed to find NVT, 2 invalid port, 3 invalid severity,
 *         99 permission denied, -1 error.
 */
int
create_override (const char* active, const char* nvt, const char* text,
                 const char* hosts, const char* port, const char* threat,
                 const char* new_threat, const char* severity,
                 const char* new_severity, task_t task, result_t result,
                 override_t* override)
{
  gchar *quoted_text, *quoted_hosts, *quoted_port, *quoted_severity;
  double severity_dbl, new_severity_dbl;
  GHashTable *reports;
  GHashTableIter reports_iter;
  report_t *reports_ptr;
  gchar *override_id, *users_where;
  int auto_cache_rebuild;
  override_t new_override;

  if (acl_user_may ("create_override") == 0)
    return 99;

  if (nvt == NULL)
    return -1;

  if (text == NULL)
    return -1;

  if (!nvt_exists (nvt))
    return 1;

  if (port && validate_results_port (port))
    return 2;

  if (threat
      && strcmp (threat, "Critical")
      && strcmp (threat, "High")
      && strcmp (threat, "Medium")
      && strcmp (threat, "Low")
      && strcmp (threat, "Log")
      && strcmp (threat, "Alarm")
      && strcmp (threat, ""))
    return -1;

  if (new_threat
      && strcmp (new_threat, "Critical")
      && strcmp (new_threat, "High")
      && strcmp (new_threat, "Medium")
      && strcmp (new_threat, "Low")
      && strcmp (new_threat, "Log")
      && strcmp (new_threat, "False Positive")
      && strcmp (new_threat, "Alarm")
      && strcmp (new_threat, ""))
    return -1;

  severity_dbl = 0.0;
  if (severity != NULL && strcmp (severity, ""))
    {
      if (sscanf (severity, "%lf", &severity_dbl) != 1
          || ((severity_dbl < 0.0 || severity_dbl > 10.0)
              && severity_dbl != SEVERITY_LOG))
        return 3;
      quoted_severity = g_strdup_printf ("'%1.1f'", severity_dbl);
    }
  else if (threat != NULL && strcmp (threat, ""))
    {
      if (strcmp (threat, "Alarm") == 0)
        severity_dbl = 0.1;
      else if (strcmp (threat, "Critical") == 0)
        severity_dbl = 0.1;
      else if (strcmp (threat, "High") == 0)
        severity_dbl = 0.1;
      else if (strcmp (threat, "Medium") == 0)
        severity_dbl = 0.1;
      else if (strcmp (threat, "Low") == 0)
        severity_dbl = 0.1;
      else if (strcmp (threat, "Log") == 0)
        severity_dbl = SEVERITY_LOG;
      else
        return -1;

      quoted_severity = g_strdup_printf ("'%1.1f'", severity_dbl);
    }
  else
    quoted_severity = g_strdup ("NULL");

  new_severity_dbl = 0.0;
  if (new_severity != NULL && strcmp (new_severity, ""))
    {
      if (sscanf (new_severity, "%lf", &new_severity_dbl) != 1
          || ((new_severity_dbl < 0.0 || new_severity_dbl > 10.0)
              && new_severity_dbl != SEVERITY_LOG
              && new_severity_dbl != SEVERITY_FP))
        {
          g_free (quoted_severity);
          return 3;
        }
    }
  else if (new_threat != NULL && strcmp (new_threat, ""))
    {
      if (strcmp (new_threat, "Alarm") == 0)
        new_severity_dbl = 10.0;
      else if (strcmp (new_threat, "Critical") == 0)
        new_severity_dbl = 10.0;
      else if (strcmp (new_threat, "High") == 0)
        new_severity_dbl = 8.9;
      else if (strcmp (new_threat, "Medium") == 0)
        new_severity_dbl = 5.0;
      else if (strcmp (new_threat, "Low") == 0)
        new_severity_dbl = 2.0;
      else if (strcmp (new_threat, "Log") == 0)
        new_severity_dbl = SEVERITY_LOG;
      else
        return -1;
    }
  else
    {
      g_free (quoted_severity);
      return -1;
    }

  quoted_text = sql_insert (text);
  quoted_hosts = sql_insert (hosts);
  quoted_port = sql_insert (port);

  result_nvt_notice (nvt);
  sql ("INSERT INTO overrides"
       " (uuid, owner, nvt, creation_time, modification_time, text, hosts,"
       "  port, severity, new_severity, task, result, end_time,"
       "  result_nvt)"
       " VALUES"
       " (make_uuid (), (SELECT id FROM users WHERE users.uuid = '%s'),"
       "  '%s', %i, %i, %s, %s, %s, %s, %1.1f, %llu, %llu, %i,"
       "  (SELECT id FROM result_nvts WHERE nvt = '%s'));",
       current_credentials.uuid,
       nvt,
       time (NULL),
       time (NULL),
       quoted_text,
       quoted_hosts,
       quoted_port,
       quoted_severity,
       new_severity_dbl,
       task,
       result,
       (active == NULL || (strcmp (active, "-1") == 0))
         ? 0
         : (strcmp (active, "0")
             ? (time (NULL) + (atoi (active) * 60 * 60 * 24))
             : 1),
       nvt);

  g_free (quoted_text);
  g_free (quoted_hosts);
  g_free (quoted_port);
  g_free (quoted_severity);

  if (override)
    *override = sql_last_insert_id ();
  new_override = sql_last_insert_id ();

  override_uuid (new_override, &override_id);
  users_where = acl_users_with_access_where ("override", override_id, NULL,
                                             "id");

  reports = reports_for_override (new_override);
  reports_ptr = NULL;
  g_hash_table_iter_init (&reports_iter, reports);
  auto_cache_rebuild = setting_auto_cache_rebuild_int ();
  while (g_hash_table_iter_next (&reports_iter,
                                 ((gpointer*)&reports_ptr), NULL))
    {
      if (auto_cache_rebuild)
        report_cache_counts (*reports_ptr, 0, 1, users_where);
      else
        report_clear_count_cache (*reports_ptr, 0, 1, users_where);
    }
  g_hash_table_destroy (reports);
  g_free (override_id);
  g_free (users_where);

  return 0;
}

/**
 * @brief Create a override from an existing override.
 *
 * @param[in]  override_id   UUID of existing override.
 * @param[out] new_override  New override.
 *
 * @return 0 success, 1 override exists already, 2 failed to find existing
 *         override, -1 error.
 */
int
copy_override (const char *override_id, override_t* new_override)
{
  return copy_resource ("override", NULL, NULL, override_id,
                        "nvt, text, hosts, port, severity, new_severity, task,"
                        " result, end_time, result_nvt",
                        1, new_override, NULL);
}

/**
 * @brief Delete a override.
 *
 * @param[in]  override_id  UUID of override.
 * @param[in]  ultimate     Whether to remove entirely, or to trashcan.
 *
 * @return 0 success, 2 failed to find override, 99 permission denied, -1 error.
 */
int
delete_override (const char *override_id, int ultimate)
{
  override_t override;
  GHashTable *reports;
  GHashTableIter reports_iter;
  report_t *reports_ptr;
  gchar *users_where;
  int auto_cache_rebuild;

  sql_begin_immediate ();

  if (acl_user_may ("delete_override") == 0)
    {
      sql_rollback ();
      return 99;
    }

  override = 0;

  if (find_override_with_permission (override_id, &override, "delete_override"))
    {
      sql_rollback ();
      return -1;
    }

  if (override == 0)
    {
      if (find_trash ("override", override_id, &override))
        {
          sql_rollback ();
          return -1;
        }
      if (override == 0)
        {
          sql_rollback ();
          return 2;
        }
      if (ultimate == 0)
        {
          /* It's already in the trashcan. */
          sql_commit ();
          return 0;
        }

      permissions_set_orphans ("override", override, LOCATION_TRASH);
      tags_remove_resource ("override", override, LOCATION_TRASH);

      sql ("DELETE FROM overrides_trash WHERE id = %llu;", override);
      sql_commit ();
      return 0;
    }

  reports = reports_for_override (override);

  users_where = acl_users_with_access_where ("override", override_id, NULL,
                                             "id");

  if (ultimate == 0)
    {
      sql ("INSERT INTO overrides_trash"
           " (uuid, owner, nvt, creation_time, modification_time, text, hosts,"
           "  port, severity, new_severity, task, result, end_time, result_nvt)"
           " SELECT uuid, owner, nvt, creation_time, modification_time, text,"
           "        hosts, port, severity, new_severity,task,"
           "        result, end_time, result_nvt"
           " FROM overrides WHERE id = %llu;",
           override);

      permissions_set_locations ("override", override,
                                 sql_last_insert_id (),
                                 LOCATION_TRASH);
      tags_set_locations ("override", override,
                          sql_last_insert_id (),
                          LOCATION_TRASH);
    }
  else
    {
      permissions_set_orphans ("override", override, LOCATION_TABLE);
      tags_remove_resource ("override", override, LOCATION_TABLE);
    }

  sql ("DELETE FROM overrides WHERE id = %llu;", override);

  g_hash_table_iter_init (&reports_iter, reports);
  reports_ptr = NULL;
  auto_cache_rebuild = setting_auto_cache_rebuild_int ();
  while (g_hash_table_iter_next (&reports_iter,
                                 ((gpointer*)&reports_ptr), NULL))
    {
      if (auto_cache_rebuild)
        report_cache_counts (*reports_ptr, 0, 1, users_where);
      else
        report_clear_count_cache (*reports_ptr, 0, 1, users_where);
    }
  g_hash_table_destroy (reports);
  g_free (users_where);

  sql_commit ();
  return 0;
}

/**
 * @brief Modify an override.
 *
 * @param[in]  override_id  Override.
 * @param[in]  active       NULL or -2 leave as is, -1 on, 0 off, n on for n
 *                          days.
 * @param[in]  nvt         OID of noted NVT.
 * @param[in]  text        Override text.
 * @param[in]  hosts       Hosts to apply override to, NULL for any host.
 * @param[in]  port        Port to apply override to, NULL for any port.
 * @param[in]  threat      Threat to apply override to, "" or NULL for any threat.
 * @param[in]  new_threat  Threat to override result to.
 * @param[in]  severity    Severity to apply override to, "" or NULL for any threat.
 * @param[in]  new_severity Severity score to override "Alarm" type results to.
 * @param[in]  task_id     Task to apply override to, 0 for any task.
 * @param[in]  result_id   Result to apply override to, 0 for any result.
 *
 * @return 0 success, -1 error, 1 syntax error in active, 2 invalid port,
 *         3 invalid severity score, 4 failed to find NVT, 5 failed to find
 *         override, 6 failed to find task, 7 failed to find result,
 *         8 invalid threat, 9 invalid new_threat, 10 invalid new_severity,
 *         11 missing new_severity.
 */
int
modify_override (const gchar *override_id, const char *active, const char *nvt,
                 const char *text, const char *hosts, const char *port,
                 const char *threat, const char *new_threat,
                 const char *severity, const char *new_severity,
                 const gchar *task_id, const gchar *result_id)
{
  gchar *quoted_text, *quoted_hosts, *quoted_port, *quoted_severity;
  double severity_dbl, new_severity_dbl;
  gchar *quoted_nvt;
  GHashTable *reports;
  GString *cache_invalidated_sql;
  int cache_invalidated;
  override_t override;
  task_t task;
  result_t result;

  reports = NULL;
  cache_invalidated = 0;

  override = 0;
  if (find_override_with_permission (override_id, &override, "modify_override"))
    return -1;
  if (override == 0)
    return 5;

  task = 0;
  if (task_id)
    {
      if (find_task_with_permission (task_id, &task, NULL))
        return -1;
      if (task == 0)
        {
          if (find_trash_task_with_permission (task_id, &task, NULL))
            return -1;
          if (task == 0)
            return 6;
        }
    }

  result = 0;
  if (result_id)
    {
      if (find_result_with_permission (result_id, &result, NULL))
        return -1;
      if (result == 0)
        return 7;
    }

  if (text == NULL)
    return -1;

  if (port && validate_results_port (port))
    return 2;

  if (nvt && !nvt_exists (nvt))
    return 4;

  severity_dbl = 0.0;
  if (severity != NULL && strcmp (severity, ""))
    {
      if (sscanf (severity, "%lf", &severity_dbl) != 1
          || ((severity_dbl < 0.0 || severity_dbl > 10.0)
              && severity_dbl != SEVERITY_LOG))
        return 3;
      quoted_severity = g_strdup_printf ("'%1.1f'", severity_dbl);
    }
  else if (threat != NULL && strcmp (threat, ""))
    {
      if (strcmp (threat, "Alarm") == 0)
        severity_dbl = 0.1;
      else if (strcmp (threat, "Critical") == 0)
        severity_dbl = 0.1;
      else if (strcmp (threat, "High") == 0)
        severity_dbl = 0.1;
      else if (strcmp (threat, "Medium") == 0)
        severity_dbl = 0.1;
      else if (strcmp (threat, "Low") == 0)
        severity_dbl = 0.1;
      else if (strcmp (threat, "Log") == 0)
        severity_dbl = SEVERITY_LOG;
      else
        return 8;

      quoted_severity = g_strdup_printf ("'%1.1f'", severity_dbl);
    }
  else
    quoted_severity = g_strdup ("NULL");

  new_severity_dbl = 0.0;
  if (new_severity != NULL && strcmp (new_severity, ""))
    {
      if (sscanf (new_severity, "%lf", &new_severity_dbl) != 1
          || ((new_severity_dbl < 0.0 || new_severity_dbl > 10.0)
              && new_severity_dbl != SEVERITY_LOG
              && new_severity_dbl != SEVERITY_FP))
        {
          g_free (quoted_severity);
          return 10;
        }
    }
  else if (new_threat != NULL && strcmp (new_threat, ""))
    {
      if (strcmp (new_threat, "Alarm") == 0)
        new_severity_dbl = 10.0;
      else if (strcmp (new_threat, "Critical") == 0)
        new_severity_dbl = 10.0;
      else if (strcmp (new_threat, "High") == 0)
        new_severity_dbl = 8.9;
      else if (strcmp (new_threat, "Medium") == 0)
        new_severity_dbl = 5.0;
      else if (strcmp (new_threat, "Low") == 0)
        new_severity_dbl = 2.0;
      else if (strcmp (new_threat, "Log") == 0)
        new_severity_dbl = SEVERITY_LOG;
      else
        {
          g_free (quoted_severity);
          return 9;
        }
    }
  else
    {
      g_free (quoted_severity);
      return 11;
    }

  quoted_text = sql_insert (text);
  quoted_hosts = sql_insert (hosts);
  quoted_port = sql_insert (port);
  quoted_nvt = nvt ? sql_quote (nvt) : NULL;

  // Tests if a cache rebuild is necessary.
  //  The "active" status is checked separately
  cache_invalidated_sql = g_string_new ("");

  g_string_append_printf (cache_invalidated_sql,
                          "SELECT (cast (new_severity AS numeric) != %1.1f)",
                          new_severity_dbl);

  g_string_append_printf (cache_invalidated_sql,
                          " OR (task != %llu)",
                          task);

  g_string_append_printf (cache_invalidated_sql,
                          " OR (result != %llu)",
                          result);

  if (strcmp (quoted_severity, "NULL") == 0)
    g_string_append_printf (cache_invalidated_sql,
                            " OR (severity IS NOT NULL)");
  else
    g_string_append_printf (cache_invalidated_sql,
                            " OR (cast (severity AS numeric) != %1.1f)",
                            severity_dbl);

  if (strcmp (quoted_hosts, "NULL") == 0)
    g_string_append_printf (cache_invalidated_sql,
                            " OR (hosts IS NOT NULL)");
  else
    g_string_append_printf (cache_invalidated_sql,
                            " OR (hosts != %s)",
                            quoted_hosts);

  if (strcmp (quoted_port, "NULL") == 0)
    g_string_append_printf (cache_invalidated_sql,
                            " OR (hosts IS NOT NULL)");
  else
    g_string_append_printf (cache_invalidated_sql,
                            " OR (port != %s)",
                            quoted_port);

  g_string_append_printf (cache_invalidated_sql,
                          " FROM overrides WHERE id = %llu",
                          override);

  if (sql_int ("%s", cache_invalidated_sql->str))
    {
      cache_invalidated = 1;
    }

  g_string_free (cache_invalidated_sql, TRUE);

  // Check active status for changes, get old reports for rebuild if necessary
  //  and update override.
  result_nvt_notice (quoted_nvt);
  if ((active == NULL) || (strcmp (active, "-2") == 0))
    {
      if (cache_invalidated)
        reports = reports_for_override (override);

      sql ("UPDATE overrides SET"
           " modification_time = %i,"
           " text = %s,"
           " hosts = %s,"
           " port = %s,"
           " severity = %s,"
           " %s%s%s"
           " %s%s%s"
           " new_severity = %f,"
           " task = %llu,"
           " result = %llu"
           " WHERE id = %llu;",
           time (NULL),
           quoted_text,
           quoted_hosts,
           quoted_port,
           quoted_severity,
           nvt ? "nvt = '" : "",
           nvt ? quoted_nvt : "",
           nvt ? "'," : "",
           nvt ? "result_nvt = (SELECT id FROM result_nvts WHERE nvt='" : "",
           nvt ? quoted_nvt : "",
           nvt ? "')," : "",
           new_severity_dbl,
           task,
           result,
           override);
    }
  else
    {
      const char *point;
      point = active;
      int new_end_time;

      if (strcmp (point, "-1"))
        {
          while (*point && isdigit (*point)) point++;
          if (*point)
            {
              return 1;
            }
        }

      new_end_time = (strcmp (active, "-1")
                        ? (strcmp (active, "0")
                            ? (time (NULL) + atoi (active) * 60 * 60 * 24)
                            : 1)
                        : 0);

      if (cache_invalidated == 0
          && sql_int ("SELECT end_time != %d FROM overrides"
                      " WHERE id = %llu",
                      new_end_time, override))
        cache_invalidated = 1;

      if (cache_invalidated)
        reports = reports_for_override (override);

      sql ("UPDATE overrides SET"
           " end_time = %i,"
           " modification_time = %i,"
           " text = %s,"
           " hosts = %s,"
           " port = %s,"
           " severity = %s,"
           " %s%s%s"
           " %s%s%s"
           " new_severity = %f,"
           " task = %llu,"
           " result = %llu"
           " WHERE id = %llu;",
           new_end_time,
           time (NULL),
           quoted_text,
           quoted_hosts,
           quoted_port,
           quoted_severity,
           nvt ? "nvt = '" : "",
           nvt ? quoted_nvt : "",
           nvt ? "'," : "",
           nvt ? "result_nvt = (SELECT id FROM result_nvts WHERE nvt='" : "",
           nvt ? quoted_nvt : "",
           nvt ? "')," : "",
           new_severity_dbl,
           task,
           result,
           override);
    }

  g_free (quoted_text);
  g_free (quoted_hosts);
  g_free (quoted_port);
  g_free (quoted_severity);
  g_free (quoted_nvt);

  if (cache_invalidated)
    {
      GHashTableIter reports_iter;
      report_t *reports_ptr;
      gchar *users_where;
      int auto_cache_rebuild;

      users_where = acl_users_with_access_where ("override", override_id, NULL,
                                                 "id");

      reports_add_for_override (reports, override);

      g_hash_table_iter_init (&reports_iter, reports);
      reports_ptr = NULL;
      auto_cache_rebuild = setting_auto_cache_rebuild_int ();
      while (g_hash_table_iter_next (&reports_iter,
                                    ((gpointer*)&reports_ptr), NULL))
        {
          if (auto_cache_rebuild)
            report_cache_counts (*reports_ptr, 0, 1, users_where);
          else
            report_clear_count_cache (*reports_ptr, 0, 1, users_where);
        }
      g_free (users_where);
    }

  if (reports)
    g_hash_table_destroy (reports);

  return 0;
}
