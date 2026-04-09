/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_notes.h"
#include "manage_acl.h"
#include "sql.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @file
 * @brief GVM management layer: Notes SQL
 *
 * The Notes SQL for the GVM management layer.
 */

/**
 * @brief Create a note.
 *
 * @param[in]  active      NULL or -1 on, 0 off, n on for n days.
 * @param[in]  nvt         OID of noted NVT.
 * @param[in]  text        Note text.
 * @param[in]  hosts       Hosts to apply note to, NULL for any host.
 * @param[in]  port        Port to apply note to, NULL for any port.
 * @param[in]  severity    Severity to apply note to, "" or NULL for any.
 * @param[in]  threat      Threat to apply note to, "" or NULL for any threat.
 *                         Only used if severity is "" or NULL.
 * @param[in]  task        Task to apply note to, 0 for any task.
 * @param[in]  result      Result to apply note to, 0 for any result.
 * @param[out] note        Created note.
 *
 * @return 0 success, 1 failed to find NVT, 2 invalid port, 99 permission
 *         denied, -1 error.
 */
int
create_note (const char* active, const char* nvt, const char* text,
             const char* hosts, const char* port, const char* severity,
             const char* threat, task_t task, result_t result, note_t *note)
{
  gchar *quoted_text, *quoted_hosts, *quoted_port, *quoted_severity;
  double severity_dbl;

  if (acl_user_may ("create_note") == 0)
    return 99;

  if (nvt == NULL)
    return -1;

  if (!nvt_exists (nvt))
    return 1;

  if (port && validate_results_port (port))
    return 2;

  if (text == NULL)
    return -1;

  if (threat
      && strcmp (threat, "Critical")
      && strcmp (threat, "High")
      && strcmp (threat, "Medium")
      && strcmp (threat, "Low")
      && strcmp (threat, "Log")
      && strcmp (threat, ""))
    return -1;

  quoted_text = sql_insert (text);
  quoted_hosts = sql_insert (hosts);
  quoted_port = sql_insert (port);

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

  sql ("INSERT INTO notes"
       " (uuid, owner, nvt, creation_time, modification_time, text, hosts,"
       "  port, severity, task, result, end_time)"
       " VALUES"
       " (make_uuid (), (SELECT id FROM users WHERE users.uuid = '%s'),"
       "  '%s', %i, %i, %s, %s, %s, %s, %llu, %llu, %i);",
       current_credentials.uuid,
       nvt,
       time (NULL),
       time (NULL),
       quoted_text,
       quoted_hosts,
       quoted_port,
       quoted_severity,
       task,
       result,
       (active == NULL || (strcmp (active, "-1") == 0))
         ? 0
         : (strcmp (active, "0")
             ? (time (NULL) + (atoi (active) * 60 * 60 * 24))
             : 1));

  g_free (quoted_text);
  g_free (quoted_hosts);
  g_free (quoted_port);
  g_free (quoted_severity);

  if (note)
    *note = sql_last_insert_id ();

  return 0;
}
