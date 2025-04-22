/* Copyright (C) 2020-2022 Greenbone AG
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
 * @file manage_alerts.c
 * @brief GVM management layer: Alerts.
 *
 * General functions for managing alerts.
 */

#include "manage_alerts.h"
#include "manage_sql.h"
#include "manage_acl.h"

#include <gvm/util/uuidutils.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"


/* Alert report data. */

/**
 * @brief Frees a alert_report_data_t struct, including contained data.
 *
 * @param[in]  data   The struct to free.
 */
void
alert_report_data_free (alert_report_data_t *data)
{
  if (data == NULL)
    return;

  alert_report_data_reset (data);
  g_free (data);
}

/**
 * @brief Frees content of an alert_report_data_t, but not the struct itself.
 *
 * @param[in]  data   The struct to free.
 */
void
alert_report_data_reset (alert_report_data_t *data)
{
  if (data == NULL)
    return;

  g_free (data->content_type);
  g_free (data->local_filename);
  g_free (data->remote_filename);
  g_free (data->report_format_name);

  memset (data, 0, sizeof (alert_report_data_t));
}


/* Alert conditions. */

/**
 * @brief Get the name of an alert condition.
 *
 * @param[in]  condition  Condition.
 *
 * @return The name of the condition (for example, "Always").
 */
const char*
alert_condition_name (alert_condition_t condition)
{
  switch (condition)
    {
      case ALERT_CONDITION_ALWAYS:
        return "Always";
      case ALERT_CONDITION_FILTER_COUNT_AT_LEAST:
        return "Filter count at least";
      case ALERT_CONDITION_FILTER_COUNT_CHANGED:
        return "Filter count changed";
      case ALERT_CONDITION_SEVERITY_AT_LEAST:
        return "Severity at least";
      case ALERT_CONDITION_SEVERITY_CHANGED:
        return "Severity changed";
      default:
        return "Internal Error";
    }
}

/**
 * @brief Get a description of an alert condition.
 *
 * @param[in]  condition  Condition.
 * @param[in]  alert  Alert.
 *
 * @return Freshly allocated description of condition.
 */
gchar*
alert_condition_description (alert_condition_t condition,
                             alert_t alert)
{
  switch (condition)
    {
      case ALERT_CONDITION_ALWAYS:
        return g_strdup ("Always");
      case ALERT_CONDITION_FILTER_COUNT_AT_LEAST:
        {
          char *count;
          gchar *ret;

          count = alert_data (alert, "condition", "count");
          ret = g_strdup_printf ("Filter count at least %s",
                                 count ? count : "0");
          free (count);
          return ret;
        }
      case ALERT_CONDITION_FILTER_COUNT_CHANGED:
        return g_strdup ("Filter count changed");
      case ALERT_CONDITION_SEVERITY_AT_LEAST:
        {
          char *level = alert_data (alert, "condition", "severity");
          gchar *ret = g_strdup_printf ("Task severity is at least '%s'",
                                        level);
          free (level);
          return ret;
        }
      case ALERT_CONDITION_SEVERITY_CHANGED:
        {
          char *direction;
          direction = alert_data (alert, "condition", "direction");
          gchar *ret = g_strdup_printf ("Task severity %s", direction);
          free (direction);
          return ret;
        }
      default:
        return g_strdup ("Internal Error");
    }
}

/**
 * @brief Get an alert condition from a name.
 *
 * @param[in]  name  Condition name.
 *
 * @return The condition.
 */
alert_condition_t
alert_condition_from_name (const char* name)
{
  if (strcasecmp (name, "Always") == 0)
    return ALERT_CONDITION_ALWAYS;
  if (strcasecmp (name, "Filter count at least") == 0)
    return ALERT_CONDITION_FILTER_COUNT_AT_LEAST;
  if (strcasecmp (name, "Filter count changed") == 0)
    return ALERT_CONDITION_FILTER_COUNT_CHANGED;
  if (strcasecmp (name, "Severity at least") == 0)
    return ALERT_CONDITION_SEVERITY_AT_LEAST;
  if (strcasecmp (name, "Severity changed") == 0)
    return ALERT_CONDITION_SEVERITY_CHANGED;
  return ALERT_CONDITION_ERROR;
}


/* Alert methods. */

/**
 * @brief Get the name of an alert method.
 *
 * @param[in]  method  Method.
 *
 * @return The name of the method (for example, "Email" or "SNMP").
 */
const char*
alert_method_name (alert_method_t method)
{
  switch (method)
    {
      case ALERT_METHOD_EMAIL:       return "Email";
      case ALERT_METHOD_HTTP_GET:    return "HTTP Get";
      case ALERT_METHOD_SCP:         return "SCP";
      case ALERT_METHOD_SEND:        return "Send";
      case ALERT_METHOD_SMB:         return "SMB";
      case ALERT_METHOD_SNMP:        return "SNMP";
      case ALERT_METHOD_SOURCEFIRE:  return "Sourcefire Connector";
      case ALERT_METHOD_START_TASK:  return "Start Task";
      case ALERT_METHOD_SYSLOG:      return "Syslog";
      case ALERT_METHOD_TIPPINGPOINT:return "TippingPoint SMS";
      case ALERT_METHOD_VERINICE:    return "verinice Connector";
      case ALERT_METHOD_VFIRE:       return "Alemba vFire";
      default:                       return "Internal Error";
    }
}

/**
 * @brief Get an alert method from a name.
 *
 * @param[in]  name  Method name.
 *
 * @return The method.
 */
alert_method_t
alert_method_from_name (const char* name)
{
  if (strcasecmp (name, "Email") == 0)
    return ALERT_METHOD_EMAIL;
  if (strcasecmp (name, "HTTP Get") == 0)
    return ALERT_METHOD_HTTP_GET;
  if (strcasecmp (name, "SCP") == 0)
    return ALERT_METHOD_SCP;
  if (strcasecmp (name, "Send") == 0)
    return ALERT_METHOD_SEND;
  if (strcasecmp (name, "SMB") == 0)
    return ALERT_METHOD_SMB;
  if (strcasecmp (name, "SNMP") == 0)
    return ALERT_METHOD_SNMP;
  if (strcasecmp (name, "Sourcefire Connector") == 0)
    return ALERT_METHOD_SOURCEFIRE;
  if (strcasecmp (name, "Start Task") == 0)
    return ALERT_METHOD_START_TASK;
  if (strcasecmp (name, "Syslog") == 0)
    return ALERT_METHOD_SYSLOG;
  if (strcasecmp (name, "TippingPoint SMS") == 0)
    return ALERT_METHOD_TIPPINGPOINT;
  if (strcasecmp (name, "verinice Connector") == 0)
    return ALERT_METHOD_VERINICE;
  if (strcasecmp (name, "Alemba vFire") == 0)
    return ALERT_METHOD_VFIRE;
  return ALERT_METHOD_ERROR;
}

/**
 * @brief Test an alert.
 *
 * @param[in]  alert_id    Alert UUID.
 * @param[out] script_message  Custom message from the alert script.
 *
 * @return 0 success, 1 failed to find alert, 2 failed to find task,
 *         99 permission denied, -1 error, -2 failed to find report format
 *         for alert, -3 failed to find filter for alert, -4 failed to find
 *         credential for alert, -5 alert script failed.
 */
int
manage_test_alert (const char *alert_id, gchar **script_message)
{
  int ret;
  alert_t alert;
  task_t task;
  report_t report;
  result_t result;
  char *task_id, *report_id;
  time_t now;
  char now_string[26];
  gchar *clean;

  if (acl_user_may ("test_alert") == 0)
    return 99;

  if (find_alert_with_permission (alert_id, &alert, "test_alert"))
    return -1;
  if (alert == 0)
    return 1;

  if (alert_event (alert) == EVENT_NEW_SECINFO
      || alert_event (alert) == EVENT_UPDATED_SECINFO)
    {
      char *alert_event_data;
      gchar *type;

      alert_event_data = alert_data (alert, "event", "secinfo_type");
      type = g_strdup_printf ("%s_example", alert_event_data ?: "NVT");
      free (alert_event_data);

      if (alert_event (alert) == EVENT_NEW_SECINFO)
        ret = manage_alert (alert_id, "0", EVENT_NEW_SECINFO, (void*) type,
                            script_message);
      else
        ret = manage_alert (alert_id, "0", EVENT_UPDATED_SECINFO, (void*) type,
                            script_message);

      g_free (type);

      return ret;
    }

  task = make_task (g_strdup ("Temporary Task for Alert"),
                    g_strdup (""),
                    0,  /* Exclude from assets. */
                    0); /* Skip event and log. */

  report_id = gvm_uuid_make ();
  if (report_id == NULL)
    return -1;
  task_uuid (task, &task_id);
  report = make_report (task, report_id, TASK_STATUS_DONE);

  result = make_result (task, "127.0.0.1", "localhost", "23/tcp",
                        "1.3.6.1.4.1.25623.1.0.10330", "Alarm",
                        "A telnet server seems to be running on this port.",
                        NULL);
  if (result)
    report_add_result (report, result);


  result = make_result (
              task, "127.0.0.1", "localhost", "general/tcp",
              "1.3.6.1.4.1.25623.1.0.103823", "Alarm",
              "IP,Host,Port,SSL/TLS-Version,Ciphers,Application-CPE\n"
              "127.0.0.1,localhost,443,TLSv1.1;TLSv1.2",
              NULL);
  if (result)
    report_add_result (report, result);

  now = time (NULL);
  if (strlen (ctime_r (&now, now_string)) == 0)
    {
      ret = -1;
      goto exit;
    }
  clean = g_strdup (now_string);
  if (clean[strlen (clean) - 1] == '\n')
    clean[strlen (clean) - 1] = '\0';
  set_task_start_time_ctime (task, g_strdup (clean));
  set_scan_start_time_ctime (report, g_strdup (clean));
  set_scan_host_start_time_ctime (report, "127.0.0.1", clean);

  insert_report_host_detail (report,
                             "127.0.0.1",
                             "nvt",
                             "1.3.6.1.4.1.25623.1.0.108577",
                             "",
                             "App",
                             "cpe:/a:openbsd:openssh:8.9p1",
                             "0123456789ABCDEF0123456789ABCDEF");

  insert_report_host_detail (report,
                             "127.0.0.1",
                             "nvt",
                             "1.3.6.1.4.1.25623.1.0.10330",
                             "Host Details",
                             "best_os_cpe",
                             "cpe:/o:canonical:ubuntu_linux:22.04",
                             "123456789ABCDEF0123456789ABCDEF0");

  set_scan_host_end_time_ctime (report, "127.0.0.1", clean);
  set_scan_end_time_ctime (report, clean);
  g_free (clean);
  ret = manage_alert (alert_id,
                      task_id,
                      EVENT_TASK_RUN_STATUS_CHANGED,
                      (void*) TASK_STATUS_DONE,
                      script_message);
 exit:
  /* No one should be running this task, so we don't worry about the lock.  We
   * could guarantee that no one runs the task, but this is a very rare case. */
  delete_task (task, 1);
  free (task_id);
  free (report_id);
  return ret;
}

/**
 * @brief Check if any SecInfo alerts are due.
 *
 * @param[in]  log_config  Log configuration.
 * @param[in]  database    Location of manage database.
 *
 * @return 0 success, -1 error,
 *         -2 database is too old, -3 database needs to be initialised
 *         from server, -5 database is too new.
 */
int
manage_check_alerts (GSList *log_config, const db_conn_info_t *database)
{
  int ret;

  g_info ("   Checking alerts.");

  ret = manage_option_setup (log_config, database,
                             0 /* avoid_db_check_inserts */);
  if (ret)
    return ret;

  /* Setup a dummy user, so that create_user will work. */
  current_credentials.uuid = "";

  check_alerts ();

  current_credentials.uuid = NULL;

  manage_option_cleanup ();

  return ret;
}
