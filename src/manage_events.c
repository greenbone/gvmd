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
 * @file manage_events.c
 * @brief GVM management layer: Events.
 *
 * General functions for managing events.
 */

#include "manage_events.h"
#include "manage_sql_alerts.h"
#include "manage_acl.h"
#include "manage_sql.h"
#include "manage_sql_tickets.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"


/**
 * @brief Return whether the condition of an alert is met by a task.
 *
 * @param[in]  task       Task.
 * @param[in]  report     Report.
 * @param[in]  alert      Alert.
 * @param[in]  condition  Condition.
 *
 * @return 1 if met, else 0.
 */
static int
condition_met (task_t task, report_t report, alert_t alert,
               alert_condition_t condition)
{
  switch (condition)
    {
      case ALERT_CONDITION_ALWAYS:
        return 1;
        break;
      case ALERT_CONDITION_FILTER_COUNT_AT_LEAST:
        {
          char *filter_id, *count_string;
          report_t last_report;
          int criticals = 0, holes, infos, logs, warnings, false_positives;
          int count;
          double severity;

          /* True if there are at least the given number of results matched by
           * the given filter in the last finished report. */

          filter_id = alert_data (alert, "condition", "filter_id");
          count_string = alert_data (alert, "condition", "count");
          if (count_string)
            {
              count = atoi (count_string);
              free (count_string);
            }
          else
            count = 0;

          if (task == 0)
            {
              int db_count;

              /* SecInfo event. */

              db_count = alert_secinfo_count (alert, filter_id);

              if (db_count >= count)
                return 1;
              break;
            }

          if (report)
            last_report = report;
          else
            {
              last_report = 0;
              if (task_last_report (task, &last_report))
                g_warning ("%s: failed to get last report", __func__);
            }

          g_debug ("%s: last_report: %llu", __func__, last_report);
          if (last_report)
            {
              int db_count;
              get_data_t get;
              memset (&get, 0, sizeof (get_data_t));
              get.type = "result";
              get.filt_id = filter_id;
#if CVSS3_RATINGS == 1
              report_counts_id (last_report, &criticals, &holes, &infos, &logs,
                                &warnings, &false_positives, &severity,
                                &get, NULL);
#else
              report_counts_id (last_report, &holes, &infos, &logs,
                                &warnings, &false_positives, &severity,
                                &get, NULL);
#endif
              db_count = criticals + holes + infos + logs + warnings
                         + false_positives;

              g_debug ("%s: count: %i vs %i", __func__, db_count, count);
              if (db_count >= count)
                {
                  g_free (filter_id);
                  return 1;
                }
            }
          g_free (filter_id);
          break;
        }
      case ALERT_CONDITION_FILTER_COUNT_CHANGED:
        {
          char *direction, *filter_id, *count_string;
          report_t last_report;
          int criticals = 0, holes, infos, logs, warnings, false_positives;
          int count;
          double severity;

          /* True if the number of results matched by the given filter in the
           * last finished report changed in the given direction with respect
           * to the second last finished report. */

          direction = alert_data (alert, "condition", "direction");
          filter_id = alert_data (alert, "condition", "filter_id");
          count_string = alert_data (alert, "condition", "count");
          if (count_string)
            {
              count = atoi (count_string);
              free (count_string);
            }
          else
            count = 0;

          if (report)
            last_report = report;
          else
            {
              last_report = 0;
              if (task_last_report (task, &last_report))
                g_warning ("%s: failed to get last report", __func__);
            }

          if (last_report)
            {
              report_t second_last_report;
              int last_count;
              get_data_t get;
              get.type = "result";
              get.filt_id = filter_id;
#if CVSS3_RATINGS == 1
              report_counts_id (last_report, &criticals, &holes, &infos, &logs,
                                &warnings, &false_positives, &severity,
                                &get, NULL);
#else
              report_counts_id (last_report, &holes, &infos, &logs,
                                &warnings, &false_positives, &severity,
                                &get, NULL);
#endif
              last_count = criticals + holes + infos + logs + warnings
                            + false_positives;

              second_last_report = 0;
              if (task_second_last_report (task, &second_last_report))
                g_warning ("%s: failed to get second last report", __func__);

              if (second_last_report)
                {
                  int cmp, second_last_count;
#if CVSS3_RATINGS == 1
                  report_counts_id (second_last_report, &criticals, &holes, &infos,
                                    &logs, &warnings, &false_positives,
                                    &severity, &get, NULL);
#else
                  report_counts_id (second_last_report, &holes, &infos,
                                    &logs, &warnings, &false_positives,
                                    &severity, &get, NULL);
#endif
                  second_last_count = criticals + holes + infos + logs + warnings
                                      + false_positives;

                  cmp = last_count - second_last_count;
                  g_debug ("cmp: %i (vs %i)", cmp, count);
                  g_debug ("direction: %s", direction);
                  g_debug ("last_count: %i", last_count);
                  g_debug ("second_last_count: %i", second_last_count);
                  if (count < 0)
                    {
                      count = -count;
                      if (direction == NULL
                          || strcasecmp (direction, "increased") == 0)
                        {
                          free (direction);
                          direction = g_strdup ("decreased");
                        }
                      else if (strcasecmp (direction, "decreased") == 0)
                        {
                          free (direction);
                          direction = g_strdup ("increased");
                        }
                    }
                  if (direction == NULL)
                    {
                      /* Same as "increased". */
                      if (cmp >= count)
                        {
                          free (filter_id);
                          return 1;
                        }
                    }
                  else if (((strcasecmp (direction, "changed") == 0)
                            && (abs (cmp) >= count))
                           || ((strcasecmp (direction, "increased") == 0)
                               && (cmp >= count))
                           || ((strcasecmp (direction, "decreased") == 0)
                               && (cmp <= count)))
                    {
                      free (direction);
                      free (filter_id);
                      return 1;
                    }
                }
              else
                {
                  g_debug ("direction: %s", direction);
                  g_debug ("last_count: %i", last_count);
                  g_debug ("second_last_count NULL");
                  if (direction == NULL)
                    {
                      /* Same as "increased". */
                      if (last_count > 0)
                        {
                          free (filter_id);
                          return 1;
                        }
                    }
                  else if (((strcasecmp (direction, "changed") == 0)
                       || (strcasecmp (direction, "increased") == 0))
                      && (last_count > 0))
                    {
                      free (direction);
                      free (filter_id);
                      return 1;
                    }
                }
            }
          free (direction);
          free (filter_id);
          break;
        }
      case ALERT_CONDITION_SEVERITY_AT_LEAST:
        {
          char *condition_severity_str;

          /* True if the threat level of the last finished report is at
           * least the given level. */

          condition_severity_str = alert_data (alert, "condition", "severity");

          if (condition_severity_str)
            {
              double condition_severity_dbl, task_severity_dbl;

              condition_severity_dbl = g_ascii_strtod (condition_severity_str,
                                                       0);
              task_severity_dbl = task_severity_double (task, 1,
                                                        MIN_QOD_DEFAULT, 0);

              if (task_severity_dbl >= condition_severity_dbl)
                {
                  free (condition_severity_str);
                  return 1;
                }
            }
          free (condition_severity_str);
          break;
        }
      case ALERT_CONDITION_SEVERITY_CHANGED:
        {
          char *direction;
          double last_severity, second_last_severity;

          /* True if the threat level of the last finished report changed
           * in the given direction with respect to the second last finished
           * report. */

          direction = alert_data (alert, "condition", "direction");
          last_severity = task_severity_double (task, 1,
                                                MIN_QOD_DEFAULT, 0);
          second_last_severity = task_severity_double (task, 1,
                                                       MIN_QOD_DEFAULT, 1);
          if (direction
              && last_severity > SEVERITY_MISSING
              && second_last_severity > SEVERITY_MISSING)
            {
              double cmp = last_severity - second_last_severity;
              g_debug ("cmp: %f", cmp);
              g_debug ("direction: %s", direction);
              g_debug ("last_level: %1.1f", last_severity);
              g_debug ("second_last_level: %1.1f", second_last_severity);
              if (((strcasecmp (direction, "changed") == 0) && cmp)
                  || ((strcasecmp (direction, "increased") == 0) && (cmp > 0))
                  || ((strcasecmp (direction, "decreased") == 0) && (cmp < 0)))
                {
                  free (direction);
                  return 1;
                }
            }
          else if (direction
                   && last_severity > SEVERITY_MISSING)
            {
              g_debug ("direction: %s", direction);
              g_debug ("last_level: %1.1f", last_severity);
              g_debug ("second_last_level NULL");
              if ((strcasecmp (direction, "changed") == 0)
                  || (strcasecmp (direction, "increased") == 0))
                {
                  free (direction);
                  return 1;
                }
            }
          free (direction);
          break;
        }
      default:
        break;
    }
  return 0;
}

/**
 * @brief Escalate an event with preset report filtering.
 *
 * @param[in]  alert       Alert.
 * @param[in]  task        Task.
 * @param[in]  report      Report.
 * @param[in]  event       Event.
 * @param[in]  event_data  Event data.
 * @param[in]  method      Method from alert.
 * @param[in]  condition   Condition from alert, which was met by event.
 * @param[out] script_message  Custom error message from alert script.
 *
 * @return 0 success, -1 error, -2 failed to find report format for alert,
 *         -3 failed to find filter for alert, -4 failed to find credential,
 *         -5 alert script failed.
 */
static int
escalate_1 (alert_t alert, task_t task, report_t report, event_t event,
            const void* event_data, alert_method_t method,
            alert_condition_t condition, gchar **script_message)
{
  int ret;
  get_data_t get;
  char *results_filter;

  memset (&get, 0, sizeof (get_data_t));
  get.details = 1;

  results_filter = setting_filter ("Results");
  if (results_filter && strlen (results_filter))
    {
      get.filt_id = results_filter;
      get.filter = filter_term (results_filter);
    }
  else
    {
      get.filt_id = g_strdup ("0");
      get.filter = g_strdup_printf ("notes=1 overrides=1 sort-reverse=severity"
                                    " rows=%d",
                                    method == ALERT_METHOD_EMAIL ? 1000 : -1);
    }

  ret = escalate_2 (alert, task, report, event, event_data, method, condition,
                    &get, 1, 1, script_message);
  free (results_filter);
  g_free (get.filter);
  return ret;
}

/**
 * @brief Get the name of an alert event.
 *
 * @param[in]  event  Event.
 *
 * @return The name of the event (for example, "Run status changed").
 */
const char*
event_name (event_t event)
{
  switch (event)
    {
      case EVENT_TASK_RUN_STATUS_CHANGED: return "Task run status changed";
      case EVENT_NEW_SECINFO:             return "New SecInfo arrived";
      case EVENT_UPDATED_SECINFO:         return "Updated SecInfo arrived";
      case EVENT_TICKET_RECEIVED:         return "Ticket received";
      case EVENT_ASSIGNED_TICKET_CHANGED: return "Assigned ticket changed";
      case EVENT_OWNED_TICKET_CHANGED:    return "Owned ticket changed";
      default:                            return "Internal Error";
    }
}

/**
 * @brief Get a description of an alert event.
 *
 * @param[in]  event       Event.
 * @param[in]  event_data  Event data.
 * @param[in]  task_name   Name of task if required in description, else NULL.
 *
 * @return Freshly allocated description of event.
 */
gchar*
event_description (event_t event, const void *event_data, const char *task_name)
{
  switch (event)
    {
      case EVENT_TASK_RUN_STATUS_CHANGED:
        if (task_name)
          return g_strdup_printf
                  ("The security scan task '%s' changed status to '%s'",
                   task_name,
                   run_status_name ((task_status_t) event_data));
        return g_strdup_printf ("Task status changed to '%s'",
                                run_status_name ((task_status_t) event_data));
        break;
      case EVENT_NEW_SECINFO:
        return g_strdup_printf ("New SecInfo arrived");
        break;
      case EVENT_UPDATED_SECINFO:
        return g_strdup_printf ("Updated SecInfo arrived");
        break;
      case EVENT_TICKET_RECEIVED:
        return g_strdup_printf ("Ticket received");
        break;
      case EVENT_ASSIGNED_TICKET_CHANGED:
        return g_strdup_printf ("Assigned ticket changed");
        break;
      case EVENT_OWNED_TICKET_CHANGED:
        return g_strdup_printf ("Owned ticket changed");
        break;
      default:
        return g_strdup ("Internal Error");
    }
}

/**
 * @brief Get an event from a name.
 *
 * @param[in]  name  Event name.
 *
 * @return The event.
 */
event_t
event_from_name (const char* name)
{
  if (strcasecmp (name, "Task run status changed") == 0)
    return EVENT_TASK_RUN_STATUS_CHANGED;
  if (strcasecmp (name, "New SecInfo arrived") == 0)
    return EVENT_NEW_SECINFO;
  if (strcasecmp (name, "Updated SecInfo arrived") == 0)
    return EVENT_UPDATED_SECINFO;
  if (strcasecmp (name, "Ticket received") == 0)
    return EVENT_TICKET_RECEIVED;
  if (strcasecmp (name, "Assigned ticket changed") == 0)
    return EVENT_ASSIGNED_TICKET_CHANGED;
  if (strcasecmp (name, "Owned ticket changed") == 0)
    return EVENT_OWNED_TICKET_CHANGED;
  return EVENT_ERROR;
}

/**
 * @brief Return whether an event applies to a task and an alert.
 *
 * @param[in]  event           Event.
 * @param[in]  event_data      Event data.
 * @param[in]  event_resource  Event resource.
 * @param[in]  alert           Alert.
 *
 * @return 1 if event applies, else 0.
 */
static int
event_applies (event_t event, const void *event_data,
               resource_t event_resource, alert_t alert)
{
  switch (event)
    {
      case EVENT_TASK_RUN_STATUS_CHANGED:
        {
          int ret;
          char *alert_event_data;

          if (alert_applies_to_task (alert, event_resource) == 0)
            return 0;

          alert_event_data = alert_data (alert, "event", "status");
          if (alert_event_data == NULL)
            return 0;
          ret = (task_run_status (event_resource) == (task_status_t) event_data)
                && (strcmp (alert_event_data,
                            run_status_name_internal ((task_status_t)
                                                      event_data))
                    == 0);
          free (alert_event_data);
          return ret;
        }
      case EVENT_NEW_SECINFO:
      case EVENT_UPDATED_SECINFO:
        {
          char *alert_event_data;

          alert_event_data = alert_data (alert, "event", "secinfo_type");
          if (alert_event_data == NULL)
            return 0;
          if (strcasecmp (alert_event_data, event_data) == 0)
            return 1;
          return 0;
        }
      case EVENT_TICKET_RECEIVED:
      case EVENT_ASSIGNED_TICKET_CHANGED:
        return ticket_assigned_to (event_resource) == alert_owner (alert);
      case EVENT_OWNED_TICKET_CHANGED:
        return ticket_owner (event_resource) == alert_owner (alert);
      default:
        return 0;
    }
}

/**
 * @brief Produce an event.
 *
 * @param[in]  event       Event.
 * @param[in]  event_data  Event type specific details.
 * @param[in]  resource_1  Event type specific resource 1.  For example,
 *                         a task for EVENT_TASK_RUN_STATUS_CHANGED.
 * @param[in]  resource_2  Event type specific resource 2.
 */
void
event (event_t event, void* event_data, resource_t resource_1,
       resource_t resource_2)
{
  iterator_t alerts;
  GArray *alerts_triggered;
  guint index;

  g_debug ("   EVENT %i on resource %llu", event, resource_1);

  alerts_triggered = g_array_new (TRUE, TRUE, sizeof (alert_t));

  if ((event == EVENT_TASK_RUN_STATUS_CHANGED)
      && (((task_status_t) event_data) == TASK_STATUS_DONE))
    check_tickets (resource_1);

  init_event_alert_iterator (&alerts, event);
  while (next (&alerts))
    {
      alert_t alert = event_alert_iterator_alert (&alerts);
      if (event_alert_iterator_active (&alerts)
          && event_applies (event, event_data, resource_1, alert))
        {
          alert_condition_t condition;

          condition = alert_condition (alert);
          if (condition_met (resource_1, resource_2, alert, condition))
            g_array_append_val (alerts_triggered, alert);
        }
    }
  cleanup_iterator (&alerts);

  /* Run the alerts outside the iterator, because they may take some
   * time and the iterator would prevent update processes (GMP MODIFY_XXX,
   * CREATE_XXX, ...) from locking the database. */
  index = alerts_triggered->len;
  while (index--)
    {
      alert_t alert;
      alert_condition_t condition;

      alert = g_array_index (alerts_triggered, alert_t, index);
      condition = alert_condition (alert);
      escalate_1 (alert,
                  resource_1,
                  resource_2,
                  event,
                  event_data,
                  alert_method (alert),
                  condition,
                  NULL);
    }

  g_array_free (alerts_triggered, TRUE);
}

/**
 * @brief Escalate an alert with task and event data.
 *
 * @param[in]  alert_id    Alert UUID.
 * @param[in]  task_id     Task UUID.
 * @param[in]  event       Event.
 * @param[in]  event_data  Event data.
 * @param[out] script_message  Custom error message from alert script.
 *
 * @return 0 success, 1 failed to find alert, 2 failed to find task,
 *         99 permission denied, -1 error, -2 failed to find report format
 *         for alert, -3 failed to find filter for alert, -4 failed to find
 *         credential for alert, -5 alert script failed.
 */
int
manage_alert (const char *alert_id, const char *task_id, event_t event,
              const void* event_data, gchar **script_message)
{
  alert_t alert;
  task_t task;
  alert_condition_t condition;
  alert_method_t method;

  if (acl_user_may ("test_alert") == 0)
    return 99;

  if (find_alert_with_permission (alert_id, &alert, "test_alert"))
    return -1;
  if (alert == 0)
    return 1;

  if (task_id == NULL || strcmp (task_id, "0") == 0)
    task = 0;
  else
    {
      if (find_task_with_permission (task_id, &task, NULL))
        return -1;
      if (task == 0)
        return 2;
    }

  condition = alert_condition (alert);
  method = alert_method (alert);
  return escalate_1 (alert, task, 0, event, event_data, method, condition,
                     script_message);
}
