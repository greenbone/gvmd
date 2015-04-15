/* OpenVAS Manager
 * $Id$
 * Description: Module for OpenVAS Manager: the Manage library.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 * Timo Pollmeier <timo.pollmeier@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2009-2013 Greenbone Networks GmbH
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

/**
 * @file  manage.c
 * @brief The OpenVAS Manager management library.
 *
 * This file defines a management library, for implementing OpenVAS
 * Managers such as the OpenVAS Manager daemon.
 *
 * This library provides facilities for storing and manipulating credential
 * and task information, and manipulating reports.  Task manipulation
 * includes sending task commands to the OTP server (the "scanner") that is
 * running the tasks.
 */

/* time.h in glibc2 needs this for strptime. */
#define _XOPEN_SOURCE

#include "manage.h"
#include "sql.h"
#include "manage_sql.h"
#include "ovas-mngr-comm.h"
#include "tracef.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <glib.h>
#include <math.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <openvas/base/openvas_string.h>
#include <openvas/omp/omp.h>
#include <openvas/misc/openvas_server.h>
#include <openvas/misc/nvt_categories.h>
#include <openvas/misc/openvas_uuid.h>

#ifdef S_SPLINT_S
#include "splint.h"
#endif

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief CPE selection stylesheet location.
 */
#define CPE_GETBYNAME_XSL SCAP_RES_DIR "/cpe_getbyname.xsl"

/**
 * @brief CVE selection stylesheet location.
 */
#define CVE_GETBYNAME_XSL SCAP_RES_DIR "/cve_getbyname.xsl"

/**
 * @brief OVALDEF selection stylesheet location.
 */
#define OVALDEF_GETBYNAME_XSL SCAP_RES_DIR "/ovaldef_getbyname.xsl"

/**
 * @brief DFN_CERT_ADV selection stylesheet location.
 */
#define DFN_CERT_ADV_GETBYNAME_XSL CERT_RES_DIR "/dfn_cert_getbyname.xsl"

/**
 * @brief CPE dictionary location.
 */
#define CPE_DICT_FILENAME SCAP_DATA_DIR "/official-cpe-dictionary_v2.2.xml"

/**
 * @brief CVE data files location format string.
 *
 * %d should be the year expressed as YYYY.
 */
#define CVE_FILENAME_FMT SCAP_DATA_DIR "/nvdcve-2.0-%d.xml"

/**
 * @brief DFN-CERT data files location format string.
 *
 * First %d should be the year expressed as YYYY,
 * second %d should be should be Month expressed as MM.
 */
#define DFN_CERT_ADV_FILENAME_FMT CERT_DATA_DIR "/dfn-cert-%04d.xml"

/**
 * @brief SCAP timestamp location.
 */
#define SCAP_TIMESTAMP_FILENAME SCAP_DATA_DIR "/timestamp"

/**
 * @brief CERT timestamp location.
 */
#define CERT_TIMESTAMP_FILENAME CERT_DATA_DIR "/timestamp"

/**
 * @brief Default for Scanner max_checks preference.
 */
#define MAX_CHECKS_DEFAULT "4"

/**
 * @brief Default for Scanner max_hosts preference.
 */
#define MAX_HOSTS_DEFAULT "20"

/* Severity related functions. */

/**
 * @brief Get the message type of a threat.
 *
 * @param  threat  Threat.
 *
 * @return Static message type name if threat names a threat, else NULL.
 */
const char *
threat_message_type (const char *threat)
{
  if (strcasecmp (threat, "High") == 0)
    return "Alarm";
  if (strcasecmp (threat, "Medium") == 0)
    return "Alarm";
  if (strcasecmp (threat, "Low") == 0)
    return "Alarm";
  if (strcasecmp (threat, "Log") == 0)
    return "Log Message";
  if (strcasecmp (threat, "Debug") == 0)
    return "Debug Message";
  if (strcasecmp (threat, "False Positive") == 0)
    return "False Positive";
  return NULL;
}

/**
 * @brief Get the threat of a message type.
 *
 * @param  type  Message type.
 *
 * @return Static threat name if type names a message type, else NULL.
 */
const char *
message_type_threat (const char *type)
{
  if (strcasecmp (type, "Alarm") == 0)
    return "Alarm";
  if (strcasecmp (type, "Security Hole") == 0)
    return "High";
  if (strcasecmp (type, "Security Warning") == 0)
    return "Medium";
  if (strcasecmp (type, "Security Note") == 0)
    return "Low";
  if (strcasecmp (type, "Log Message") == 0)
    return "Log";
  if (strcasecmp (type, "Debug Message") == 0)
    return "Debug";
  if (strcasecmp (type, "False Positive") == 0)
    return "False Positive";
  return NULL;
}

/**
 * @brief Check whether a severity falls within a threat level.
 *
 * @param[in]  severity  Severity.
 * @param[in]  level     Threat level.
 *
 * @return 1 if in level, else 0.
 */
int
severity_in_level (double severity, const char *level)
{
  const char *class;

  class = setting_severity ();
  if (strcmp (class, "classic") == 0)
    {
      if (strcmp (level, "high") == 0)
        return severity > 5 && severity <= 10;
      else if (strcmp (level, "medium") == 0)
        return severity > 2 && severity <= 5;
      else if (strcmp (level, "low") == 0)
        return severity > 0 && severity <= 2;
      else if (strcmp (level, "none") == 0)
        return severity == 0;
      else
        return 0;
    }
  else if (strcmp (class, "pci-dss") == 0)
    {
      if (strcmp (level, "high") == 0)
        return severity >= 4.3;
      else if (strcmp (level, "none") == 0)
        return severity == 0;
      else
        return 0;
    }
  else
    {
      /* NIST/BSI. */
      if (strcmp (level, "high") == 0)
        return severity >= 7 && severity <= 10;
      else if (strcmp (level, "medium") == 0)
        return severity >= 4 && severity < 7;
      else if (strcmp (level, "low") == 0)
        return severity > 0 && severity < 4;
      else if (strcmp (level, "none") == 0)
        return severity == 0;
      else
        return 0;
    }
}

/**
 * @brief Get the minimum severity for a severity level and class.
 *
 * @param[in] level  The name of the severity level.
 * @param[in] class  The severity class, NULL to get from current user setting.
 *
 * @return The minimum severity.
 */
double
level_min_severity (const char *level, const gchar *class)
{
  if (strcmp (level, "Log") == 0)
    return SEVERITY_LOG;
  else if (strcmp (level, "False Positive") == 0)
    return SEVERITY_FP;
  else if (strcmp (level, "Debug") == 0)
    return SEVERITY_DEBUG;
  else if (strcmp (level, "Error") == 0)
    return SEVERITY_ERROR;
  else if (strcmp (class, "classic") == 0)
    {
      if (strcmp (level, "high") == 0)
        return 5.1;
      else if (strcmp (level, "medium") == 0)
        return 2.1;
      else if (strcmp (level, "low") == 0)
        return 0.1;
      else
        return SEVERITY_UNDEFINED;
    }
  else if (strcmp (class, "pci-dss") == 0)
    {
      if (strcmp (level, "high") == 0)
        return 4.3;
      else
        return SEVERITY_UNDEFINED;
    }
  else
    {
      /* NIST/BSI. */
      if (strcmp (level, "high") == 0)
        return 7.0;
      else if (strcmp (level, "medium") == 0)
        return 4.0;
      else if (strcmp (level, "low") == 0)
        return 0.1;
      else
        return SEVERITY_UNDEFINED;
    }
}

/**
 * @brief Get the minimum severity for a severity level and class.
 *
 * @param[in] level  The name of the severity level.
 * @param[in] class  The severity class.
 *
 * @return The minimum severity.
 */
double
level_max_severity (const char *level, const gchar *class)
{
  if (strcmp (level, "Log") == 0)
    return SEVERITY_LOG;
  else if (strcmp (level, "False Positive") == 0)
    return SEVERITY_FP;
  else if (strcmp (level, "Debug") == 0)
    return SEVERITY_DEBUG;
  else if (strcmp (level, "Error") == 0)
    return SEVERITY_ERROR;
  else if (strcmp (class, "classic") == 0)
    {
      if (strcmp (level, "high") == 0)
        return 10.0;
      else if (strcmp (level, "medium") == 0)
        return 5.0;
      else if (strcmp (level, "low") == 0)
        return 2.0;
      else
        return SEVERITY_UNDEFINED;
    }
  else if (strcmp (class, "pci-dss") == 0)
    {
      if (strcmp (level, "high") == 0)
        return 10.0;
      else
        return SEVERITY_UNDEFINED;
    }
  else
    {
      /* NIST/BSI. */
      if (strcmp (level, "high") == 0)
        return 10.0;
      else if (strcmp (level, "medium") == 0)
        return 6.9;
      else if (strcmp (level, "low") == 0)
        return 3.9;
      else
        return SEVERITY_UNDEFINED;
    }
}

/**
 * @brief Check whether a severity matches a message type.
 *
 * @param[in] severity  severity score
 * @param[in] type      message type
 *
 * @return 1 if matches, else 0.
 */
int
severity_matches_type (double severity, const char *type)
{
  if (type == NULL)
    {
      g_warning ("%s: type is NULL", __FUNCTION__);
      return 0;
    }
  if (severity == SEVERITY_LOG)
    return strcmp ("Log Message", type) == 0;
  if (severity == SEVERITY_FP)
    return strcmp ("False Positive", type) == 0;
  if (severity == SEVERITY_DEBUG)
    return strcmp ("Debug Message", type) == 0;
  if (severity == SEVERITY_ERROR)
    return strcmp ("Error Message", type) == 0;
  if (severity > 0.0 && severity <= 10.0)
    {
      if (strcmp ("Alarm", type) == 0)
        return 1;
      if ((strcmp ("high", type) == 0)
               || (strcmp ("medium", type) == 0)
               || (strcmp ("low", type) == 0))
        return severity_in_level (severity, type);
      if (strcmp ("Security Hole", type) == 0)
        return severity_in_level (severity, "high");
      if (strcmp ("Security Warning", type) == 0)
        return severity_in_level (severity, "medium");
      if (strcmp ("Security Note", "type") == 0)
        return severity_in_level (severity, "low");
      return 0;
    }
  g_warning ("%s: Invalid severity score given: %f",
             __FUNCTION__, severity);
  return 0;
}

/**
 * @brief Check whether a severity matches an override's severity.
 *
 * @param[in] severity     severity score
 * @param[in] ov_severity  override severity score to match
 *
 * @return 1 if matches, else 0.
 */
int
severity_matches_ov (double severity, double ov_severity)
{
  if (ov_severity <= 0.0)
    return severity == ov_severity;
  else
    return severity >= ov_severity;
}

/**
 * @brief Get the threat level matching a severity score.
 *
 * @param[in] severity  severity score
 * @param[in] mode      0 for normal levels, 1 to use "Alarm" for severity > 0.0
 *
 * @return the level as a static string
 */
const char*
severity_to_level (double severity, int mode)
{
  if (severity == SEVERITY_LOG)
    return "Log";
  else if (severity == SEVERITY_FP)
    return "False Positive";
  else if (severity == SEVERITY_DEBUG)
    return "Debug";
  else if (severity == SEVERITY_ERROR)
    return "Error";
  else if (severity > 0.0 && severity <= 10.0)
    {
      if (mode == 1)
        return ("Alarm");
      else if (severity_in_level (severity, "high"))
        return ("High");
      else if (severity_in_level (severity, "medium"))
        return ("Medium");
      else if (severity_in_level (severity, "low"))
        return ("Low");
      else
        return ("Log");
    }
  else
    {
      g_warning ("%s: Invalid severity score given: %f",
                 __FUNCTION__, severity);
      return (NULL);
    }
}

/**
 * @brief Get the message type matching a severity score.
 *
 * @param[in] severity  severity score
 *
 * @return the message type as a static string
 */
const char*
severity_to_type (double severity)
{
  if (severity == SEVERITY_LOG)
    return "Log Message";
  else if (severity == SEVERITY_FP)
    return "False Positive";
  else if (severity == SEVERITY_DEBUG)
    return "Debug Message";
  else if (severity == SEVERITY_ERROR)
    return "Error Message";
  else if (severity > 0.0 && severity <= 10.0)
    return "Alarm";
  else
    {
      g_warning ("%s: Invalid severity score given: %f",
                 __FUNCTION__, severity);
      return (NULL);
    }
}


/* Credentials. */

/**
 * @brief Current credentials during any OMP command.
 */
credentials_t current_credentials;


/* Reports. */

/**
 * @brief Delete all the reports for a task.
 *
 * It's up to the caller to ensure that this runs in a contention safe
 * context (for example within an SQL transaction).
 *
 * @param[in]  task  A task descriptor.
 *
 * @return 0 on success, -1 on error.
 */
int
delete_reports (task_t task)
{
  report_t report;
  iterator_t iterator;
  init_report_iterator_task (&iterator, task);
  while (next_report (&iterator, &report))
    if (delete_report_internal (report))
      {
        cleanup_iterator (&iterator);
        return -1;
      }
  cleanup_iterator (&iterator);
  return 0;
}

/**
 * @brief Return the threat associated with a result type.
 *
 * @param[in]  type  Result type.
 *
 * @return Threat name.
 */
const char*
manage_result_type_threat (const char* type)
{
  if (strcasecmp (type, "Security Hole") == 0)
    return "High";
  if (strcasecmp (type, "Security Warning") == 0)
    return "Medium";
  if (strcasecmp (type, "Security Note") == 0)
    return "Low";
  if (strcasecmp (type, "False Positive") == 0)
    return "False Positive";
  return "Log";
}


/* Array index of severity 0.0 in the severity_data_t.counts array */
#define ZERO_SEVERITY_INDEX 4

/**
 * @brief Convert a severity value into an index in the counts array.
 *
 * @param[in]   severity        Severity value.
 *
 * @return      The index, 0 for invalid severity scores.
 */
int
severity_data_index (double severity)
{
  int ret;
  if (severity >= 0.0)
    ret = (int)(round (severity * SEVERITY_SUBDIVISIONS)) + ZERO_SEVERITY_INDEX;
  else if (severity == SEVERITY_FP || severity == SEVERITY_DEBUG
           || severity == SEVERITY_ERROR)
    ret = (int)(round (severity)) + ZERO_SEVERITY_INDEX;
  else
    ret = 0;

  return ret;
}

/**
 * @brief Convert an index in the counts array to a severity value.
 *
 * @param[in]   index   Index in the counts array.
 *
 * @return      The corresponding severity value.
 */
double
severity_data_value (int index)
{
  double ret;
  if (index <= ZERO_SEVERITY_INDEX && index > 0)
    ret = ((double) index) - ZERO_SEVERITY_INDEX;
  else if (index <= (ZERO_SEVERITY_INDEX
                     + (SEVERITY_SUBDIVISIONS * SEVERITY_MAX)))
    ret = (((double) (index - ZERO_SEVERITY_INDEX)) / SEVERITY_SUBDIVISIONS);
  else
    ret = SEVERITY_MISSING;

  return ret;
}

/**
 * @brief Initialize a severity data structure.
 *
 * @param[in] data  The data structure to initialize.
 */
void
init_severity_data (severity_data_t* data)
{
  int max_i;
  max_i = ZERO_SEVERITY_INDEX + (SEVERITY_SUBDIVISIONS * SEVERITY_MAX);

  data->counts = g_malloc0 (sizeof (int) * (max_i + 1));

  data->total = 0;
  data->max = SEVERITY_MISSING;
}

/**
 * @brief Clean up a severity data structure.
 *
 * @param[in] data  The data structure to initialize.
 */
void
cleanup_severity_data (severity_data_t* data)
{
  g_free (data->counts);
}

/**
 * @brief Add a severity occurence to the counts of a severity_data_t.
 *
 * @param[in]   severity_data   The severity count struct to add to.
 * @param[in]   severity        The severity to add.
 */
void
severity_data_add (severity_data_t* severity_data, double severity)
{
  (severity_data->counts)[severity_data_index (severity)]++;

  if (severity_data->total == 0 || severity_data->max <= severity)
    severity_data->max = severity;

  (severity_data->total)++;
}

/**
 * @brief Add a multiple severity occurences to the counts of a severity_data_t.
 *
 * @param[in]   severity_data   The severity count struct to add to.
 * @param[in]   severity        The severity to add.
 * @param[in]   count           The number of occurences to add.
 */
void
severity_data_add_count (severity_data_t* severity_data, double severity,
                         int count)
{
  (severity_data->counts)[severity_data_index (severity)] += count;

  if (severity_data->total == 0 || severity_data->max <= severity)
    severity_data->max = severity;

  (severity_data->total) += count;
}

/**
 * @brief Calculate the total of severity counts in a range.
 *
 * @param[in]  severity_data   The severity data struct to get counts from.
 * @param[in]  min_severity    The minimum severity included in the range.
 * @param[in]  max_severity    The maximum severity included in the range.
 *
 * @return     The total of severity counts in the specified range.
 */
int
severity_data_range_count (const severity_data_t* severity_data,
                           double min_severity, double max_severity)
{
  int i, i_max, count;

  i_max = severity_data_index (max_severity);
  count = 0;

  for (i = severity_data_index (min_severity);
       i <= i_max;
       i++)
    {
      count += (severity_data->counts)[i];
    }
  return count;
}

/**
 * @brief Count the occurrences of severities in the levels.
 *
 * @param[in] severity_data    The severity counts data to evaluate.
 * @param[in] severity_class   The severity class setting to use.
 * @param[out] errors          The number of error messages.
 * @param[out] debugs          The number of debug messages.
 * @param[out] false_positives The number of False Positives.
 * @param[out] logs            The number of Log messages.
 * @param[out] lows            The number of Low severity results.
 * @param[out] mediums         The number of Medium severity results.
 * @param[out] highs           The number of High severity results.
 */
void
severity_data_level_counts (const severity_data_t *severity_data,
                            const gchar *severity_class,
                            int *errors, int *debugs, int *false_positives,
                            int *logs, int *lows, int *mediums, int *highs)
{
  if (errors)
    *errors
      = severity_data_range_count (severity_data,
                                   level_min_severity ("Error",
                                                       severity_class),
                                   level_max_severity ("Error",
                                                       severity_class));

  if (debugs)
    *debugs
      = severity_data_range_count (severity_data,
                                   level_min_severity ("Debug",
                                                       severity_class),
                                   level_max_severity ("Debug",
                                                       severity_class));

  if (false_positives)
    *false_positives
      = severity_data_range_count (severity_data,
                                   level_min_severity ("False Positive",
                                                       severity_class),
                                   level_max_severity ("False Positive",
                                                       severity_class));

  if (logs)
    *logs
      = severity_data_range_count (severity_data,
                                   level_min_severity ("Log",
                                                       severity_class),
                                   level_max_severity ("Log",
                                                       severity_class));

  if (lows)
    *lows
      = severity_data_range_count (severity_data,
                                   level_min_severity ("low",
                                                       severity_class),
                                   level_max_severity ("low",
                                                       severity_class));

  if (mediums)
    *mediums
      = severity_data_range_count (severity_data,
                                   level_min_severity ("medium",
                                                       severity_class),
                                   level_max_severity ("medium",
                                                       severity_class));

  if (highs)
    *highs
      = severity_data_range_count (severity_data,
                                   level_min_severity ("high",
                                                       severity_class),
                                   level_max_severity ("high",
                                                       severity_class));
}


/* Task globals. */

/**
 * @brief Scanner available flag.
 */
short scanner_up = 1;

/**
 * @brief Scanner active flag.
 *
 * This indicates whether the scanner is doing something that the manager
 * must wait for.  Set, for example, by \ref start_task.  If this variable
 * is true then the manager keeps the management process alive until the
 * scanner closes its connection, even if the client closes its connection.
 */
short scanner_active = 0;

/**
 * @brief The task currently running on the scanner.
 */
/*@null@*/ task_t current_scanner_task = (task_t) 0;

/**
 * @brief The report of the current task.
 */
report_t current_report = (report_t) 0;


/* Alerts. */

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
      case ALERT_CONDITION_SEVERITY_AT_LEAST:
        return "Severity at least";
      case ALERT_CONDITION_SEVERITY_CHANGED:
        return "Severity changed";
      default:
        return "Internal Error";
    }
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
      default:                            return "Internal Error";
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
      default:
        return g_strdup ("Internal Error");
    }
}

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
      case ALERT_METHOD_SOURCEFIRE:  return "Sourcefire Connector";
      case ALERT_METHOD_SYSLOG:      return "Syslog";
      case ALERT_METHOD_VERINICE:    return "verinice Connector";
      default:                       return "Internal Error";
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
  if (strcasecmp (name, "Severity at least") == 0)
    return ALERT_CONDITION_SEVERITY_AT_LEAST;
  if (strcasecmp (name, "Severity changed") == 0)
    return ALERT_CONDITION_SEVERITY_CHANGED;
  return ALERT_CONDITION_ERROR;
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
  return EVENT_ERROR;
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
  if (strcasecmp (name, "Sourcefire Connector") == 0)
    return ALERT_METHOD_SOURCEFIRE;
  if (strcasecmp (name, "Syslog") == 0)
    return ALERT_METHOD_SYSLOG;
  if (strcasecmp (name, "verinice Connector") == 0)
    return ALERT_METHOD_VERINICE;
  return ALERT_METHOD_ERROR;
}


/* General task facilities. */

/**
 * @brief Get the name of a run status.
 *
 * @param[in]  status  Run status.
 *
 * @return The name of the status (for example, "Done" or "Running").
 */
const char*
run_status_name (task_status_t status)
{
  switch (status)
    {
      case TASK_STATUS_DELETE_REQUESTED:
      case TASK_STATUS_DELETE_WAITING:
        return "Delete Requested";
      case TASK_STATUS_DELETE_ULTIMATE_REQUESTED:
      case TASK_STATUS_DELETE_ULTIMATE_WAITING:
        return "Ultimate Delete Requested";
      case TASK_STATUS_DONE:             return "Done";
      case TASK_STATUS_NEW:              return "New";

      case TASK_STATUS_PAUSE_REQUESTED:
      case TASK_STATUS_PAUSE_WAITING:
        return "Pause Requested";

      case TASK_STATUS_PAUSED:           return "Paused";
      case TASK_STATUS_REQUESTED:        return "Requested";

      case TASK_STATUS_RESUME_REQUESTED:
      case TASK_STATUS_RESUME_WAITING:
        return "Resume Requested";

      case TASK_STATUS_RUNNING:          return "Running";

      case TASK_STATUS_STOP_REQUESTED_GIVEUP:
      case TASK_STATUS_STOP_REQUESTED:
      case TASK_STATUS_STOP_WAITING:
        return "Stop Requested";

      case TASK_STATUS_STOPPED:          return "Stopped";
      default:                           return "Internal Error";
    }
}

/**
 * @brief Get the unique name of a run status.
 *
 * @param[in]  status  Run status.
 *
 * @return The name of the status (for example, "Done" or "Running").
 */
const char*
run_status_name_internal (task_status_t status)
{
  switch (status)
    {
      case TASK_STATUS_DELETE_REQUESTED: return "Delete Requested";
      case TASK_STATUS_DELETE_ULTIMATE_REQUESTED:
        return "Ultimate Delete Requested";
      case TASK_STATUS_DELETE_ULTIMATE_WAITING:
        return "Ultimate Delete Waiting";
      case TASK_STATUS_DELETE_WAITING:   return "Delete Waiting";
      case TASK_STATUS_DONE:             return "Done";
      case TASK_STATUS_NEW:              return "New";

      case TASK_STATUS_PAUSE_REQUESTED:
        return "Pause Requested";

      case TASK_STATUS_PAUSE_WAITING:
        return "Pause Waiting";

      case TASK_STATUS_PAUSED:           return "Paused";
      case TASK_STATUS_REQUESTED:        return "Requested";

      case TASK_STATUS_RESUME_REQUESTED:
        return "Resume Requested";

      case TASK_STATUS_RESUME_WAITING:
        return "Resume Waiting";

      case TASK_STATUS_RUNNING:          return "Running";

      case TASK_STATUS_STOP_REQUESTED_GIVEUP:
      case TASK_STATUS_STOP_REQUESTED:
        return "Stop Requested";

      case TASK_STATUS_STOP_WAITING:
        return "Stop Waiting";

      case TASK_STATUS_STOPPED:          return "Stopped";
      default:                           return "Internal Error";
    }
}

/**
 * @brief Get the name of the status of a task.
 *
 * @param[in]  task  The task.
 *
 * @return The name of the status of the given task (for example, "Done" or
 *         "Running").
 */
const char*
task_run_status_name (task_t task)
{
  return run_status_name (task_run_status (task));
}

/** @todo Test these RC parsing functions. */

/**
 * @brief Return a preference from an RC.
 *
 * @param[in]  desc  The RC.
 * @param[in]  name  The name of the preference.
 *
 * @return The preference on success, else NULL.
 */
char*
rc_preference (const char* desc, const char* name)
{
  char* seek;

  if (desc == NULL)
    {
      tracef ("   desc NULL\n");
      return NULL;
    }

  while ((seek = strchr (desc, '\n')))
    {
      char* eq = seek
                 ? memchr (desc, '=', seek - desc)
                 : strchr (desc, '=');
      if (eq)
        {
#if 0
          tracef ("   1 found: %.*s\n",
                  seek ? seek - desc : strlen (seek),
                  desc);
#endif
          if (strncmp (desc, name, eq - desc - 1) == 0)
            {
              gchar* ret;
              if (seek > eq + 1)
                ret = g_strndup (eq + 2,
                                 seek ? seek - (eq + 2) : strlen (seek));
              else
                ret = g_strdup ("");
              return ret;
            }
        }
      else if ((seek ? seek - desc > 7 : 1)
               && strncmp (desc, "begin(", 6) == 0)
        {
          /* Read over the section. */
          desc = seek + 1;
          while ((seek = strchr (desc, '\n')))
            {
              if ((seek ? seek - desc > 5 : 1)
                  && strncmp (desc, "end(", 4) == 0)
                {
                  break;
                }
#if 0
              tracef ("   1 skip: %.*s\n",
                      seek ? seek - desc : strlen (seek),
                      desc);
#endif
              desc = seek + 1;
            }
        }
      if (seek == NULL) break;
      desc = seek + 1;
    }
  return NULL;
}

/**
 * @brief Get files to send.
 *
 * @param  task  Task of interest.
 *
 * @return List of files to send, (NULL if none), data has to be freed with
 *         g_free.
 */
static GSList*
get_files_to_send (task_t task)
{
  iterator_t files;
  GSList* filelist = NULL;

  init_task_file_iterator (&files, task, NULL);
  while (next (&files))
    {
      const gchar* file_path = task_file_iterator_name (&files);
      filelist = g_slist_append (filelist, g_strdup (file_path));
    }
  cleanup_iterator (&files);

  return filelist;
}

/**
 * @brief Return the plugins of a config, as a semicolon separated string.
 *
 * @param[in]  config  Config.
 *
 * @return A string of semi-colon separated plugin IDS.
 */
static gchar*
nvt_selector_plugins (config_t config)
{
  GString* plugins = g_string_new ("");
  iterator_t families, nvts;
  gboolean first = TRUE;

  init_family_iterator (&families, 0, NULL, 1);
  while (next (&families))
    {
      const char *family = family_iterator_name (&families);
      if (family)
        {
          init_nvt_iterator (&nvts, 0, config, family, NULL, 1, NULL);
          while (next (&nvts))
            {
              if (first)
                first = FALSE;
              else
                g_string_append_c (plugins, ';');
              g_string_append (plugins, nvt_iterator_oid (&nvts));
            }
          cleanup_iterator (&nvts);
        }
    }
  cleanup_iterator (&families);

  /* Always add all settings NVTs onto list. */
  init_nvt_iterator (&nvts, 0, 0, 0, "2", 1, NULL);
  while (next (&nvts))
    {
      if (first)
        first = FALSE;
      else
        g_string_append_c (plugins, ';');
      g_string_append (plugins, nvt_iterator_oid (&nvts));
    }
  cleanup_iterator (&nvts);

  return g_string_free (plugins, FALSE);
}

/**
 * @brief Return the real value of a preference.
 *
 * Take care of radio button options.
 *
 * @param[in]  name        Name of preference.
 * @param[in]  full_value  Entire value of preference.
 *
 * @return Real value of the preference.
 */
static gchar*
preference_value (const char* name, const char* full_value)
{
  char *bracket = strchr (name, '[');
  if (bracket)
    {
      if (strncmp (bracket, "[radio]:", strlen ("[radio]:")) == 0)
        {
          char *semicolon = strchr (full_value, ';');
          if (semicolon)
            return g_strndup (full_value, semicolon - full_value);
        }
    }
  return g_strdup (full_value);
}

/**
 * @brief Send the preferences from a config to the scanner.
 *
 * @param[in]  config        Config.
 * @param[in]  section_name  Name of preference section to send.
 * @param[in]  task_files    Files associated with the task.
 * @param[out] pref_files    Files associated with config (UUID, contents, ...).
 *
 * @return 0 on success, -1 on failure.
 */
static int
send_config_preferences (config_t config, const char* section_name,
                         GSList *task_files, GPtrArray *pref_files)
{
  iterator_t prefs;

  init_otp_pref_iterator (&prefs, config, section_name);
  while (next (&prefs))
    {
      const char *pref_name = otp_pref_iterator_name (&prefs);
      char *value;

      if (strcmp (pref_name, "port_range") == 0)
        continue;

      if (send_to_server (pref_name))
        {
          cleanup_iterator (&prefs);
          return -1;
        }

      if (sendn_to_server (" <|> ", 5))
        {
          cleanup_iterator (&prefs);
          return -1;
        }

      value = preference_value (pref_name,
                                otp_pref_iterator_value (&prefs));

      if (pref_files)
        {
          int type_start = -1, type_end = -1, count;

          /* LDAPsearch[entry]:Timeout value */
          count = sscanf (pref_name, "%*[^[][%n%*[^]]%n]:", &type_start,
                          &type_end);
          if (count == 0
              && type_start > 0
              && type_end > 0
              && (strncmp (pref_name + type_start,
                           "file",
                           type_end - type_start)
                  == 0))
            {
              GSList *head;
              char *uuid;

              /* A "file" preference.
               *
               * If the value of the preference is empty, then send an empty
               * value.
               *
               * If the value of the preference is the name of a task file,
               * then just send the preference value, otherwise send a UUID and
               * add the value to the list of preference files (pref_files). */

              if (strcmp (value, "") == 0)
                {
                  g_free (value);
                  if (sendn_to_server ("\n", 1))
                    {
                      cleanup_iterator (&prefs);
                      return -1;
                    }
                  continue;
                }

              head = task_files;
              while (head)
                {
                  if (strcmp (head->data, value) == 0)
                    break;
                  head = g_slist_next (head);
                }

              if (head == NULL)
                {
                  uuid = openvas_uuid_make ();
                  if (uuid == NULL)
                    {
                      g_free (value);
                      cleanup_iterator (&prefs);
                      return -1;
                    }

                  g_ptr_array_add (pref_files, (gpointer) uuid);
                  g_ptr_array_add (pref_files, (gpointer) value);

                  if (send_to_server (uuid))
                    {
                      free (uuid);
                      g_free (value);
                      cleanup_iterator (&prefs);
                      return -1;
                    }

                  if (sendn_to_server ("\n", 1))
                    {
                      free (uuid);
                      g_free (value);
                      cleanup_iterator (&prefs);
                      return -1;
                    }

                  continue;
                }
            }
        }

      if (send_to_server (value))
        {
          g_free (value);
          cleanup_iterator (&prefs);
          return -1;
        }
      g_free (value);

      if (sendn_to_server ("\n", 1))
        {
          cleanup_iterator (&prefs);
          return -1;
        }
    }
  cleanup_iterator (&prefs);
  return 0;
}

/**
 * @brief Send task preferences to the scanner.
 *
 * @param[in]  task  Task.
 *
 * @return 0 on success, -1 on failure.
 */
static int
send_task_preferences (task_t task)
{
  gchar *value;

  value = task_preference_value (task, "max_checks");
  if (sendf_to_server ("max_checks <|> %s\n",
                       value ? value : MAX_CHECKS_DEFAULT))
    {
      g_free (value);
      return -1;
    }
  g_free (value);

  value = task_preference_value (task, "max_hosts");
  if (sendf_to_server ("max_hosts <|> %s\n",
                       value ? value : MAX_HOSTS_DEFAULT))
    {
      g_free (value);
      return -1;
    }
  g_free (value);

  value = task_preference_value (task, "source_iface");
  if (value && sendf_to_server ("source_iface <|> %s\n", value))
    {
      g_free (value);
      return -1;
    }
  g_free (value);

  return 0;
}

/**
 * @brief Send ifaces_allow and ifaces_deny preferences to scanner.
 *
 * @return 0 on success, -1 on failure.
 */
static int
send_ifaces_access_preferences (void)
{
  char *ifaces;
  int ifaces_allow;

  ifaces = sql_string (0, 0,
                       "SELECT ifaces FROM users WHERE uuid = '%s';",
                       current_credentials.uuid);
  ifaces_allow = sql_int (0, 0,
                          "SELECT ifaces_allow FROM users WHERE uuid = '%s';",
                          current_credentials.uuid);

  if (ifaces && strlen (ifaces))
    {
      char *pref;

      if (ifaces_allow == 1)
        pref = "ifaces_allow";
      else if (ifaces_allow == 0)
        pref = "ifaces_deny";
      else
        {
          g_free (ifaces);
          return 0;
        }

      if (sendf_to_server ("%s <|> %s\n", pref, ifaces))
        {
          g_free (ifaces);
          return -1;
        }
    }
  return 0;
}

/**
 * @brief Send ifaces_allow and ifaces_deny preferences to scanner.
 *
 * @return 0 on success, -1 on failure.
 */
static int
send_hosts_access_preferences (void)
{
  char *hosts;
  int hosts_allow;

  hosts = sql_string (0, 0,
                       "SELECT hosts FROM users WHERE uuid = '%s';",
                       current_credentials.uuid);
  hosts_allow = sql_int (0, 0,
                          "SELECT hosts_allow FROM users WHERE uuid = '%s';",
                          current_credentials.uuid);

  if (hosts && strlen (hosts))
    {
      char *pref;

      if (hosts_allow == 1)
        pref = "hosts_allow";
      else if (hosts_allow == 0)
        pref = "hosts_deny";
      else
        {
          g_free (hosts);
          return 0;
        }

      if (sendf_to_server ("%s <|> %s\n", pref, hosts))
        {
          g_free (hosts);
          return -1;
        }
    }
  return 0;
}

/**
 * @brief Gives a comma-separated list of a report's finished hosts.
 *
 * @return String of finished hosts if found, NULL otherwise.
 */
static char *
finished_hosts_str (report_t stopped_report)
{
  iterator_t hosts;
  char *str = NULL;

  if (stopped_report == 0)
    return NULL;
  init_host_iterator (&hosts, stopped_report, NULL, 0);
  while (next (&hosts))
    {
      const char *end_time = host_iterator_end_time (&hosts);

      if (end_time && strlen (end_time))
        {
          char *new_str = str ?
                           g_strdup_printf ("%s, %s", str,
                                            host_iterator_host (&hosts))
                           : g_strdup_printf ("%s",
                                              host_iterator_host (&hosts));
          g_free (str);
          str = new_str;
        }
    }
  return str;
}

/**
 * @brief Send some scanner preferences to the scanner.
 *
 * @param[in]  task            Task.
 * @param[in]  target          Scan target.
 * @param[in]  stopped_report  Previously stoppped report, if any, else 0.
 *
 * @return 0 on success, -1 on failure.
 */
static int
send_scanner_preferences (task_t task, target_t target, report_t stopped_report)
{
  char *hosts_ordering, *exclude_hosts, *reverse_lookup_only;
  char *reverse_lookup_unify;

  /* Send ifaces_allow / ifaces_deny preferences. */
  if (send_ifaces_access_preferences ())
    return -1;

  /* Send hosts_allow / hosts_deny preferences. */
  if (send_hosts_access_preferences ())
    return -1;

  /* Send hosts_ordering preference. */
  hosts_ordering = task_hosts_ordering (task);
  if (hosts_ordering)
    {
      if (sendf_to_server ("hosts_ordering <|> %s\n", hosts_ordering))
        {
          free (hosts_ordering);
          return -1;
        }
      free (hosts_ordering);
    }

  /* Send exclude_hosts preference. */
  exclude_hosts = target_exclude_hosts (target);
  if (exclude_hosts)
    {
      char *finished, *str;

      finished = finished_hosts_str (stopped_report);
      if (finished)
        {
          str = g_strdup_printf ("%s, %s", exclude_hosts, finished);
          g_free (exclude_hosts);
          g_free (finished);
          exclude_hosts = str;
        }
    }
  else
    exclude_hosts = finished_hosts_str (stopped_report);

  if (exclude_hosts)
    {
      if (sendf_to_server ("exclude_hosts <|> %s\n", exclude_hosts))
        {
          free (exclude_hosts);
          return -1;
        }
      free (exclude_hosts);
    }

  /* Send reverse_lookup_only preference. */
  reverse_lookup_only = target_reverse_lookup_only (target);
  if (reverse_lookup_only == NULL || strcmp (reverse_lookup_only, "0") == 0)
    reverse_lookup_only = "no";
  else
    reverse_lookup_only = "yes";
  if (sendf_to_server ("reverse_lookup_only <|> %s\n", reverse_lookup_only))
    return -1;

  /* Send reverse_lookup_unify preference. */
  reverse_lookup_unify = target_reverse_lookup_unify (target);
  if (reverse_lookup_unify == NULL || strcmp (reverse_lookup_unify, "0") == 0)
    reverse_lookup_unify = "no";
  else
    reverse_lookup_unify = "yes";
  if (sendf_to_server ("reverse_lookup_unify <|> %s\n", reverse_lookup_unify))
    return -1;

  return 0;
}

/**
 * @brief Send a file to the scanner.
 *
 * @param[in]  name     File name.
 * @param[in]  content  File contents.
 *
 * @return 0 on success, -1 on failure.
 */
static int
send_file (const char* name, const char* content)
{
  size_t content_len = strlen (content);

  if (sendf_to_server ("CLIENT <|> ATTACHED_FILE\n"
                       "name: %s\n"
                       "content: octet/stream\n"
                       "bytes: %i\n",
                       name,
                       content_len))
    return -1;

  if (sendn_to_server (content, content_len))
    return -1;

  return 0;
}

/**
 * @brief Send a file from a task to the scanner.
 *
 * @param[in]  task  The task.
 * @param[in]  file  File name.
 *
 * @return 0 on success, -1 on failure.
 */
static int
send_task_file (task_t task, const char* file)
{
  iterator_t files;

  init_task_file_iterator (&files, task, file);
  while (next (&files))
    {
      gsize content_len;
      guchar *content;
      const char *content_64 = task_file_iterator_content (&files);

      content = g_base64_decode (content_64, &content_len);

      if (sendf_to_server ("CLIENT <|> ATTACHED_FILE\n"
                           "name: %s\n"
                           "content: octet/stream\n"
                           "bytes: %i\n",
                           file,
                           content_len))
        {
          g_free (content);
          cleanup_iterator (&files);
          return -1;
        }

      if (sendn_to_server (content, content_len))
        {
          g_free (content);
          cleanup_iterator (&files);
          return -1;
        }
      g_free (content);
    }
  cleanup_iterator (&files);
  return 0;
}

/**
 * @brief Send target "Alive Test" preferences to the scanner.
 *
 * @param[in]  target   Scan target.
 *
 * @return 0 on success, -1 on failure.
 */
static int
send_alive_test_preferences (target_t target)
{
  alive_test_t alive_test;

  alive_test = target_alive_tests (target);

  if (alive_test == 0)
    return 0;

  if (sendf_to_server ("Ping Host[checkbox]:Do a TCP ping <|> %s\n",
                       alive_test & ALIVE_TEST_TCP_ACK_SERVICE
                       || alive_test & ALIVE_TEST_TCP_SYN_SERVICE
                        ? "yes"
                        : "no"))
    return -1;

  if (sendf_to_server ("Ping Host[checkbox]:TCP ping tries also TCP-SYN ping"
                       " <|> %s\n",
                       alive_test & ALIVE_TEST_TCP_SYN_SERVICE
                        ? "yes"
                        : "no"))
    return -1;

  if (sendf_to_server ("Ping Host[checkbox]:Do an ICMP ping <|> %s\n",
                       alive_test & ALIVE_TEST_ICMP
                        ? "yes"
                        : "no"))
    return -1;

  if (sendf_to_server ("Ping Host[checkbox]:Use ARP <|> %s\n",
                       alive_test & ALIVE_TEST_ARP
                        ? "yes"
                        : "no"))
    return -1;

  if (sendf_to_server ("Ping Host[checkbox]:"
                       "Mark unrechable Hosts as dead (not scanning) <|> %s\n",
                       alive_test & ALIVE_TEST_CONSIDER_ALIVE
                        ? "no"
                        : "yes"))
    return -1;

  if (alive_test == ALIVE_TEST_CONSIDER_ALIVE)
    {
      /* Also select a method, otherwise Ping Host logs a warning. */
      if (sendf_to_server ("Ping Host[checkbox]:Do a TCP ping <|> yes\n"))
        return -1;
    }

  return 0;
}

/** @todo g_convert back to ISO-8559-1 for scanner? */

/**
 * @brief Free an slist of pointers, including the pointers.
 *
 * @param[in]  list  The list.
 */
/** @todo Duplicate in openvas_string module (openvas_string_list_free) .
  *       Find proper module to place this function. */
void
slist_free (GSList* list)
{
  GSList *head = list;
  while (list)
    {
      g_free (list->data);
      list = g_slist_next (list);
    }
  g_slist_free (head);
}

/**
 * @brief Update the locally cached task progress from the slave.
 *
 * @param[in]  get_tasks  Slave GET_TASKS response.
 *
 * @return 0 success, -1 error.
 */
int
update_slave_progress (entity_t get_tasks)
{
  entity_t entity;

  entity = entity_child (get_tasks, "task");
  if (entity == NULL)
    return -1;
  entity = entity_child (entity, "progress");
  if (entity == NULL)
    return -1;

  if (current_report == 0)
    return -1;

  set_report_slave_progress (current_report,
                             atoi (entity_text (entity)));

  return 0;
}

/**
 * @brief Authenticate with a slave.
 *
 * @param[in]  session  GNUTLS session.
 * @param[in]  slave    Slave.
 *
 * @return 0 success, -1 error.
 */
int
slave_authenticate (gnutls_session_t *session, slave_t slave)
{
  int ret;
  gchar *login, *password;

  login = slave_login (slave);
  if (login == NULL)
    return -1;

  password = slave_password (slave);
  if (password == NULL)
    {
      g_free (login);
      return -1;
    }

  ret = omp_authenticate (session, login, password);
  g_free (login);
  g_free (password);
  if (ret)
    return -1;
  return 0;
}

/* Defined in omp.c. */
void buffer_config_preference_xml (GString *, iterator_t *, config_t, int);


/**
 * @brief Number of seconds to sleep between polls to slave.
 */
#define RUN_SLAVE_TASK_SLEEP_SECONDS 25

/**
 * @brief Connect to a slave.
 *
 * @param[in]   slave    Slave.
 * @param[in]   host     Host.
 * @param[out]  port     Port.
 * @param[out]  socket   Socket.
 * @param[out]  session  Session.
 *
 * @return 0 success, -1 error, 1 auth failure.
 */
static int
slave_connect (slave_t slave, const char *host, int port, int *socket,
               gnutls_session_t *session)
{
  *socket = openvas_server_open (session, host, port);
  if (*socket == -1)
    return -1;

  {
    int optval;
    optval = 1;
    if (setsockopt (*socket,
                    SOL_SOCKET, SO_KEEPALIVE,
                    &optval, sizeof (int)))
      {
        g_warning ("%s: failed to set SO_KEEPALIVE on slave socket: %s\n",
                   __FUNCTION__,
                   strerror (errno));
        openvas_server_close (*socket, *session);
        return -1;
      }
  }

  tracef ("   %s: connected\n", __FUNCTION__);

  /* Authenticate using the slave login. */

  if (slave_authenticate (session, slave))
    {
      openvas_server_close (*socket, *session);
      return 1;
    }

  tracef ("   %s: authenticated\n", __FUNCTION__);

  return 0;
}

/**
 * @brief Sleep then connect to slave.  Retry until success or giveup requested.
 *
 * @param[in]   slave    Slave.
 * @param[in]   host     Host.
 * @param[in]   port     Port.
 * @param[in]   task     Local task.
 * @param[out]  socket   Socket.
 * @param[out]  session  Session.
 *
 * @return 0 success, 3 giveup.
 */
static int
slave_sleep_connect (slave_t slave, const char *host, int port, task_t task,
                     int *socket, gnutls_session_t *session)
{
  do
    {
      if (task_run_status (task) == TASK_STATUS_STOP_REQUESTED_GIVEUP)
        {
          tracef ("   %s: task stopped for giveup\n", __FUNCTION__);
          set_task_run_status (current_scanner_task, TASK_STATUS_STOPPED);
          return 3;
        }
      sleep (RUN_SLAVE_TASK_SLEEP_SECONDS);
    }
  while (slave_connect (slave, host, port, socket, session));
  return 0;
}

/**
 * @brief Update end times, and optionally add host details.
 *
 * @param[in]  report            Report.
 * @param[in]  add_host_details  Whether to add host details.
 *
 * @return 0 success, -1 error.
 */
static int
update_end_times (entity_t report, int add_host_details)
{
  entity_t end;
  entities_t entities;

  /* Set the scan end time. */

  entities = report->entities;
  while ((end = first_entity (entities)))
    {
      if (strcmp (entity_name (end), "scan_end") == 0)
        {
          char *text;
          text = entity_text (end);
          while (*text && isspace (*text)) text++;
          if (*text == '\0')
            break;
          set_task_end_time (current_scanner_task,
                             g_strdup (entity_text (end)));
          set_scan_end_time (current_report, entity_text (end));
          break;
        }
      entities = next_entities (entities);
    }

  /* Add host details and set the host end times. */

  entities = report->entities;
  while ((end = first_entity (entities)))
    {
      if (strcmp (entity_name (end), "host_end") == 0)
        {
          entity_t host;
          char *text;

          /* Set the end time this way first, in case the slave is
           * very old. */

          host = entity_child (end, "host");
          if (host == NULL)
            return -1;

          text = entity_text (end);
          while (*text && isspace (*text)) text++;
          if (*text != '\0')
            set_scan_host_end_time (current_report,
                                    entity_text (host),
                                    entity_text (end));
        }

      if (strcmp (entity_name (end), "host") == 0)
        {
          entity_t ip, time;
          char *text;

          ip = entity_child (end, "ip");
          if (ip == NULL)
            return -1;

          time = entity_child (end, "end");
          if (time == NULL)
            return -1;

          text = entity_text (time);
          while (*text && isspace (*text)) text++;
          if (*text != '\0')
            set_scan_host_end_time (current_report,
                                    entity_text (ip),
                                    entity_text (time));
          if (add_host_details
              && manage_report_host_details (current_report,
                                             entity_text (ip),
                                             end))
            return -1;
        }

      entities = next_entities (entities);
    }

  return 0;
}

/**
 * @brief Slave credential UUID.
 */
gchar *slave_ssh_credential_uuid = NULL;

/**
 * @brief Slave credential UUID.
 */
gchar *slave_smb_credential_uuid = NULL;

/**
 * @brief Slave target UUID.
 */
gchar *slave_target_uuid = NULL;

/**
 * @brief Slave config UUID.
 */
gchar *slave_config_uuid = NULL;

/**
 * @brief Slave task UUID.
 */
gchar *slave_task_uuid = NULL;

/**
 * @brief Slave report UUID.
 */
gchar *slave_report_uuid = NULL;

/**
 * @brief Slave session.
 */
gnutls_session_t *slave_session = NULL;

/**
 * @brief Slave socket.
 */
int *slave_socket = NULL;

/**
 * @brief Cleanup slave.  Callback for atexit.
 */
static void
cleanup_slave ()
{
  if (slave_session && slave_socket)
    {
      if (slave_task_uuid)
        omp_stop_task (slave_session, slave_task_uuid);
      openvas_server_close (*slave_socket, *slave_session);
    }
}

/**
 * @brief Setup a task on a slave.
 *
 * @param[in]   slave       Slave.
 * @param[in]   session     Session.
 * @param[in]   socket      Socket.
 * @param[in]   name        Name of task on slave.
 * @param[in]   host        Slave host.
 * @param[in]   port        Slave host port.
 * @param[in]   task        The task.
 * @param[out]  target      Task target.
 * @param[out]  target_ssh_credential    Target SSH credential.
 * @param[out]  target_smb_credential    Target SMB credential.
 * @param[out]  last_stopped_report  Last stopped report if any, else 0.
 *
 * @return 0 success, 1 retry, 3 giveup.
 */
static int
slave_setup (slave_t slave, gnutls_session_t *session, int *socket,
             const char *name, const char *host, int port, task_t task,
             target_t target, lsc_credential_t target_ssh_credential,
             lsc_credential_t target_smb_credential,
             report_t last_stopped_report)
{
  int ret, next_result;
  iterator_t credentials, targets;

  omp_delete_opts_t del_opts = omp_delete_opts_ultimate_defaults;

  slave_session = session;
  slave_socket = socket;

  /* Register a cleanup callback to stop the slave task if the process is
   * killed, for example by a reboot.  On restart Manager will set the task
   * status to Stopped, which will match the slave. */
  if (atexit (&cleanup_slave))
    {
      g_critical ("%s: failed to register `atexit' slave_cleanup function\n",
                  __FUNCTION__);
      goto fail;
    }

  if (last_stopped_report)
    {
      /* Resume the task on the slave. */

      slave_task_uuid = report_slave_task_uuid (last_stopped_report);
      if (slave_task_uuid == NULL)
        {
          /* This may happen if someone sets a slave on a local task.  Clear
           * all the report results and start the task from the beginning.  */
          trim_report (last_stopped_report);
          last_stopped_report = 0;
        }
      else switch (omp_resume_stopped_task_report (session, slave_task_uuid,
                                                   &slave_report_uuid))
        {
          case 0:
            if (slave_report_uuid == NULL)
              goto fail;
            set_task_run_status (task, TASK_STATUS_REQUESTED);
            break;
          case 1:
            /* The resume may have failed because the task slave changed or
             * because someone removed the task on the slave.  Clear all the
             * report results and start the task from the beginning.
             *
             * This and the if above both "leak" the resources on the slave,
             * because on the report these resources are replaced with the new
             * resources. */
            trim_report (last_stopped_report);
            last_stopped_report = 0;
            break;
          default:
            free (slave_task_uuid);
            goto fail;
        }
    }

  if (last_stopped_report == 0)
    {
      /* Create the target credentials on the slave. */

      if (target_ssh_credential)
        {
          init_user_lsc_credential_iterator (&credentials,
                                             target_ssh_credential, 0,
                                             1, NULL);
          if (next (&credentials))
            {
              const char *user, *password, *public_key, *private_key;
              gchar *user_copy, *password_copy;

              user = lsc_credential_iterator_login (&credentials);
              password = lsc_credential_iterator_password (&credentials);
              public_key = lsc_credential_iterator_public_key (&credentials);
              private_key = lsc_credential_iterator_private_key (&credentials);

              if (user == NULL
                  || (public_key == NULL && password == NULL))
                {
                  cleanup_iterator (&credentials);
                  goto fail;
                }

              if (public_key)
                ret = omp_create_lsc_credential_key
                       (session, name, user, password, public_key, private_key,
                        "Slave SSH credential created by Master",
                        &slave_ssh_credential_uuid);
              else
                {
                  user_copy = g_strdup (user);
                  password_copy = g_strdup (password);
                  cleanup_iterator (&credentials);

                  ret = omp_create_lsc_credential
                         (session, name, user_copy, password_copy,
                          "Slave SSH credential created by Master",
                          &slave_ssh_credential_uuid);
                  g_free (user_copy);
                  g_free (password_copy);
                }
              if (ret)
                goto fail;
            }
        }

      if (target_smb_credential)
        {
          init_user_lsc_credential_iterator (&credentials,
                                             target_smb_credential, 0,
                                             1, NULL);
          if (next (&credentials))
            {
              const char *user, *password;
              gchar *user_copy, *password_copy, *smb_name;

              user = lsc_credential_iterator_login (&credentials);
              password = lsc_credential_iterator_password (&credentials);

              if (user == NULL || password == NULL)
                {
                  cleanup_iterator (&credentials);
                  goto fail_ssh_credential;
                }

              user_copy = g_strdup (user);
              password_copy = g_strdup (password);
              cleanup_iterator (&credentials);

              smb_name = g_strdup_printf ("%ssmb", name);
              ret = omp_create_lsc_credential
                     (session, smb_name, user_copy, password_copy,
                      "Slave SMB credential created by Master",
                      &slave_smb_credential_uuid);
              g_free (smb_name);
              g_free (user_copy);
              g_free (password_copy);
              if (ret)
                goto fail_ssh_credential;
            }
        }

      tracef ("   %s: slave SSH credential uuid: %s\n", __FUNCTION__,
              slave_ssh_credential_uuid);

      tracef ("   %s: slave SMB credential uuid: %s\n", __FUNCTION__,
              slave_smb_credential_uuid);

      /* Create the target on the slave. */

      init_user_target_iterator (&targets, target);
      if (next (&targets))
        {
          const char *hosts, *port, *exclude_hosts, *alive_tests;
          const char *reverse_lookup_only, *reverse_lookup_unify;
          gchar *hosts_copy, *exclude_hosts_copy;
          gchar *alive_tests_copy, *port_range;
          omp_create_target_opts_t opts;
          int ssh_port;

          hosts = target_iterator_hosts (&targets);
          exclude_hosts = target_iterator_exclude_hosts (&targets);
          alive_tests = target_iterator_alive_tests (&targets);
          reverse_lookup_only
            = target_iterator_reverse_lookup_only (&targets);
          reverse_lookup_unify
            = target_iterator_reverse_lookup_unify (&targets);
          if (hosts == NULL)
            {
              cleanup_iterator (&targets);
              goto fail_smb_credential;
            }

          port = target_iterator_ssh_port (&targets);
          if (port == NULL)
            ssh_port = 0;
          else
            ssh_port = atoi (port);

          hosts_copy = g_strdup (hosts);
          exclude_hosts_copy = g_strdup (exclude_hosts);
          alive_tests_copy = g_strdup (alive_tests);
          port_range = target_port_range (target_iterator_target (&targets));
          cleanup_iterator (&targets);

          opts = omp_create_target_opts_defaults;
          opts.hosts = hosts_copy;
          opts.exclude_hosts = exclude_hosts_copy;
          opts.alive_tests = alive_tests_copy;
          opts.ssh_credential_id = slave_ssh_credential_uuid;
          opts.ssh_credential_port = ssh_port;
          opts.smb_credential_id = slave_smb_credential_uuid;
          opts.port_range = port_range;
          opts.name = name;
          opts.comment = "Slave target created by Master";
          opts.reverse_lookup_only
            = reverse_lookup_only ? atoi (reverse_lookup_only) : 0;
          opts.reverse_lookup_unify
            = reverse_lookup_unify ? atoi (reverse_lookup_unify) : 0;

          ret = omp_create_target_ext (session, opts, &slave_target_uuid);
          g_free (hosts_copy);
          g_free (exclude_hosts_copy);
          g_free (alive_tests_copy);
          g_free (port_range);
          if (ret)
            goto fail_smb_credential;
        }
      else
        {
          cleanup_iterator (&targets);
          goto fail_smb_credential;
        }

      tracef ("   %s: slave target uuid: %s\n", __FUNCTION__, slave_target_uuid);

      /* Create the config on the slave. */

      {
        config_t config;
        iterator_t prefs, selectors;

        /* This must follow the GET_CONFIGS_RESPONSE export case. */

        config = task_config (task);
        if (config == 0)
          goto fail_target;

        if (openvas_server_sendf (session,
                                  "<create_config>"
                                  "<get_configs_response"
                                  " status=\"200\""
                                  " status_text=\"OK\">"
                                  "<config id=\"XXX\">"
                                  "<name>%s</name>"
                                  "<comment>"
                                  "Slave config created by Master"
                                  "</comment>"
                                  "<preferences>",
                                  name))
          goto fail_target;

        /* Send NVT timeout preferences where a timeout has been
         * specified. */
        init_config_timeout_iterator (&prefs, config);
        while (next (&prefs))
          {
            const char *timeout;

            timeout = config_timeout_iterator_value (&prefs);

            if (timeout && strlen (timeout)
                && openvas_server_sendf (session,
                                         "<preference>"
                                         "<nvt oid=\"%s\">"
                                         "<name>%s</name>"
                                         "</nvt>"
                                         "<name>Timeout</name>"
                                         "<type>entry</type>"
                                         "<value>%s</value>"
                                         "</preference>",
                                         config_timeout_iterator_oid (&prefs),
                                         config_timeout_iterator_nvt_name (&prefs),
                                         timeout))
              {
                cleanup_iterator (&prefs);
                goto fail_target;
              }
          }
        cleanup_iterator (&prefs);

        init_nvt_preference_iterator (&prefs, NULL);
        while (next (&prefs))
          {
            GString *buffer = g_string_new ("");
            buffer_config_preference_xml (buffer, &prefs, config, 0);
            if (openvas_server_send (session, buffer->str))
              {
                cleanup_iterator (&prefs);
                goto fail_target;
              }
            g_string_free (buffer, TRUE);
          }
        cleanup_iterator (&prefs);

        if (openvas_server_send (session,
                                 "</preferences>"
                                 "<nvt_selectors>"))
          {
            cleanup_iterator (&prefs);
            goto fail_target;
          }

        init_nvt_selector_iterator (&selectors,
                                    NULL,
                                    config,
                                    NVT_SELECTOR_TYPE_ANY);
        while (next (&selectors))
          {
            int type = nvt_selector_iterator_type (&selectors);
            if (openvas_server_sendf
                 (session,
                  "<nvt_selector>"
                  "<name>%s</name>"
                  "<include>%i</include>"
                  "<type>%i</type>"
                  "<family_or_nvt>%s</family_or_nvt>"
                  "</nvt_selector>",
                  nvt_selector_iterator_name (&selectors),
                  nvt_selector_iterator_include (&selectors),
                  type,
                  (type == NVT_SELECTOR_TYPE_ALL
                    ? ""
                    : nvt_selector_iterator_nvt (&selectors))))
              goto fail_target;
          }
        cleanup_iterator (&selectors);

        if (openvas_server_send (session,
                                 "</nvt_selectors>"
                                 "</config>"
                                 "</get_configs_response>"
                                 "</create_config>")
            || (omp_read_create_response (session, &slave_config_uuid) != 201))
          goto fail_target;
      }

      tracef ("   %s: slave config uuid: %s\n", __FUNCTION__, slave_config_uuid);

      /* Create the task on the slave. */

      {
        gchar *in_assets, *max_checks, *max_hosts, *source_iface;
        gchar *hosts_ordering;
        omp_create_task_opts_t opts;

        opts = omp_create_task_opts_defaults;
        opts.config_id = slave_config_uuid;
        opts.target_id = slave_target_uuid;
        opts.name = name;
        opts.comment = "Slave task created by Master";

        in_assets = task_preference_value (task, "in_assets");
        max_checks = task_preference_value (task, "max_checks");
        max_hosts = task_preference_value (task, "max_hosts");
        source_iface = task_preference_value (task, "source_iface");
        hosts_ordering = task_hosts_ordering (task);

        opts.alterable = 0;
        opts.in_assets = in_assets;
        opts.max_checks = max_checks ? max_checks : MAX_CHECKS_DEFAULT;
        opts.max_hosts = max_hosts ? max_hosts : MAX_HOSTS_DEFAULT;
        opts.source_iface = source_iface;
        opts.hosts_ordering = hosts_ordering;

        opts.alert_ids = NULL;
        opts.observers = NULL;
        opts.observer_groups = NULL;
        opts.schedule_id = NULL;
        opts.slave_id = NULL;

        ret = omp_create_task_ext (session, opts, &slave_task_uuid);
        g_free (in_assets);
        g_free (max_checks);
        g_free (max_hosts);
        g_free (source_iface);
        g_free (hosts_ordering);
        if (ret)
          goto fail_config;
      }

      /* Start the task on the slave. */

      if (omp_start_task_report (session, slave_task_uuid, &slave_report_uuid))
        goto fail_task;
      if (slave_report_uuid == NULL)
        goto fail_stop_task;

      set_report_slave_task_uuid (current_report, slave_task_uuid);
    }

  /* Setup the current task for functions like set_task_run_status. */

  current_scanner_task = task;

  /* Poll the slave until the task is finished. */

  next_result = 1;
  while (1)
    {
      entity_t get_tasks, report, get_report;
      const char *status;
      task_status_t run_status;

      /* Check if some other process changed the task status. */

      run_status = task_run_status (task);
      switch (run_status)
        {
          case TASK_STATUS_PAUSE_REQUESTED:
            switch (omp_pause_task (session, slave_task_uuid))
              {
                case 0:
                  break;
                case 404:
                  /* Resource Missing. */
                  tracef ("   %s: task missing on slave\n", __FUNCTION__);
                  set_task_run_status (task, TASK_STATUS_INTERNAL_ERROR);
                  goto giveup;
                default:
                  goto fail_stop_task;
              }
            set_task_run_status (current_scanner_task,
                                 TASK_STATUS_PAUSE_WAITING);
            break;
          case TASK_STATUS_RESUME_REQUESTED:
            switch (omp_resume_paused_task (session, slave_task_uuid))
              {
                case 0:
                  break;
                case 404:
                  /* Resource Missing. */
                  tracef ("   %s: task missing on slave\n", __FUNCTION__);
                  set_task_run_status (task, TASK_STATUS_INTERNAL_ERROR);
                  goto giveup;
                default:
                  goto fail_stop_task;
              }
            set_task_run_status (current_scanner_task,
                                 TASK_STATUS_RESUME_WAITING);
            break;
          case TASK_STATUS_DELETE_REQUESTED:
          case TASK_STATUS_DELETE_ULTIMATE_REQUESTED:
          case TASK_STATUS_STOP_REQUESTED:
            switch (omp_stop_task (session, slave_task_uuid))
              {
                case 0:
                  break;
                case 404:
                  if (ret == 404)
                    {
                      /* Resource Missing. */
                      tracef ("   %s: task missing on slave\n", __FUNCTION__);
                      set_task_run_status (task, TASK_STATUS_INTERNAL_ERROR);
                      goto giveup;
                    }
                  break;
                default:
                  goto fail_stop_task;
              }
            if (run_status == TASK_STATUS_DELETE_REQUESTED)
              set_task_run_status (current_scanner_task,
                                   TASK_STATUS_DELETE_WAITING);
            else if (run_status == TASK_STATUS_DELETE_ULTIMATE_REQUESTED)
              set_task_run_status (current_scanner_task,
                                   TASK_STATUS_DELETE_ULTIMATE_WAITING);
            else
              set_task_run_status (current_scanner_task,
                                   TASK_STATUS_STOP_WAITING);
            break;
          case TASK_STATUS_STOP_REQUESTED_GIVEUP:
            tracef ("   %s: task stopped for giveup\n", __FUNCTION__);
            set_task_run_status (current_scanner_task, TASK_STATUS_STOPPED);
            goto giveup;
            break;
          case TASK_STATUS_PAUSED:
            /* Keep doing the status checks even though the task is paused, in
             * case someone resumes the task on the slave. */
            break;
          case TASK_STATUS_STOPPED:
            assert (0);
            goto fail_stop_task;
            break;
          case TASK_STATUS_PAUSE_WAITING:
          case TASK_STATUS_RESUME_WAITING:
          case TASK_STATUS_DELETE_WAITING:
          case TASK_STATUS_DELETE_ULTIMATE_WAITING:
          case TASK_STATUS_DONE:
          case TASK_STATUS_NEW:
          case TASK_STATUS_REQUESTED:
          case TASK_STATUS_RUNNING:
          case TASK_STATUS_STOP_WAITING:
          case TASK_STATUS_INTERNAL_ERROR:
            break;
        }

      ret = omp_get_tasks (session, slave_task_uuid, 0, 0, &get_tasks);
      if (ret == 404)
        {
          /* Resource Missing. */
          tracef ("   %s: task missing on slave\n", __FUNCTION__);
          set_task_run_status (task, TASK_STATUS_INTERNAL_ERROR);
          goto giveup;
        }
      else if (ret)
        {
          openvas_server_close (*socket, *session);
          ret = slave_sleep_connect (slave, host, port, task, socket, session);
          if (ret == 3)
            goto giveup;
          continue;
        }

      status = omp_task_status (get_tasks);
      if (status == NULL)
        {
          tracef ("   %s: status was NULL\n", __FUNCTION__);
          set_task_run_status (task, TASK_STATUS_INTERNAL_ERROR);
          goto giveup;
        }
      if ((strcmp (status, "Running") == 0)
          || (strcmp (status, "Done") == 0))
        {
          int ret2;
          omp_get_report_opts_t opts;

          if ((run_status == TASK_STATUS_REQUESTED)
              || (run_status == TASK_STATUS_RESUME_WAITING)
              /* In case someone resumes the task on the slave. */
              || (run_status == TASK_STATUS_PAUSED))
            set_task_run_status (task, TASK_STATUS_RUNNING);

          if ((strcmp (status, "Running") == 0)
              && update_slave_progress (get_tasks))
            {
              free_entity (get_tasks);
              goto fail_stop_task;
            }

          opts = omp_get_report_opts_defaults;
          opts.report_id = slave_report_uuid;
          opts.first_result = next_result;
          opts.format_id = "a994b278-1f62-11e1-96ac-406186ea4fc5";
          opts.apply_overrides = 0;
          opts.levels = "hmlgd";

          if (strcmp (status, "Done") == 0)
            /* Request all the hosts to get their end times. */
            opts.result_hosts_only = 0;
          else
            opts.result_hosts_only = 1;

          ret = omp_get_report_ext (session, opts, &get_report);
          if (ret)
            {
              opts.format_id = "d5da9f67-8551-4e51-807b-b6a873d70e34";
              ret2 = omp_get_report_ext (session, opts, &get_report);
            }
          if ((ret == 404) && (ret2 == 404))
            {
              /* Resource Missing. */
              tracef ("   %s: report missing on slave\n", __FUNCTION__);
              set_task_run_status (task, TASK_STATUS_INTERNAL_ERROR);
              goto giveup;
            }
          if (ret && ret2)
            {
              free_entity (get_tasks);
              openvas_server_close (*socket, *session);
              ret = slave_sleep_connect (slave, host, port, task, socket,
                                         session);
              if (ret == 3)
                goto giveup;
              continue;
            }

          if (update_from_slave (task, get_report, &report, &next_result))
            {
              free_entity (get_tasks);
              free_entity (get_report);
              goto fail_stop_task;
            }

          if (strcmp (status, "Running") == 0)
            {
              if (update_end_times (report, 0))
                goto fail_stop_task;
              free_entity (get_report);
            }
        }
      else if (strcmp (status, "Paused") == 0)
        set_task_run_status (task, TASK_STATUS_PAUSED);
      else if (strcmp (status, "Pause Requested") == 0)
        set_task_run_status (task, TASK_STATUS_PAUSE_WAITING);
      else if (strcmp (status, "Stopped") == 0)
        {
          set_task_run_status (task, TASK_STATUS_STOPPED);
          goto succeed_stopped;
        }
      else if (strcmp (status, "Stop Requested") == 0)
        set_task_run_status (task, TASK_STATUS_STOP_WAITING);
      else if (strcmp (status, "Resume Requested") == 0)
        set_task_run_status (task, TASK_STATUS_RESUME_WAITING);
      else if ((strcmp (status, "Internal Error") == 0)
               || (strcmp (status, "Delete Requested") == 0))
        {
          free_entity (get_tasks);
          goto fail_stop_task;
        }

      if (strcmp (status, "Done") == 0)
        {
          if (update_end_times (report, 1))
            {
              free_entity (get_tasks);
              free_entity (get_report);
              goto fail_stop_task;
            }
          free_entity (get_report);
          if (update_slave_progress (get_tasks))
            {
              free_entity (get_report);
              free_entity (get_tasks);
              goto fail_stop_task;
            }
          free_entity (get_tasks);
          set_task_run_status (task, TASK_STATUS_DONE);
          break;
        }

      free_entity (get_tasks);

      sleep (RUN_SLAVE_TASK_SLEEP_SECONDS);
    }

  /* Cleanup. */

  current_scanner_task = (task_t) 0;

  omp_delete_task_ext (session, slave_task_uuid, del_opts);
  set_report_slave_task_uuid (current_report, "");
  omp_delete_config_ext (session, slave_config_uuid, del_opts);
  omp_delete_target_ext (session, slave_target_uuid, del_opts);
  omp_delete_lsc_credential_ext (session, slave_ssh_credential_uuid, del_opts);
  omp_delete_lsc_credential_ext (session, slave_smb_credential_uuid, del_opts);
 succeed_stopped:
  free (slave_task_uuid);
  slave_task_uuid = NULL;
  free (slave_report_uuid);
  slave_report_uuid = NULL;
  free (slave_config_uuid);
  slave_config_uuid = NULL;
  free (slave_target_uuid);
  slave_target_uuid = NULL;
  free (slave_smb_credential_uuid);
  slave_smb_credential_uuid = NULL;
  free (slave_ssh_credential_uuid);
  slave_ssh_credential_uuid = NULL;
  openvas_server_close (*socket, *session);
  slave_session = NULL;
  slave_socket = NULL;
  return 0;

 fail_stop_task:
  omp_stop_task (session, slave_task_uuid);
  free (slave_report_uuid);
 fail_task:
  omp_delete_task_ext (session, slave_task_uuid, del_opts);
  set_report_slave_task_uuid (current_report, "");
  free (slave_task_uuid);
 fail_config:
  omp_delete_config_ext (session, slave_config_uuid, del_opts);
  free (slave_config_uuid);
 fail_target:
  omp_delete_target_ext (session, slave_target_uuid, del_opts);
  free (slave_target_uuid);
 fail_smb_credential:
  omp_delete_lsc_credential_ext (session, slave_smb_credential_uuid, del_opts);
  free (slave_smb_credential_uuid);
 fail_ssh_credential:
  omp_delete_lsc_credential_ext (session, slave_ssh_credential_uuid, del_opts);
  free (slave_ssh_credential_uuid);
 fail:
  openvas_server_close (*socket, *session);
  slave_session = NULL;
  slave_socket = NULL;
  return 1;

 giveup:
  openvas_server_close (*socket, *session);
  slave_session = NULL;
  slave_socket = NULL;
  return 3;
}

/**
 * @brief Start a task on a slave.
 *
 * @param[in]   task        The task.
 * @param[out]  target      Task target.
 * @param[out]  target_ssh_credential    Target SSH credential.
 * @param[out]  target_smb_credential    Target SMB credential.
 * @param[out]  last_stopped_report  Last stopped report if any, else 0.
 *
 * @return 0 success, -1 error.
 */
static int
run_slave_task (task_t task, target_t target, lsc_credential_t
                target_ssh_credential, lsc_credential_t target_smb_credential,
                report_t last_stopped_report)
{
  slave_t slave;
  char *host, *name, *uuid;
  int port, socket, ret;
  gnutls_session_t session;

  /* Some of the cases in here must write to the session outside an open
   * statement.  For example, the omp_create_lsc_credential must come after
   * cleaning up the credential iterator.  This is because the slave may be
   * the master, and the open statement would prevent the slave from getting
   * a lock on the database and fulfilling the request. */

  tracef ("   Running slave task %llu\n", task);

  slave = task_slave (task);
  tracef ("   %s: slave: %llu\n", __FUNCTION__, slave);
  assert (slave);
  if (slave == 0) return -1;

  host = slave_host (slave);
  if (host == NULL) return -1;

  tracef ("   %s: host: %s\n", __FUNCTION__, host);

  port = slave_port (slave);
  if (port == -1)
    {
      free (host);
      return -1;
    }

  uuid = slave_uuid (slave);
  name = slave_name (slave);
  report_set_slave_uuid (current_report, uuid);
  report_set_slave_name (current_report, name);
  report_set_slave_port (current_report, port);
  report_set_slave_host (current_report, host);
  free (uuid);
  free (name);

  name = openvas_uuid_make ();
  if (name == NULL)
    {
      free (host);
      return -1;
    }

  while ((ret = slave_connect (slave, host, port, &socket, &session)))
    if (ret == 1)
      {
        /* Login failed. */
        free (host);
        return -1;
      }
    else
      sleep (RUN_SLAVE_TASK_SLEEP_SECONDS);

  while (1)
    {
      ret = slave_setup (slave, &session, &socket, name, host, port, task,
                         target, target_ssh_credential, target_smb_credential,
                         last_stopped_report);
      if (ret == 1)
        {
          ret = slave_sleep_connect (slave, host, port, task, &socket, &session);
          if (ret == 3)
            /* User requested "giveup". */
            break;
        }
      else
        break;
    }

  current_scanner_task = (task_t) 0;
  free (host);
  free (name);

  return 0;
}

/**
 * @brief Start a task.
 *
 * Use \ref send_to_server to queue the task start sequence in the scanner
 * output buffer.
 *
 * Only one task can run at a time in a process.
 *
 * @param[in]   task_id    The task ID.
 * @param[out]  report_id  The report ID.
 * @param[in]   from       0 start from beginning, 1 continue from stopped, 2
 *                         continue if stopped else start from beginning.
 * @param[in]   permission  Permission required on task.
 *
 * @return Before forking: 1 task is active already, 3 failed to find task,
 *         -1 error, 99 permission denied,
 *         -2 task is missing a target, -3 creating the report failed,
 *         -4 target missing hosts, -5 scanner is down, -6 already a task
 *         running in this process, -9 fork failed.
 *         After forking: 0 success (parent), 2 success (child),
 *         -10 error (child).
 */
static int
run_task (const char *task_id, char **report_id, int from,
          const char *permission)
{
  task_t task;
  target_t target;
  slave_t slave;
  char *hosts, *port_range, *port;
  gchar *plugins;
  int fail, pid;
  GSList *files = NULL;
  GPtrArray *preference_files;
  task_status_t run_status;
  config_t config;
  lsc_credential_t ssh_credential, smb_credential;
  report_t last_stopped_report;

  task = 0;
  if (find_task_with_permission (task_id, &task, permission))
    return -1;
  if (task == 0)
    return 3;

  if (scanner_up == 0)
    return -5;

  slave = task_slave (task);
  if (slave)
    {
      char *uuid;
      slave_t found;

      uuid = slave_uuid (slave);
      if (find_slave_with_permission (uuid, &found, "get_slave"))
        {
          g_free (uuid);
          return -1;
        }
      g_free (uuid);
      if (found == 0)
        return 99;
    }

  if (set_task_requested (task, &run_status))
    return 1;

  /* Every fail exit from here must reset the run status. */

  if (current_scanner_task)
    {
      set_task_run_status (task, run_status);
      return -6;
    }

  target = task_target (task);
  if (target == 0)
    {
      tracef ("   task target is 0.\n");
      set_task_run_status (task, run_status);
      return -2;
    }

  ssh_credential = target_ssh_lsc_credential (target);
  smb_credential = target_smb_lsc_credential (target);

  hosts = target_hosts (target);
  if (hosts == NULL)
    {
      tracef ("   target hosts is NULL.\n");
      set_task_run_status (task, run_status);
      return -4;
    }

  if ((from == 1)
      || ((from == 2)
          && (run_status == TASK_STATUS_STOPPED)))
    {
      if (task_last_stopped_report (task, &last_stopped_report))
        {
          tracef ("   error getting last stopped report.\n");
          set_task_run_status (task, run_status);
          free (hosts);
          return -1;
        }

      current_report = last_stopped_report;
      if (report_id) *report_id = report_uuid (last_stopped_report);

      /* Remove partial host information from the report. */

      trim_partial_report (last_stopped_report);

      /* Ensure the report is marked as requested. */

      set_report_scan_run_status (current_report, TASK_STATUS_REQUESTED);

      /* Clear the end times of the task and partial report. */

      set_task_start_time_epoch (task, scan_start_time_epoch (current_report));
      set_task_end_time (task, NULL);
      set_scan_end_time (last_stopped_report, NULL);
    }
  else if ((from == 0) || (from == 2))
    {
      last_stopped_report = 0;

      /* Create the report. */

      if (create_current_report (task, report_id, TASK_STATUS_REQUESTED))
        {
          set_task_run_status (task, run_status);
          free (hosts);
          return -3;
        }

      reset_task (task);
    }
  else
    {
      /* "from" must be 0, 1 or 2. */
      assert (0);
      free (hosts);
      return -1;
    }

  /* Fork a child to start and handle the task while the parent responds to
   * the client. */

  pid = fork ();
  switch (pid)
    {
      case 0:
        /* Child.  Carry on starting the task, reopen the database (required
         * after fork). */
        reinit_manage_process ();
        break;
      case -1:
        /* Parent when error. */
        g_warning ("%s: failed to fork task child: %s\n",
                   __FUNCTION__,
                   strerror (errno));
        set_task_run_status (task, run_status);
        current_report = (report_t) 0;
        free (hosts);
        return -9;
        break;
      default:
        /* Parent.  Return, in order to respond to client. */
        current_report = (report_t) 0;
        free (hosts);
        return 0;
        break;
    }

  /* Every fail exit from here must reset to this run status, and must
   * clear current_report. */

  /** @todo On fail exits only, may need to honour request states that one of
   *        the other processes has set on the task (stop_task,
   *        request_delete_task). */

  /** @todo Also reset status on report, as current_scanner_task is 0 here. */

  run_status = TASK_STATUS_INTERNAL_ERROR;

  /* Reset any running information. */

  {
    char *iface;
    iface = task_preference_value (task, "source_iface");
    if (iface)
      report_set_source_iface (current_report, iface);
    else
      report_set_source_iface (current_report, "");
    free (iface);
  }

  if (slave)
    {
      if (run_slave_task (task, target, ssh_credential, smb_credential,
                          last_stopped_report))
        {
          free (hosts);
          set_task_run_status (task, run_status);
          set_report_scan_run_status (current_report, run_status);
          exit (EXIT_FAILURE);
        }
      exit (EXIT_SUCCESS);
    }

  report_set_slave_uuid (current_report, "");
  report_set_slave_name (current_report, "");
  report_set_slave_port (current_report, 0);
  report_set_slave_host (current_report, "");

  /* Send the preferences header. */

  if (send_to_server ("CLIENT <|> PREFERENCES <|>\n"))
    {
      free (hosts);
      set_task_run_status (task, run_status);
      set_report_scan_run_status (current_report, run_status);
      current_report = (report_t) 0;
      return -10;
    }

  /* Get the config and selector. */

  config = task_config (task);
  if (config == 0)
    {
      free (hosts);
      tracef ("   task config is 0.\n");
      set_task_run_status (task, run_status);
      set_report_scan_run_status (current_report, run_status);
      current_report = (report_t) 0;
      return -10;
    }

  /* Send the plugin list. */

  plugins = nvt_selector_plugins (config);
  if (plugins)
    {
      if (ssh_credential && smb_credential)
        fail = sendf_to_server ("plugin_set <|>"
                                " 1.3.6.1.4.1.25623.1.0.90022;"
                                "1.3.6.1.4.1.25623.1.0.90023;%s\n",
                                plugins);
      else if (ssh_credential)
        fail = sendf_to_server ("plugin_set <|>"
                                " 1.3.6.1.4.1.25623.1.0.90022;%s\n",
                                plugins);
      else if (smb_credential)
        fail = sendf_to_server ("plugin_set <|>"
                                " 1.3.6.1.4.1.25623.1.0.90023;%s\n",
                                plugins);
      else
        fail = sendf_to_server ("plugin_set <|> %s\n", plugins);
    }
  else
    fail = send_to_server ("plugin_set <|> 0\n");
  free (plugins);
  if (fail)
    {
      free (hosts);
      set_task_run_status (task, run_status);
      set_report_scan_run_status (current_report, run_status);
      current_report = (report_t) 0;
      return -10;
    }

  /* Send some fixed preferences. */

  if (send_to_server ("ntp_keep_communication_alive <|> yes\n"))
    {
      free (hosts);
      set_task_run_status (task, run_status);
      set_report_scan_run_status (current_report, run_status);
      current_report = (report_t) 0;
      return -10;
    }
  if (send_to_server ("ntp_client_accepts_notes <|> yes\n"))
    {
      free (hosts);
      set_task_run_status (task, run_status);
      set_report_scan_run_status (current_report, run_status);
      current_report = (report_t) 0;
      return -10;
    }
  /** @todo Confirm this really stops scanner from sending FINISHED messages. */
  if (send_to_server ("ntp_opt_show_end <|> no\n"))
    {
      free (hosts);
      set_task_run_status (task, run_status);
      set_report_scan_run_status (current_report, run_status);
      current_report = (report_t) 0;
      return -10;
    }
  if (send_to_server ("ntp_short_status <|> no\n"))
    {
      free (hosts);
      set_task_run_status (task, run_status);
      set_report_scan_run_status (current_report, run_status);
      current_report = (report_t) 0;
      return -10;
    }

  /* Send the scanner and task preferences. */

  if (send_config_preferences (config, "SERVER_PREFS", NULL, NULL))
    {
      free (hosts);
      set_task_run_status (task, run_status);
      set_report_scan_run_status (current_report, run_status);
      current_report = (report_t) 0;
      return -10;
    }

  if (send_task_preferences (task))
    {
      free (hosts);
      set_task_run_status (task, run_status);
      set_report_scan_run_status (current_report, run_status);
      current_report = (report_t) 0;
      return -10;
    }

  /* Send the port range. */

  port_range = target_port_range (target);
  if (sendf_to_server ("port_range <|> %s\n",
                       port_range ? port_range : "default"))
    {
      free (port_range);
      free (hosts);
      set_task_run_status (task, run_status);
      set_report_scan_run_status (current_report, run_status);
      current_report = (report_t) 0;
      return -10;
    }
  free (port_range);

  /* Send the SSH LSC port. */

  port = target_ssh_port (target);
  if (port && sendf_to_server ("auth_port_ssh <|> %s\n", port))
    {
      free (port);
      set_task_run_status (task, run_status);
      set_report_scan_run_status (current_report, run_status);
      current_report = (report_t) 0;
      return -10;
    }
  free (port);

  /* Collect task files to send. */

  files = get_files_to_send (task);

  /* Send the plugins preferences. */

  preference_files = g_ptr_array_new ();
  if (send_config_preferences (config, "PLUGINS_PREFS", files, preference_files))
    {
      g_ptr_array_free (preference_files, TRUE);
      slist_free (files);
      free (hosts);
      set_task_run_status (task, run_status);
      set_report_scan_run_status (current_report, run_status);
      current_report = (report_t) 0;
      return -10;
    }

  /* Send network_targets preference. */

  if (sendf_to_server ("network_targets <|> %s\n", hosts))
    {
      free (hosts);
      g_ptr_array_add (preference_files, NULL);
      array_free (preference_files);
      slist_free (files);
      set_task_run_status (task, run_status);
      set_report_scan_run_status (current_report, run_status);
      current_report = (report_t) 0;
      return -10;
    }

  /* Send other scanner preferences. */
  if (send_scanner_preferences (task, target, last_stopped_report))
    {
      free (hosts);
      g_ptr_array_add (preference_files, NULL);
      array_free (preference_files);
      slist_free (files);
      set_task_run_status (task, run_status);
      set_report_scan_run_status (current_report, run_status);
      current_report = (report_t) 0;
      return -10;
    }

  /* Send credential preferences if there are credentials linked to target. */

  if (ssh_credential)
    {
      iterator_t credentials;

      init_user_lsc_credential_iterator (&credentials, ssh_credential, 0, 1,
                                         NULL);
      if (next (&credentials))
        {
          const char *user = lsc_credential_iterator_login (&credentials);
          const char *password = lsc_credential_iterator_password (&credentials);

          if (sendf_to_server ("SSH Authorization[entry]:SSH login name:"
                               " <|> %s\n",
                               user)
              || (lsc_credential_iterator_public_key (&credentials)
                   ? sendf_to_server ("SSH Authorization[password]:"
                                      "SSH key passphrase:"
                                      " <|> %s\n",
                                      password)
                   : sendf_to_server ("SSH Authorization[password]:"
                                      "SSH password (unsafe!):"
                                      " <|> %s\n",
                                      password)))

            {
 fail:
              free (hosts);
              cleanup_iterator (&credentials);
              g_ptr_array_add (preference_files, NULL);
              array_free (preference_files);
              slist_free (files);
              set_task_run_status (task, run_status);
              set_report_scan_run_status (current_report, run_status);
              current_report = (report_t) 0;
              return -10;
            }

          if (lsc_credential_iterator_public_key (&credentials)
              && (strlen (lsc_credential_iterator_public_key (&credentials))
                  > 7))
            {
              gchar *public_key, *space;
              char *uuid = openvas_uuid_make ();
              if (uuid == NULL)
                goto fail;

              public_key = g_strdup (lsc_credential_iterator_public_key
                                      (&credentials)
                                     + 8);
              space = memchr (public_key, ' ', strlen (public_key));
              if (space)
                *space = '\0';

              g_ptr_array_add (preference_files, (gpointer) uuid);
              g_ptr_array_add (preference_files, (gpointer) public_key);

              if (sendf_to_server ("SSH Authorization[file]:"
                                   "SSH public key:"
                                   " <|> %s\n",
                                   uuid))
                goto fail;
            }

          if (lsc_credential_iterator_private_key (&credentials))
            {
              char *uuid = openvas_uuid_make ();
              if (uuid == NULL)
                goto fail;

              g_ptr_array_add (preference_files, (gpointer) uuid);
              g_ptr_array_add
               (preference_files,
                (gpointer) g_strdup (lsc_credential_iterator_private_key
                                      (&credentials)));

              if (sendf_to_server ("SSH Authorization[file]:"
                                   "SSH private key:"
                                   " <|> %s\n",
                                   uuid))
                goto fail;
            }
        }
      cleanup_iterator (&credentials);
    }

  if (smb_credential)
    {
      iterator_t credentials;

      init_user_lsc_credential_iterator (&credentials, smb_credential, 0, 1,
                                         NULL);
      if (next (&credentials))
        {
          const char *user = lsc_credential_iterator_login (&credentials);
          const char *password = lsc_credential_iterator_password (&credentials);

          if (sendf_to_server ("SMB Authorization[entry]:SMB login: <|> %s\n",
                               user)
              || sendf_to_server ("SMB Authorization[password]:SMB password:"
                                  " <|> %s\n",
                                  password))
            {
              free (hosts);
              cleanup_iterator (&credentials);
              g_ptr_array_add (preference_files, NULL);
              array_free (preference_files);
              slist_free (files);
              set_task_run_status (task, run_status);
              set_report_scan_run_status (current_report, run_status);
              current_report = (report_t) 0;
              return -10;
            }
        }
      cleanup_iterator (&credentials);
    }

  g_ptr_array_add (preference_files, NULL);

  /* Send preferences for target "Alive Test", overriding config values. */

  if (send_alive_test_preferences (target))
    {
      free (hosts);
      array_free (preference_files);
      slist_free (files);
      set_task_run_status (task, run_status);
      set_report_scan_run_status (current_report, run_status);
      current_report = (report_t) 0;
      return -10;
    }

  if (send_to_server ("<|> CLIENT\n"))
    {
      free (hosts);
      array_free (preference_files);
      slist_free (files);
      set_task_run_status (task, run_status);
      set_report_scan_run_status (current_report, run_status);
      current_report = (report_t) 0;
      return -10;
    }

  /* Send any files stored in the config preferences. */

  {
    gchar *file;
    int index = 0;
    while ((file = g_ptr_array_index (preference_files, index)))
      {
        GSList *head;
        gchar *value;

        index++;

        /* Skip the file if the value of the preference is the name of a
         * file associated with the task. */
        value = g_ptr_array_index (preference_files, index);
        head = files;
        while (head)
          {
            if (strcmp (head->data, value) == 0)
              break;
            head = g_slist_next (head);
          }

        if (head == NULL && send_file (file, value))
          {
            free (hosts);
            array_free (preference_files);
            slist_free (files);
            set_task_run_status (task, run_status);
            set_report_scan_run_status (current_report, run_status);
            current_report = (report_t) 0;
            return -10;
          }
        index++;
      }

    array_free (preference_files);
  }

  /* Send any files. */

  while (files)
    {
      GSList *last = files;
      if (send_task_file (task, files->data))
        {
          free (hosts);
          slist_free (files);
          set_task_run_status (task, run_status);
          set_report_scan_run_status (current_report, run_status);
          current_report = (report_t) 0;
          return -10;
        }
      files = g_slist_next (files);
      g_free (last->data);
      g_slist_free_1 (last);
    }

  /* Send the attack command. */

  /* Send all the hosts to the Scanner.  When resuming a stopped task,
   * the hosts that have been completely scanned are excluded by being
   * included in exclude_hosts preference. */
  fail = sendf_to_server ("CLIENT <|> LONG_ATTACK <|>\n%d\n%s\n",
                          strlen (hosts),
                          hosts);
  free (hosts);
  if (fail)
    {
      set_task_run_status (task, run_status);
      set_report_scan_run_status (current_report, run_status);
      current_report = (report_t) 0;
      return -10;
    }
  scanner_active = 1;

  current_scanner_task = task;

#if 0
  /** @todo This is what the file based tasks did. */
  if (task->open_ports) g_array_free (task->open_ports, TRUE);
  task->open_ports = g_array_new (FALSE, FALSE, (guint) sizeof (port_t));
  task->open_ports_size = 0;
#endif

  return 2;
}

/**
 * @brief Start a task.
 *
 * Use \ref send_to_server to queue the task start sequence in the scanner
 * output buffer.
 *
 * Only one task can run at a time in a process.
 *
 * @param[in]   task_id    The task ID.
 * @param[out]  report_id  The report ID.
 *
 * @return Before forking: 1 task is active already, 3 failed to find task,
 *         99 permission denied, -1 internal error,
 *         -2 task is missing a target, -3 creating the report failed,
 *         -4 target missing hosts, -6 already a task running in this process,
 *         -9 fork failed.
 *         After forking: 0 success (parent), 2 success (child),
 *         -10 error (child).
 */
int
start_task (const char *task_id, char **report_id)
{
  if (user_may ("start_task") == 0)
    return 99;

  return run_task (task_id, report_id, 0, "start_task");
}

/**
 * @brief Initiate stopping a task.
 *
 * Use \ref send_to_server to queue the task stop sequence in the
 * scanner output buffer.
 *
 * @param[in]  task  Task.
 *
 * @return 0 on success, 1 if stop requested, -1 if out of space in scanner
 *         output buffer, -5 scanner down.
 */
int
stop_task_internal (task_t task)
{
  task_status_t run_status;

  run_status = task_run_status (task);
  if (run_status == TASK_STATUS_PAUSE_REQUESTED
      || run_status == TASK_STATUS_PAUSE_WAITING
      || run_status == TASK_STATUS_PAUSED
      || run_status == TASK_STATUS_RESUME_REQUESTED
      || run_status == TASK_STATUS_RESUME_WAITING
      || run_status == TASK_STATUS_REQUESTED
      || run_status == TASK_STATUS_RUNNING)
    {
      if (current_scanner_task == task)
        {
          if (scanner_up == 0)
            return -5;
          if (send_to_server ("CLIENT <|> STOP_WHOLE_TEST <|> CLIENT\n"))
            return -1;
        }
      set_task_run_status (task, TASK_STATUS_STOP_REQUESTED);
      return 1;
    }
  else if ((run_status == TASK_STATUS_DELETE_REQUESTED
            || run_status == TASK_STATUS_DELETE_WAITING
            || run_status == TASK_STATUS_DELETE_ULTIMATE_REQUESTED
            || run_status == TASK_STATUS_DELETE_ULTIMATE_WAITING
            || run_status == TASK_STATUS_STOP_REQUESTED
            || run_status == TASK_STATUS_STOP_WAITING)
           && task_slave (task))
    {
      /* A special request from the user to get the task out of a requested
       * state when contact with the slave is lost. */
      set_task_run_status (task, TASK_STATUS_STOP_REQUESTED_GIVEUP);
      return 1;
    }

  return 0;
}

/**
 * @brief Initiate stopping a task.
 *
 * Use \ref send_to_server to queue the task stop sequence in the
 * scanner output buffer.
 *
 * @param[in]  task_id  Task UUID.
 *
 * @return 0 on success, 1 if stop requested, 3 failed to find task,
 *         99 permission denied, -1 if out of space in scanner output buffer,
 *         -5 scanner down.
 */
int
stop_task (const char *task_id)
{
  task_t task;

  if (user_may ("stop_task") == 0)
    return 99;

  task = 0;
  if (find_task_with_permission (task_id, &task, "stop_task"))
    return -1;
  if (task == 0)
    return 3;

  return stop_task_internal (task);
}

/**
 * @brief Initiate pausing of a task.
 *
 * Use \ref send_to_server to queue the task pause sequence in the
 * scanner output buffer.
 *
 * @param[in]  task_id  Task UUID.
 *
 * @return 0 on success, 1 if pause requested, 3 failed to find task,
 *         99 permission denied, -1 internal error, -3 if out of space in
 *         scanner output buffer, -5 scanner down.
 */
int
pause_task (const char *task_id)
{
  task_t task;
  task_status_t run_status;

  if (user_may ("pause_task") == 0)
    return 99;

  task = 0;
  if (find_task_with_permission (task_id, &task, "pause_task"))
    return -1;
  if (task == 0)
    return 3;

  if (scanner_up == 0)
    return -5;

  run_status = task_run_status (task);
  if (run_status == TASK_STATUS_REQUESTED
      || run_status == TASK_STATUS_RUNNING)
    {
      if (current_scanner_task == task
          && send_to_server ("CLIENT <|> PAUSE_WHOLE_TEST <|> CLIENT\n"))
        return -3;
      set_task_run_status (task, TASK_STATUS_PAUSE_REQUESTED);
      return 1;
    }

  return 0;
}

/**
 * @brief Initiate resuming of a task.
 *
 * Use \ref send_to_server to queue the task resume sequence in the
 * scanner output buffer.
 *
 * @param[in]  task_id  Task UUID.
 *
 * @return 0 on success, 1 if resume requested, 3 failed to find task,
 *         99 permission denied, -1 if out of space in scanner output buffer,
 *         -5 scanner down.
 */
int
resume_paused_task (const char *task_id)
{
  task_t task;
  task_status_t run_status;

  if (user_may ("resume_paused_task") == 0)
    return 99;

  task = 0;
  if (find_task_with_permission (task_id, &task, "resume_paused_task"))
    return -1;
  if (task == 0)
    return 3;

  if (scanner_up == 0)
    return -5;

  run_status = task_run_status (task);
  if (run_status == TASK_STATUS_PAUSE_REQUESTED
      || run_status == TASK_STATUS_PAUSED)
    {
      if (current_scanner_task == task
          && send_to_server ("CLIENT <|> RESUME_WHOLE_TEST <|> CLIENT\n"))
        return -1;
      set_task_run_status (task, TASK_STATUS_RESUME_REQUESTED);
      return 1;
    }

  return 0;
}

/**
 * @brief Resume a stopped task.
 *
 * @param[in]   task_id    Task UUID.
 * @param[out]  report_id  If successful, ID of the resultant report.
 *
 * @return 22 caller error (task must be in "stopped" state), or any
 *         start_task error.
 */
int
resume_stopped_task (const char *task_id, char **report_id)
{
  task_t task;
  task_status_t run_status;

  if (user_may ("resume_stopped_task") == 0)
    return 99;

  task = 0;
  if (find_task_with_permission (task_id, &task, "resume_stopped_task"))
    return -1;
  if (task == 0)
    return 3;

  run_status = task_run_status (task);
  if (run_status == TASK_STATUS_STOPPED)
    return run_task (task_id, report_id, 1, "resume_stopped_task");
  return 22;
}

/**
 * @brief Resume task if stopped, else start task.
 *
 * Only one task can run at a time in a process.
 *
 * @param[out]  task_id    The task ID.
 * @param[out]  report_id  The report ID.
 *
 * @return Any start_task error.
 */
int
resume_or_start_task (const char *task_id, char **report_id)
{
  if (user_may ("resume_or_start_task") == 0)
    return 99;

  return run_task (task_id, report_id, 2, "resume_or_start_task");
}


/* Scanner messaging. */

/**
 * @brief Acknowledge a scanner BYE.
 *
 * @return 0 on success, -1 if out of space in scanner output buffer.
 */
int
acknowledge_bye ()
{
  if (send_to_server ("CLIENT <|> BYE <|> ACK\n"))
    return -1;
  return 0;
}

/**
 * @brief Acknowledge scanner PLUGINS_FEED_VERSION message,
 * @brief requesting all plugin info.
 *
 * @return 0 on success, -1 if out of space in scanner output buffer.
 */
int
acknowledge_feed_version_info ()
{
  if (send_to_server ("CLIENT <|> COMPLETE_LIST <|> CLIENT\n"))
    return -1;
  return 0;
}

/**
 * @brief Handle state changes to current task made by other processes.
 *
 * @return 0 on success, -1 if out of space in scanner output buffer, 1 if
 *         queued to scanner.
 */
int
manage_check_current_task ()
{
  if (current_scanner_task)
    {
      task_status_t run_status;

      /* Commit pending transaction if needed. */
      manage_transaction_stop (FALSE);

      /* Check if some other process changed the status. */

      run_status = task_run_status (current_scanner_task);
      switch (run_status)
        {
          case TASK_STATUS_PAUSE_REQUESTED:
            if (send_to_server ("CLIENT <|> PAUSE_WHOLE_TEST <|> CLIENT\n"))
              return -1;
            set_task_run_status (current_scanner_task,
                                 TASK_STATUS_PAUSE_WAITING);
            return 1;
            break;
          case TASK_STATUS_RESUME_REQUESTED:
            if (send_to_server ("CLIENT <|> RESUME_WHOLE_TEST <|> CLIENT\n"))
              return -1;
            set_task_run_status (current_scanner_task,
                                 TASK_STATUS_RESUME_WAITING);
            return 1;
            break;
          case TASK_STATUS_STOP_REQUESTED_GIVEUP:
            /* This should only happen for slave tasks. */
            assert (0);
          case TASK_STATUS_STOP_REQUESTED:
            if (send_to_server ("CLIENT <|> STOP_WHOLE_TEST <|> CLIENT\n"))
              return -1;
            set_task_run_status (current_scanner_task,
                                 TASK_STATUS_STOP_WAITING);
            return 1;
            break;
          case TASK_STATUS_DELETE_REQUESTED:
            if (send_to_server ("CLIENT <|> STOP_WHOLE_TEST <|> CLIENT\n"))
              return -1;
            set_task_run_status (current_scanner_task,
                                 TASK_STATUS_DELETE_WAITING);
            return 1;
            break;
          case TASK_STATUS_DELETE_ULTIMATE_REQUESTED:
            if (send_to_server ("CLIENT <|> STOP_WHOLE_TEST <|> CLIENT\n"))
              return -1;
            set_task_run_status (current_scanner_task,
                                 TASK_STATUS_DELETE_ULTIMATE_WAITING);
            return 1;
            break;
          case TASK_STATUS_DELETE_WAITING:
          case TASK_STATUS_DELETE_ULTIMATE_WAITING:
          case TASK_STATUS_DONE:
          case TASK_STATUS_NEW:
          case TASK_STATUS_REQUESTED:
          case TASK_STATUS_RESUME_WAITING:
          case TASK_STATUS_RUNNING:
          case TASK_STATUS_PAUSE_WAITING:
          case TASK_STATUS_PAUSED:
          case TASK_STATUS_STOP_WAITING:
          case TASK_STATUS_STOPPED:
          case TASK_STATUS_INTERNAL_ERROR:
            break;
        }
    }
  return 0;
}


/* System reports. */

/**
 * @brief Get system report types from a slave.
 *
 * @param[in]   required_type  Single type to limit types to.
 * @param[out]  types          Types on success.
 * @param[out]  start          Actual start of types, which caller must free.
 * @param[out]  slave_id       ID of slave.
 *
 * @return 0 if successful, 2 failed to find slave, -1 otherwise.
 */
static int
get_slave_system_report_types (const char *required_type, gchar ***start,
                               gchar ***types, const char *slave_id)
{
  slave_t slave = 0;
  char *host, **end;
  int port, socket;
  gnutls_session_t session;
  entity_t get, report;
  entities_t reports;

  if (find_slave (slave_id, &slave))
    return -1;
  if (slave == 0)
    return 2;

  host = slave_host (slave);
  if (host == NULL) return -1;

  tracef ("   %s: host: %s\n", __FUNCTION__, host);

  port = slave_port (slave);
  if (port == -1)
    {
      free (host);
      return -1;
    }

  socket = openvas_server_open (&session, host, port);
  free (host);
  if (socket == -1) return -1;

  tracef ("   %s: connected\n", __FUNCTION__);

  /* Authenticate using the slave login. */

  if (slave_authenticate (&session, slave))
    goto fail;

  tracef ("   %s: authenticated\n", __FUNCTION__);

  if (omp_get_system_reports (&session, required_type, 1, &get))
    goto fail;

  openvas_server_close (socket, session);

  reports = get->entities;
  end = *types = *start = g_malloc ((xml_count_entities (reports) + 1)
                                    * sizeof (gchar*));
  while ((report = first_entity (reports)))
    {
      if (strcmp (entity_name (report), "system_report") == 0)
        {
          entity_t name, title;
          gchar *pair;
          char *name_text, *title_text;
          name = entity_child (report, "name");
          title = entity_child (report, "title");
          if (name == NULL || title == NULL)
            {
              *end = NULL;
              g_strfreev (*start);
              free_entity (get);
              return -1;
            }
          name_text = entity_text (name);
          title_text = entity_text (title);
          *end = pair = g_malloc (strlen (name_text) + strlen (title_text) + 2);
          strcpy (pair, name_text);
          pair += strlen (name_text) + 1;
          strcpy (pair, title_text);
          end++;
        }
      reports = next_entities (reports);
    }
  *end = NULL;

  free_entity (get);

  return 0;

 fail:
  openvas_server_close (socket, session);
  return -1;
}

/**
 * @brief Command called by get_system_report_types.
 */
#define COMMAND "openvasmr 0 titles"

/**
 * @brief Get system report types.
 *
 * @param[in]   required_type  Single type to limit types to.
 * @param[out]  types          Types on success.
 * @param[out]  start          Actual start of types, which caller must free.
 * @param[out]  slave_id       ID of slave.
 *
 * @return 0 if successful, 1 failed to find report type, 2 failed to find
 *         slave, 3 serving the fallback, -1 otherwise.
 */
static int
get_system_report_types (const char *required_type, gchar ***start,
                         gchar ***types, const char *slave_id)
{
  gchar *astdout = NULL;
  gchar *astderr = NULL;
  GError *err = NULL;
  gint exit_status;

  if (slave_id && strcmp (slave_id, "0"))
    return get_slave_system_report_types (required_type, start, types,
                                          slave_id);

  tracef ("   command: " COMMAND);

  if ((g_spawn_command_line_sync (COMMAND,
                                  &astdout,
                                  &astderr,
                                  &exit_status,
                                  &err)
       == FALSE)
      || (WIFEXITED (exit_status) == 0)
      || WEXITSTATUS (exit_status))
    {
      tracef ("%s: openvasmr failed with %d", __FUNCTION__, exit_status);
      tracef ("%s: stdout: %s", __FUNCTION__, astdout);
      tracef ("%s: stderr: %s", __FUNCTION__, astderr);
      g_free (astdout);
      g_free (astderr);
      *start = *types = g_malloc0 (sizeof (gchar*) * 2);
      (*start)[0] = g_strdup ("fallback Fallback Report");
      (*start)[0][strlen ("fallback")] = '\0';
      return 3;
    }
  if (astdout)
    {
      char **type;
      *start = *types = type = g_strsplit (g_strchomp (astdout), "\n", 0);
      while (*type)
        {
          char *space;
          space = strchr (*type, ' ');
          if (space == NULL)
            {
              g_strfreev (*types);
              *types = NULL;
              g_free (astdout);
              g_free (astderr);
              return -1;
            }
          *space = '\0';
          if (required_type && (strcmp (*type, required_type) == 0))
            {
              char **next;
              /* Found the single given type. */
              next = type + 1;
              while (*next)
                {
                  free (*next);
                  next++;
                }
              next = type + 1;
              *next = NULL;
              *types = type;
              g_free (astdout);
              g_free (astderr);
              return 0;
            }
          type++;
        }
      if (required_type)
        {
          /* Failed to find the single given type. */
          g_free (astdout);
          g_free (astderr);
          g_strfreev (*types);
          return 1;
        }
    }
  else
    *start = *types = g_malloc0 (sizeof (gchar*));

  g_free (astdout);
  g_free (astderr);
  return 0;
}

#undef COMMAND

/**
 * @brief Initialise a system report type iterator.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  type        Single report type to iterate over, NULL for all.
 * @param[in]  slave_id    ID of slave to get reports from.  0 for local.
 *
 * @return 0 on success, 1 failed to find report type, 2 failed to find slave,
 *         3 used the fallback report, 99 permission denied, -1 on error.
 */
int
init_system_report_type_iterator (report_type_iterator_t* iterator,
                                  const char* type,
                                  const char* slave_id)
{
  int ret;

  if (user_may ("get_system_reports") == 0)
    return 99;

  ret = get_system_report_types (type, &iterator->start, &iterator->current,
                                 slave_id);
  if (ret == 0 || ret == 3)
    {
      iterator->current--;
      return ret;
    }
  return ret;
}

/**
 * @brief Cleanup a report type iterator.
 *
 * @param[in]  iterator  Iterator.
 */
void
cleanup_report_type_iterator (report_type_iterator_t* iterator)
{
  g_strfreev (iterator->start);
}

/**
 * @brief Increment a report type iterator.
 *
 * The caller must stop using this after it returns FALSE.
 *
 * @param[in]  iterator  Task iterator.
 *
 * @return TRUE if there was a next item, else FALSE.
 */
gboolean
next_report_type (report_type_iterator_t* iterator)
{
  iterator->current++;
  if (*iterator->current == NULL) return FALSE;
  return TRUE;
}

/**
 * @brief Return the name from a report type iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name.
 */
const char*
report_type_iterator_name (report_type_iterator_t* iterator)
{
  return (const char*) *iterator->current;
}

/**
 * @brief Return the title from a report type iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Title.
 */
const char*
report_type_iterator_title (report_type_iterator_t* iterator)
{
  const char *name = *iterator->current;
  return name + strlen (name) + 1;
}

/**
 * @brief Get a system report from a slave.
 *
 * @param[in]   name      Name of report.
 * @param[in]   duration  Time range of report, in seconds.
 * @param[in]   slave_id  ID of slave to get report from.  0 for local.
 * @param[out]  report    On success, report in base64 if such a report exists
 *                        else NULL.  Arbitrary on error.
 *
 * @return 0 if successful, 2 failed to find slave, -1 otherwise.
 */
static int
slave_system_report (const char *name, const char *duration,
                     const char *slave_id, char **report)
{
  slave_t slave = 0;
  char *host;
  int port, socket;
  gnutls_session_t session;
  entity_t get, entity;
  entities_t reports;
  omp_get_system_reports_opts_t opts;

  if (find_slave (slave_id, &slave))
    return -1;
  if (slave == 0)
    return 2;

  host = slave_host (slave);
  if (host == NULL) return -1;

  tracef ("   %s: host: %s\n", __FUNCTION__, host);

  port = slave_port (slave);
  if (port == -1)
    {
      free (host);
      return -1;
    }

  socket = openvas_server_open (&session, host, port);
  free (host);
  if (socket == -1) return -1;

  tracef ("   %s: connected\n", __FUNCTION__);

  /* Authenticate using the slave login. */

  if (slave_authenticate (&session, slave))
    goto fail;

  tracef ("   %s: authenticated\n", __FUNCTION__);

  opts = omp_get_system_reports_opts_defaults;
  opts.name = name;
  opts.duration = duration;
  opts.brief = 0;

  if (omp_get_system_reports_ext (&session, opts, &get))
    goto fail;

  openvas_server_close (socket, session);

  reports = get->entities;
  if ((entity = first_entity (reports))
      && (strcmp (entity_name (entity), "system_report") == 0))
    {
      entity = entity_child (entity, "report");
      if (entity)
        {
          *report = g_strdup (entity_text (entity));
          return 0;
        }
    }

  free_entity (get);
  return -1;

 fail:
  openvas_server_close (socket, session);
  return -1;
}

/**
 * @brief Header for fallback system report.
 */
#define FALLBACK_SYSTEM_REPORT_HEADER \
"This is the most basic, fallback report.  The system can be configured to\n" \
"produce more powerful reports.  Please contact your system administrator\n" \
"for more information.\n\n"

/**
 * @brief Get a system report.
 *
 * @param[in]   name      Name of report.
 * @param[in]   duration  Time range of report, in seconds.
 * @param[in]   slave_id  ID of slave to get report from.  0 for local.
 * @param[out]  report    On success, report in base64 if such a report exists
 *                        else NULL.  Arbitrary on error.
 *
 * @return 0 if successful (including failure to find report), -1 on error,
 *         3 if used the fallback report.
 */
int
manage_system_report (const char *name, const char *duration,
                      const char *slave_id, char **report)
{
  gchar *astdout = NULL;
  gchar *astderr = NULL;
  GError *err = NULL;
  gint exit_status;
  gchar *command;

  assert (name);

  if (duration == NULL)
    duration = "86400";

  if (slave_id && strcmp (slave_id, "0"))
    return slave_system_report (name, duration, slave_id, report);

  /* For simplicity, it's up to the command to do the base64 encoding. */
  command = g_strdup_printf ("openvasmr %s %s", duration, name);

  tracef ("   command: %s", command);

  if ((g_spawn_command_line_sync (command,
                                  &astdout,
                                  &astderr,
                                  &exit_status,
                                  &err)
       == FALSE)
      || (WIFEXITED (exit_status) == 0)
      || WEXITSTATUS (exit_status))
    {
      int ret;
      double load[3];
      GError *get_error;
      gchar *output;
      gsize output_len;
      GString *buffer;

      tracef ("%s: openvasmr failed with %d", __FUNCTION__, exit_status);
      tracef ("%s: stdout: %s", __FUNCTION__, astdout);
      tracef ("%s: stderr: %s", __FUNCTION__, astderr);
      g_free (astdout);
      g_free (astderr);
      g_free (command);

      buffer = g_string_new (FALLBACK_SYSTEM_REPORT_HEADER);

      ret = getloadavg (load, 3);
      if (ret == 3)
        {
          g_string_append_printf (buffer,
                                  "Load average for past minute:     %.1f\n",
                                  load[0]);
          g_string_append_printf (buffer,
                                  "Load average for past 5 minutes:  %.1f\n",
                                  load[1]);
          g_string_append_printf (buffer,
                                  "Load average for past 15 minutes: %.1f\n",
                                  load[2]);
        }
      else
        g_string_append (buffer, "Error getting load averages.\n");

      get_error = NULL;
      g_file_get_contents ("/proc/meminfo",
                           &output,
                           &output_len,
                           &get_error);
      if (get_error)
        g_error_free (get_error);
      else
        {
          gchar *safe;
          g_string_append (buffer, "\n/proc/meminfo:\n\n");
          safe = g_markup_escape_text (output, strlen (output));
          g_free (output);
          g_string_append (buffer, safe);
          g_free (safe);
        }

      *report = g_string_free (buffer, FALSE);
      return 3;
    }
  g_free (astderr);
  g_free (command);
  if (astdout == NULL || strlen (astdout) == 0)
    {
      g_free (astdout);
      if (strcmp (name, "blank") == 0)
        return -1;
      return manage_system_report ("blank", duration, NULL, report);
    }
  else
    *report = astdout;
  return 0;
}


/* Scheduling. */

/**
 * @brief Flag for manage_auth_allow_all.
 */
int authenticate_allow_all = 0;

/**
 * @brief UUID of user whose scheduled task is to be started (in connection
 *        with authenticate_allow_all).
 */
gchar* schedule_user_uuid = 0;

/**
 * @brief Calculate the next time from now given a start time and a period.
 *
 * @param[in] first         The first time.
 * @param[in] period        The period in seconds.
 * @param[in] period_months The period in months.
 *
 * @return  the next time a schedule with the given times is due.
 */
time_t
next_time (time_t first, int period, int period_months)
{
  int periods_diff;
  time_t now = time (NULL);

  if (first >= now)
    {
      return first;
    }
  else if (period > 0)
    {
      return first + ((((now - first) / period) + 1) * period);
    }
  else if (period_months > 0)
    {
      periods_diff = months_between (first, now) / period_months;
      if (add_months (first, (periods_diff + 1) * period_months)
          >= now)
        return add_months (first, (periods_diff + 1) * period_months);
      else
        return add_months (first, periods_diff * period_months);
    }
  return 0;
}

/**
 * @brief Ensure that any subsequent authentications succeed.
 */
void
manage_auth_allow_all ()
{
  authenticate_allow_all = 1;
}

/**
 * @brief Access UUID of user that scheduled the current task.
 *
 * @return UUID of user that scheduled the current task.
 */
gchar*
get_scheduled_user_uuid ()
{
  return schedule_user_uuid;
}

/**
 * @brief Set UUID of user that scheduled the current task.
 *
 * @param user_uuid UUID of user that scheduled the current task.
 */
void
set_scheduled_user_uuid (gchar* user_uuid)
{
  schedule_user_uuid = user_uuid;
}

/**
 * @brief Set a task's schedule so that it runs again next scheduling round.
 *
 * @param  task_id  UUID of task.
 */
void
reschedule_task (const gchar *task_id)
{
  task_t task;
  task = 0;
  switch (sql_int64 (&task, 0, 0,
                     "SELECT id FROM tasks WHERE uuid = '%s'"
                     " AND hidden != 2;",
                     task_id))
    {
      case 0:
        g_warning ("%s: rescheduling task '%s'\n", __FUNCTION__, task_id);
        set_task_schedule_next_time (task, time (NULL) - 1);
        break;
      case 1:        /* Too few rows in result of query. */
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        break;
    }
}

/**
 * @brief Schedule any actions that are due.
 *
 * In openvasmd, periodically called from the main daemon loop.
 *
 * @param[in]  fork_connection  Function that forks a child which is connected
 *                              to the Manager.  Must return PID in parent, 0
 *                              in child, or -1 on error.
 * @param[in]  run_tasks        Whether to run scheduled tasks.
 *
 * @return 0 success, 1 failed to get lock, -1 error.
 */
int
manage_schedule (int (*fork_connection) (int *,
                                         gnutls_session_t *,
                                         gnutls_certificate_credentials_t *,
                                         gchar*),
                 gboolean run_tasks)
{
  iterator_t schedules;
  GSList *starts = NULL, *stops = NULL;
  int ret;

  manage_update_nvti_cache ();

  if (run_tasks == 0)
    return 0;

  /* Assemble "starts" and "stops" list containing task uuid and owner name
   * for each (scheduled) task to start or stop. */

  ret = init_task_schedule_iterator (&schedules);
  if (ret)
    {
      if (ret == -1)
        g_warning ("%s: iterator init error\n", __FUNCTION__);
      return ret;
    }
  /* This iterator runs in an exclusive transaction, so this loop is atomic. */
  while (next (&schedules))
    if (task_schedule_iterator_start_due (&schedules))
      {
        time_t period, period_months;

        /* Update the task schedule info to prevent multiple schedules. */

        period = task_schedule_iterator_period (&schedules);
        period_months = task_schedule_iterator_period_months (&schedules);

        if (period)
          {
            time_t now = time (NULL);
            time_t first = task_schedule_iterator_first_time (&schedules);
            time_t duration = task_schedule_iterator_duration (&schedules);

            assert (first <= now);

            /* In the database keep the times in UTC... */
            set_task_schedule_next_time
             (task_schedule_iterator_task (&schedules),
              first + ((((now - first) / period) + 1) * period));

            /* ...but for the calculations offset for daylight saving. */
            first += task_schedule_iterator_initial_offset (&schedules)
                      - current_offset (task_schedule_iterator_timezone
                                         (&schedules));

            /* Ensure that the task starts within the duration if it has one. */
            if (duration && (((now - first) % period) > duration))
              continue;
          }
        else if (period_months)
          {
            time_t now = time (NULL);
            time_t first = task_schedule_iterator_first_time (&schedules);
            time_t duration = task_schedule_iterator_duration (&schedules);

            assert (first <= now);

            /* In the database keep the times in UTC... */
            set_task_schedule_next_time
             (task_schedule_iterator_task (&schedules),
              add_months (first, months_between (first, now) + 1));

            /* ...but for the calculations offset for daylight saving. */
            first += task_schedule_iterator_initial_offset (&schedules)
                      - current_offset (task_schedule_iterator_timezone
                                         (&schedules));

            /* Ensure that the task starts within the duration if it has one. */
            if (duration
                && ((now - add_months (first, months_between (first, now)))
                    > duration))
              continue;
          }
        else
          set_task_schedule_next_time
           (task_schedule_iterator_task (&schedules), 0);

        /* Add task UUID and owner name and UUID to the list. */

        starts = g_slist_prepend
                  (starts,
                   g_strdup (task_schedule_iterator_task_uuid (&schedules)));
        starts = g_slist_prepend
                  (starts,
                   g_strdup (task_schedule_iterator_owner_uuid (&schedules)));
        starts = g_slist_prepend
                  (starts,
                   g_strdup (task_schedule_iterator_owner_name (&schedules)));
      }
    else if (task_schedule_iterator_stop_due (&schedules))
      {
        /* Add task UUID and owner name and UUID to the list. */

        stops = g_slist_prepend
                 (stops,
                  g_strdup (task_schedule_iterator_task_uuid (&schedules)));
        stops = g_slist_prepend
                 (stops,
                  g_strdup (task_schedule_iterator_owner_uuid (&schedules)));
        stops = g_slist_prepend
                 (stops,
                  g_strdup (task_schedule_iterator_owner_name (&schedules)));
      }
  cleanup_task_schedule_iterator (&schedules);

  /* Start tasks in forked processes, now that the SQL statement is closed. */

  while (starts)
    {
      int socket, pid;
      gnutls_session_t session;
      gnutls_certificate_credentials_t credentials;
      gchar *task_uuid, *owner, *owner_uuid;
      GSList *head;

      owner = starts->data;
      assert (starts->next);
      owner_uuid = starts->next->data;
      assert (starts->next->next);
      task_uuid = starts->next->next->data;

      head = starts;
      starts = starts->next->next->next;
      g_slist_free_1 (head->next->next);
      g_slist_free_1 (head->next);
      g_slist_free_1 (head);

      /* Fork a child to start the task and wait for the response, so that the
       * parent can return to the main loop. */

      pid = fork ();
      switch (pid)
        {
          case 0:
            /* Child.  Carry on to start the task, reopen the database (required
             * after fork). */
            reinit_manage_process ();
            while (starts)
              {
                g_free (starts->data);
                starts = g_slist_delete_link (starts, starts);
              }
            break;

          case -1:
            /* Parent on error.  Reschedule and continue to next task. */
            g_warning ("%s: fork failed\n", __FUNCTION__);
            reschedule_task (task_uuid);
            g_free (task_uuid);
            g_free (owner);
            g_free (owner_uuid);
            continue;

          default:
            /* Parent.  Continue to next task. */
            g_debug ("%s: %i forked %i", __FUNCTION__, getpid (), pid);
            g_free (task_uuid);
            g_free (owner);
            g_free (owner_uuid);
            continue;

        }

      /* Run the callback to fork a child connected to the Manager. */

      pid = fork_connection (&socket, &session, &credentials, owner_uuid);
      switch (pid)
        {
          case 0:
            /* Child.  Break, start task, exit. */
            g_free (owner_uuid);
            break;

          case -1:
            /* Parent on error. */
            g_warning ("%s: fork_connection failed\n", __FUNCTION__);
            reschedule_task (task_uuid);
            g_free (task_uuid);
            g_free (owner);
            g_free (owner_uuid);
            exit (EXIT_FAILURE);

          default:
            {
              int status;

              /* Parent.  Wait for child, to check return. */

              g_debug ("%s: %i fork_connectioned %i",
                       __FUNCTION__, getpid (), pid);

              g_free (owner);
              g_free (owner_uuid);

              if (signal (SIGCHLD, SIG_DFL) == SIG_ERR)
                g_warning ("%s: failed to set SIGCHLD", __FUNCTION__);
              while (waitpid (pid, &status, 0) < 0)
                {
                  if (errno == ECHILD)
                    {
                      g_warning ("%s: Failed to get child exit,"
                                 " so task '%s' may not have been scheduled",
                                 __FUNCTION__,
                                 task_uuid);
                      g_free (task_uuid);
                      exit (EXIT_FAILURE);
                    }
                  if (errno == EINTR)
                    continue;
                  g_warning ("%s: waitpid: %s",
                             __FUNCTION__,
                             strerror (errno));
                  g_warning ("%s: As a result, task '%s' may not have been"
                             " scheduled",
                             __FUNCTION__,
                             task_uuid);
                  g_free (task_uuid);
                  exit (EXIT_FAILURE);
                }
              if (WIFEXITED (status))
                switch (WEXITSTATUS (status))
                  {
                    case EXIT_SUCCESS:
                      /* Child succeeded. */
                      g_free (task_uuid);
                      exit (EXIT_SUCCESS);

                    case EXIT_FAILURE:
                    default:
                      break;
                  }

              /* Child failed, reset task schedule time and exit. */

              g_warning ("%s: child failed\n", __FUNCTION__);
              reschedule_task (task_uuid);
              g_free (task_uuid);

              exit (EXIT_FAILURE);
            }
        }

      /* Start the task. */

      if (omp_authenticate (&session, owner, ""))
        {
          g_warning ("%s: omp_authenticate failed", __FUNCTION__);
          g_free (task_uuid);
          g_free (owner);
          openvas_server_free (socket, session, credentials);
          exit (EXIT_FAILURE);
        }

      g_free (owner);

      if (omp_resume_or_start_task (&session, task_uuid))
        {
          g_warning ("%s: omp_resume_or_start_task failed", __FUNCTION__);
          g_free (task_uuid);
          openvas_server_free (socket, session, credentials);
          exit (EXIT_FAILURE);
        }

      g_free (task_uuid);
      openvas_server_free (socket, session, credentials);
      exit (EXIT_SUCCESS);
   }

  /* Stop tasks in forked processes, now that the SQL statement is closed. */

  while (stops)
    {
      int socket;
      gnutls_session_t session;
      gnutls_certificate_credentials_t credentials;
      gchar *task_uuid, *owner, *owner_uuid;
      GSList *head;

      owner = stops->data;
      assert (stops->next);
      owner_uuid = stops->next->data;
      assert (stops->next->next);
      task_uuid = stops->next->next->data;

      head = stops;
      stops = stops->next->next->next;
      g_slist_free_1 (head->next->next);
      g_slist_free_1 (head->next);
      g_slist_free_1 (head);

      /* TODO As with starts above, this should retry if the stop failed. */

      /* Run the callback to fork a child connected to the Manager. */

      switch (fork_connection (&socket, &session, &credentials, owner_uuid))
        {
          case 0:
            /* Child.  Break, stop task, exit. */
            while (stops)
              {
                g_free (stops->data);
                stops = g_slist_delete_link (stops, stops);
              }
            break;

          case -1:
            /* Parent on error. */
            g_free (task_uuid);
            g_free (owner);
            g_free (owner_uuid);
            while (stops)
              {
                g_free (stops->data);
                stops = g_slist_delete_link (stops, stops);
              }
            g_warning ("%s: stop fork failed\n", __FUNCTION__);
            return -1;
            break;

          default:
            /* Parent.  Continue to next task. */
            g_free (task_uuid);
            g_free (owner);
            g_free (owner_uuid);
            continue;
            break;
        }

      /* Stop the task. */

      if (omp_authenticate (&session, owner, ""))
        {
          g_free (task_uuid);
          g_free (owner);
          g_free (owner_uuid);
          openvas_server_free (socket, session, credentials);
          exit (EXIT_FAILURE);
        }

      if (omp_stop_task (&session, task_uuid))
        {
          g_free (task_uuid);
          g_free (owner);
          g_free (owner_uuid);
          openvas_server_free (socket, session, credentials);
          exit (EXIT_FAILURE);
        }

      g_free (task_uuid);
      g_free (owner);
      g_free (owner_uuid);
      openvas_server_free (socket, session, credentials);
      exit (EXIT_SUCCESS);
   }

  return 0;
}


/* Report formats. */

/**
 * @brief Get the name of a report format param type.
 *
 * @param[in]  type  Param type.
 *
 * @return The name of the param type.
 */
const char *
report_format_param_type_name (report_format_param_type_t type)
{
  switch (type)
    {
      case REPORT_FORMAT_PARAM_TYPE_BOOLEAN:
        return "boolean";
      case REPORT_FORMAT_PARAM_TYPE_INTEGER:
        return "integer";
      case REPORT_FORMAT_PARAM_TYPE_SELECTION:
        return "selection";
      case REPORT_FORMAT_PARAM_TYPE_STRING:
        return "string";
      case REPORT_FORMAT_PARAM_TYPE_TEXT:
        return "text";
      default:
        assert (0);
      case REPORT_FORMAT_PARAM_TYPE_ERROR:
        return "ERROR";
    }
}

/**
 * @brief Get a report format param type from a name.
 *
 * @param[in]  name  Param type name.
 *
 * @return The param type.
 */
report_format_param_type_t
report_format_param_type_from_name (const char *name)
{
  if (strcmp (name, "boolean") == 0)
    return REPORT_FORMAT_PARAM_TYPE_BOOLEAN;
  if (strcmp (name, "integer") == 0)
    return REPORT_FORMAT_PARAM_TYPE_INTEGER;
  if (strcmp (name, "selection") == 0)
    return REPORT_FORMAT_PARAM_TYPE_SELECTION;
  if (strcmp (name, "string") == 0)
    return REPORT_FORMAT_PARAM_TYPE_STRING;
  if (strcmp (name, "text") == 0)
    return REPORT_FORMAT_PARAM_TYPE_TEXT;
  return REPORT_FORMAT_PARAM_TYPE_ERROR;
}

/**
 * @brief Return whether a name is a backup file name.
 *
 * @return 0 if normal file name, 1 if backup file name.
 */
static int
backup_file_name (const char *name)
{
  int length = strlen (name);

  if (length && (name[length - 1] == '~'))
    return 1;

  if ((length > 3)
      && (name[length - 4] == '.'))
    return ((name[length - 3] == 'b')
            && (name[length - 2] == 'a')
            && (name[length - 1] == 'k'))
           || ((name[length - 3] == 'B')
               && (name[length - 2] == 'A')
               && (name[length - 1] == 'K'))
           || ((name[length - 3] == 'C')
               && (name[length - 2] == 'K')
               && (name[length - 1] == 'P'));

  return 0;
}

/**
 * @brief Get files associated with a report format.
 *
 * @param[in]   dir_name  Location of files.
 * @param[out]  start     Files on success.
 *
 * @return 0 if successful, -1 otherwise.
 */
static int
get_report_format_files (const char *dir_name, GPtrArray **start)
{
  GPtrArray *files;
  struct dirent **names;
  int n, index;
  char *locale;

  files = g_ptr_array_new ();

  locale = setlocale (LC_ALL, "C");
  n = scandir (dir_name, &names, NULL, alphasort);
  setlocale (LC_ALL, locale);
  if (n < 0)
    {
      g_warning ("%s: failed to open dir %s: %s\n",
                 __FUNCTION__,
                 dir_name,
                 strerror (errno));
      return -1;
    }

  for (index = 0; index < n; index++)
    {
      if (strcmp (names[index]->d_name, ".")
          && strcmp (names[index]->d_name, "..")
          && (backup_file_name (names[index]->d_name) == 0))
        g_ptr_array_add (files, g_strdup (names[index]->d_name));
      free (names[index]);
    }
  free (names);

  g_ptr_array_add (files, NULL);

  *start = files;
  return 0;
}

/**
 * @brief Initialise a report format file iterator.
 *
 * @param[in]  iterator       Iterator.
 * @param[in]  report_format  Single report format to iterate over, NULL for
 *                            all.
 *
 * @return 0 on success, -1 on error.
 */
int
init_report_format_file_iterator (file_iterator_t* iterator,
                                  report_format_t report_format)
{
  gchar *dir_name, *uuid;

  uuid = report_format_uuid (report_format);
  if (uuid == NULL)
    return -1;

  if (report_format_global (report_format))
    dir_name = g_build_filename (OPENVAS_DATA_DIR,
                                 "openvasmd",
                                 "global_report_formats",
                                 uuid,
                                 NULL);
  else
    {
      gchar *owner_uuid;

      owner_uuid = report_format_owner_uuid (report_format);
      if (owner_uuid == NULL)
        return -1;
      dir_name = g_build_filename (OPENVAS_STATE_DIR,
                                   "openvasmd",
                                   "report_formats",
                                   owner_uuid,
                                   uuid,
                                   NULL);
      g_free (owner_uuid);
    }

  g_free (uuid);

  if (get_report_format_files (dir_name, &iterator->start))
    {
      g_free (dir_name);
      return -1;
    }

  iterator->current = iterator->start->pdata;
  iterator->current--;
  iterator->dir_name = dir_name;
  return 0;
}

/**
 * @brief Cleanup a report type iterator.
 *
 * @param[in]  iterator  Iterator.
 */
void
cleanup_file_iterator (file_iterator_t* iterator)
{
  array_free (iterator->start);
  g_free (iterator->dir_name);
}

/**
 * @brief Increment a report type iterator.
 *
 * The caller must stop using this after it returns FALSE.
 *
 * @param[in]  iterator  Task iterator.
 *
 * @return TRUE if there was a next item, else FALSE.
 */
gboolean
next_file (file_iterator_t* iterator)
{
  iterator->current++;
  if (*iterator->current == NULL) return FALSE;
  return TRUE;
}

/**
 * @brief Return the name from a file iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return File name.
 */
const char*
file_iterator_name (file_iterator_t* iterator)
{
  return (const char*) *iterator->current;
}

/**
 * @brief Return the file contents from a file iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Freshly allocated file contents, in base64.
 */
gchar*
file_iterator_content_64 (file_iterator_t* iterator)
{
  gchar *path_name, *content;
  GError *error;
  gsize content_size;

  path_name = g_build_filename (iterator->dir_name,
                                (gchar*) *iterator->current,
                                NULL);

  /* Read in the contents. */

  error = NULL;
  if (g_file_get_contents (path_name,
                           &content,
                           &content_size,
                           &error)
      == FALSE)
    {
      if (error)
        {
          g_debug ("%s: failed to read %s: %s",
                   __FUNCTION__, path_name, error->message);
          g_error_free (error);
        }
      g_free (path_name);
      return NULL;
    }

  g_free (path_name);

  /* Base64 encode the contents. */

  if (content && (content_size > 0))
    {
      gchar *base64 = g_base64_encode ((guchar*) content, content_size);
      g_free (content);
      return base64;
    }

  return content;
}


/* Scanner Tags. */

/**
 * @brief Split up the tags received from the scanner.
 *
 * @param[in]  scanner_tags  The tags sent by the scanner.
 * @param[out] tags          Tags.
 * @param[out] cvss_base     CVSS base.
 * @param[out] risk_factor   Risk factor.
 */
void
parse_tags (const char *scanner_tags, gchar **tags, gchar **cvss_base,
            gchar **risk_factor)
{
  gchar **split, **point;
  GString *tags_buffer;
  gboolean first;

  tags_buffer = g_string_new ("");
  split = g_strsplit (scanner_tags, "|", 0);
  point = split;
  *cvss_base = NULL;
  *risk_factor = NULL;
  first = TRUE;

  while (*point)
    {
      if (strncmp (*point, "cvss_base=", strlen ("cvss_base=")) == 0)
        {
          if (*cvss_base == NULL)
            *cvss_base = g_strdup (*point + strlen ("cvss_base="));
        }
      else if (strncmp (*point, "risk_factor=", strlen ("risk_factor=")) == 0)
        {
          if (*risk_factor == NULL)
            *risk_factor = g_strdup (*point + strlen ("risk_factor="));
        }
      else
        {
          if (first)
            first = FALSE;
          else
            g_string_append_c (tags_buffer, '|');
          g_string_append (tags_buffer, *point);
        }
      point++;
    }

  if (tags_buffer->len == 0)
    {
      g_string_free (tags_buffer, TRUE);
      *tags = g_strdup ("NOTAG");
    }
  else
    *tags = g_string_free (tags_buffer, FALSE);
  g_strfreev (split);
}


/* Slaves. */

/**
 * @brief Delete a task on a slave.
 *
 * @param[in]   slave            The slave.
 * @param[in]   slave_task_uuid  UUID of task on slave.
 *
 * @return 0 success, -1 error.
 */
int
delete_slave_task (slave_t slave, const char *slave_task_uuid)
{
  int socket;
  gnutls_session_t session;
  char *host;
  int port;
  entity_t get_tasks, get_targets, entity, task, credential;
  const char *slave_config_uuid, *slave_target_uuid;
  const char *slave_ssh_credential_uuid, *slave_smb_credential_uuid;

  omp_delete_opts_t del_opts = omp_delete_opts_ultimate_defaults;

  assert (slave);

  /* Connect to the slave. */

  host = slave_host (slave);
  if (host == NULL) return -1;

  tracef ("   %s: host: %s\n", __FUNCTION__, host);

  port = slave_port (slave);
  if (port == -1)
    {
      free (host);
      return -1;
    }

  socket = openvas_server_open (&session, host, port);
  free (host);
  if (socket == -1) return -1;

  tracef ("   %s: connected\n", __FUNCTION__);

  /* Authenticate using the slave login. */

  if (slave_authenticate (&session, slave))
    goto fail;

  tracef ("   %s: authenticated\n", __FUNCTION__);

  /* Get the UUIDs of the slave resources. */

  if (omp_get_tasks (&session, slave_task_uuid, 0, 0, &get_tasks))
    goto fail;

  task = entity_child (get_tasks, "task");
  if (task == NULL)
    goto fail_free_task;

  entity = entity_child (task, "config");
  if (entity == NULL)
    goto fail_free_task;
  slave_config_uuid = entity_attribute (entity, "id");

  entity = entity_child (task, "target");
  if (entity == NULL)
    goto fail_free_task;
  slave_target_uuid = entity_attribute (entity, "id");

  if (omp_get_targets (&session, slave_target_uuid, 0, 0, &get_targets))
    goto fail_free_task;

  entity = entity_child (get_targets, "target");
  if (entity == NULL)
    goto fail_free;

  credential = entity_child (entity, "ssh_lsc_credential");
  if (credential == NULL)
    goto fail_free;
  slave_ssh_credential_uuid = entity_attribute (credential, "id");

  credential = entity_child (entity, "smb_lsc_credential");
  if (credential == NULL)
    goto fail_free;
  slave_smb_credential_uuid = entity_attribute (credential, "id");

  /* Remove the slave resources. */

  omp_stop_task (&session, slave_task_uuid);
  if (omp_delete_task_ext (&session, slave_task_uuid, del_opts))
    goto fail_config;
  if (omp_delete_config_ext (&session, slave_config_uuid, del_opts))
    goto fail_target;
  if (omp_delete_target_ext (&session, slave_target_uuid, del_opts))
    goto fail_credential;
  if (omp_delete_lsc_credential_ext (&session, slave_smb_credential_uuid,
                                     del_opts))
    goto fail;
  if (omp_delete_lsc_credential_ext (&session, slave_ssh_credential_uuid,
                                     del_opts))
    goto fail;

  /* Cleanup. */

  free_entity (get_targets);
  free_entity (get_tasks);
  openvas_server_close (socket, session);
  return 0;

 fail_config:
  omp_delete_config_ext (&session, slave_config_uuid, del_opts);
 fail_target:
  omp_delete_target_ext (&session, slave_target_uuid, del_opts);
 fail_credential:
  omp_delete_lsc_credential_ext (&session, slave_smb_credential_uuid, del_opts);
  omp_delete_lsc_credential_ext (&session, slave_ssh_credential_uuid, del_opts);
 fail_free:
  free_entity (get_targets);
 fail_free_task:
  free_entity (get_tasks);
 fail:
  openvas_server_close (socket, session);
  return -1;
}

/* Resource types */

/**
 * @brief Check whether a resource type table name is valid.
 *
 * @param[in]  type  Type of resource.
 *
 * @return 1 yes, 0 no.
 */
int
valid_db_resource_type (const char* type)
{
  if (type == NULL)
    return 0;

  return (strcasecmp (type, "agent") == 0)
         || (strcasecmp (type, "alert") == 0)
         || (strcasecmp (type, "config") == 0)
         || (strcasecmp (type, "cpe") == 0)
         || (strcasecmp (type, "cve") == 0)
         || (strcasecmp (type, "lsc_credential") == 0)
         || (strcasecmp (type, "dfn_cert_adv") == 0)
         || (strcasecmp (type, "filter") == 0)
         || (strcasecmp (type, "group") == 0)
         || (strcasecmp (type, "note") == 0)
         || (strcasecmp (type, "nvt") == 0)
         || (strcasecmp (type, "ovaldef") == 0)
         || (strcasecmp (type, "override") == 0)
         || (strcasecmp (type, "port_list") == 0)
         || (strcasecmp (type, "permission") == 0)
         || (strcasecmp (type, "report") == 0)
         || (strcasecmp (type, "report_format") == 0)
         || (strcasecmp (type, "result") == 0)
         || (strcasecmp (type, "role") == 0)
         || (strcasecmp (type, "schedule") == 0)
         || (strcasecmp (type, "slave") == 0)
         || (strcasecmp (type, "tag") == 0)
         || (strcasecmp (type, "target") == 0)
         || (strcasecmp (type, "task") == 0)
         || (strcasecmp (type, "user") == 0);
}


/**
 * @brief Return the path to the CPE dictionary.
 *
 * @return A dynamically allocated string (to be g_free'd) containing the
 *         path to the desired file.
 */
static char *
get_cpe_filename ()
{
  return g_strdup (CPE_DICT_FILENAME);
}

/**
 * @brief Compute the filename where a given CVE can be found.
 *
 * @param[in] item_id   Full CVE identifier ("CVE-YYYY-ZZZZ").
 *
 * @return A dynamically allocated string (to be g_free'd) containing the
 *         path to the desired file or NULL on error.
 */
static char *
get_cve_filename (char *item_id)
{
  int year;

  if (sscanf (item_id, "%*3s-%d-%*d", &year) == 1)
    {
      /* CVEs before 2002 are stored in the 2002 file. */
      if (year <= 2002)
        year = 2002;
      return g_strdup_printf (CVE_FILENAME_FMT, year);
    }
  return NULL;
}

/**
 * @brief Get the filename where a given OVAL definition can be found.
 *
 * @param[in] item_id   Full OVAL identifier with file suffix.
 *
 * @return A dynamically allocated string (to be g_free'd) containing the
 *         path to the desired file or NULL on error.
 */
static char *
get_ovaldef_filename (char *item_id)
{
  char *result, *short_filename;

  result = NULL;
  short_filename = get_ovaldef_short_filename (item_id);

  if (*short_filename)
    {
      result = g_strdup_printf ("%s/%s", SCAP_DATA_DIR, short_filename);
    }
  free (short_filename);

  return result;
}

/**
 * @brief Compute the filename where a given DFN-CERT Advisory can be found.
 *
 * @param[in] item_id   Full DFN-CERT identifier ("DFN-CERT-YYYY-ZZZZ").
 *
 * @return A dynamically allocated string (to be g_free'd) containing the
 *         path to the desired file or NULL on error.
 */
static char *
get_dfn_cert_adv_filename (char *item_id)
{
  int year;

  if (sscanf (item_id, "DFN-CERT-%d-%*s", &year) == 1)
    {
      return g_strdup_printf (DFN_CERT_ADV_FILENAME_FMT, year);
    }
  return NULL;
}

/**
 * @brief Run xsltproc in an external process.
 *
 * @param[in] stylesheet    XSL stylesheet to use.
 * @param[in] xmlfile       XML file to process.
 * @param[in] param_names   NULL terminated array of stringparam names (can
 *                          be NULL).
 * @param[in] param_values  NULL terminated array of stringparam values (can
 *                          be NULL).
 *
 * @return A dynamically allocated (to be g_free'd) string containing the
 *         result of the operation of NULL on failure.
 */
gchar *
xsl_transform (gchar *stylesheet, gchar *xmlfile, gchar **param_names,
               gchar **param_values)
{
  int i, param_idx;
  gchar **cmd, *cmd_full;
  gint exit_status;
  gboolean success;
  gchar *standard_out = NULL, *standard_err = NULL;

  param_idx = 0;
  if (param_names && param_values)
    while (param_names[param_idx] && param_values[param_idx])
      param_idx++;

  cmd = (gchar **)g_malloc ((4 + param_idx * 3) * sizeof (gchar *));

  i = 0;
  cmd[i++] = "xsltproc";
  if (param_idx)
    {
      int j;

      for (j = 0; j < param_idx; j++)
        {
          cmd[i++] = "--stringparam";
          cmd[i++] = param_names[j];
          cmd[i++] = param_values[j];
        }
    }
  cmd[i++] = stylesheet;
  cmd[i++] = xmlfile;
  cmd[i] = NULL;


  /* DEBUG: display the final command line. */
  cmd_full = g_strjoinv (" ", cmd);
  g_debug ("%s: Spawning in parent dir: %s\n",
           __FUNCTION__, cmd_full);
  g_free (cmd_full);
  /* --- */

  if ((g_spawn_sync (NULL,
                     cmd,
                     NULL,                  /* Environment. */
                     G_SPAWN_SEARCH_PATH,
                     NULL,                  /* Setup function. */
                     NULL,
                     &standard_out,
                     &standard_err,
                     &exit_status,
                     NULL)
       == FALSE)
      || (WIFEXITED (exit_status) == 0)
      || WEXITSTATUS (exit_status))
    {
      g_debug ("%s: failed to transform the xml: %d (WIF %i, WEX %i)",
               __FUNCTION__,
               exit_status,
               WIFEXITED (exit_status),
               WEXITSTATUS (exit_status));
      g_debug ("%s: stderr: %s\n", __FUNCTION__, standard_err);
      g_debug ("%s: stdout: %s\n", __FUNCTION__, standard_out);
      success = FALSE;
    }
  else if (strlen (standard_out) == 0)
    success = FALSE; /* execution succeeded but nothing was found */
  else
    success = TRUE; /* execution succeeded and we have a result */

  /* Cleanup. */
  g_free (cmd);
  g_free (standard_err);

  if (success)
    return standard_out;

  g_free (standard_out);
  return NULL;
}

/**
 * @brief Return the name of a category.
 *
 * @param  category  The number of the category.
 *
 * @return The name of the category.
 */
static const char*
category_name (int category)
{
  static const char *categories[] = { ACT_STRING_LIST_ALL };
  if (category >= ACT_FIRST && category <= ACT_END)
    {
      return categories[category];
    }
  return categories[ACT_UNKNOWN];
}

/**
 * @brief Define a code snippet for get_nvti_xml.
 *
 * @param  x  Prefix for names in snippet.
 */
#define DEF(x)                                                    \
      const char* x = nvt_iterator_ ## x (nvts);                  \
      gchar* x ## _text = x                                       \
                          ? g_markup_escape_text (x, -1)          \
                          : g_strdup ("");

/**
 * @brief Create and return XML description for an NVT.
 *
 * @param[in]  nvts        The NVT.
 * @param[in]  details     If true, detailed XML, else simple XML.
 * @param[in]  pref_count  Preference count.  Used if details is true.
 * @param[in]  timeout     Timeout.  Used if details is true.
 * @param[in]  close_tag   Wether to close the NVT tag or not.
 *
 * @return A dynamically allocated string containing the XML description.
 */
gchar *
get_nvti_xml (iterator_t *nvts, int details, int pref_count,
              const char *timeout, int close_tag)
{
  const char* oid = nvt_iterator_oid (nvts);
  const char* name = nvt_iterator_name (nvts);
  gchar* msg;

  gchar* name_text = g_markup_escape_text (name, strlen (name));
  if (details)
    {
      GString *cert_refs_str, *tags_str;
      iterator_t cert_refs_iterator, tags;
      gchar *tag_name_esc, *tag_value_esc, *tag_comment_esc;

#ifndef S_SPLINT_S
      DEF (copyright);
      DEF (summary);
      DEF (family);
      DEF (version);
      DEF (xref);
      DEF (tag);
#endif /* not S_SPLINT_S */

#undef DEF

      cert_refs_str = g_string_new ("");
      if (manage_cert_loaded())
        {
          init_nvt_dfn_cert_adv_iterator (&cert_refs_iterator, oid, 0, 0);
          while (next (&cert_refs_iterator))
            {
              g_string_append_printf (cert_refs_str,
                                      "<cert_ref type=\"DFN-CERT\" id=\"%s\"/>",
                                      get_iterator_name (&cert_refs_iterator));
          }
          cleanup_iterator (&cert_refs_iterator);
        }
      else
        {
          g_string_append(cert_refs_str, "<warning>database not available</warning>");
        }

      tags_str = g_string_new ("");
      g_string_append_printf (tags_str,
                              "<count>%i</count>",
                              resource_tag_count ("nvt",
                                                  get_iterator_resource
                                                    (nvts),
                                                  1));

      init_resource_tag_iterator (&tags, "nvt",
                                  get_iterator_resource (nvts),
                                  1, NULL, 1);
      while (next (&tags))
        {
          tag_name_esc = g_markup_escape_text (resource_tag_iterator_name
                                                (&tags),
                                               -1);
          tag_value_esc = g_markup_escape_text (resource_tag_iterator_value
                                                  (&tags),
                                                -1);
          tag_comment_esc = g_markup_escape_text (resource_tag_iterator_comment
                                                    (&tags),
                                                  -1);
          g_string_append_printf (tags_str,
                                  "<tag id=\"%s\">"
                                  "<name>%s</name>"
                                  "<value>%s</value>"
                                  "<comment>%s</comment>"
                                  "</tag>",
                                  resource_tag_iterator_uuid (&tags),
                                  tag_name_esc,
                                  tag_value_esc,
                                  tag_comment_esc);
          g_free (tag_name_esc);
          g_free (tag_value_esc);
          g_free (tag_comment_esc);
        }
      cleanup_iterator (&tags);

      msg = g_strdup_printf ("<nvt"
                             " oid=\"%s\">"
                             "<name>%s</name>"
                             "<creation_time>%s</creation_time>"
                             "<modification_time>%s</modification_time>"
                             "<user_tags>%s</user_tags>"
                             "<category>%s</category>"
                             "<copyright>%s</copyright>"
                             "<summary>%s</summary>"
                             "<family>%s</family>"
                             "<version>%s</version>"
                             "<cvss_base>%s</cvss_base>"
                             "<cve_id>%s</cve_id>"
                             "<bugtraq_id>%s</bugtraq_id>"
                             "<cert_refs>%s</cert_refs>"
                             "<xrefs>%s</xrefs>"
                             "<tags>%s</tags>"
                             "<preference_count>%i</preference_count>"
                             "<timeout>%s</timeout>"
                             "<checksum>"
                             "<algorithm>md5</algorithm>"
                             /** @todo Implement checksum. */
                             "2397586ea5cd3a69f953836f7be9ef7b"
                             "</checksum>%s",
                             oid,
                             name_text,
                             get_iterator_creation_time (nvts)
                              ? get_iterator_creation_time (nvts)
                              : "",
                             get_iterator_modification_time (nvts)
                              ? get_iterator_modification_time (nvts)
                              : "",
                             tags_str->str,
                             category_name (nvt_iterator_category (nvts)),
                             copyright_text,
                             summary_text,
                             family_text,
                             version_text,
                             nvt_iterator_cvss_base (nvts)
                              ? nvt_iterator_cvss_base (nvts)
                              : "",
                             nvt_iterator_cve (nvts),
                             nvt_iterator_bid (nvts),
                             cert_refs_str->str,
                             xref_text,
                             tag_text,
                             pref_count,
                             timeout ? timeout : "",
                             close_tag ? "</nvt>" : "");
      g_free (copyright_text);
      g_free (summary_text);
      g_free (family_text);
      g_free (version_text);
      g_free (xref_text);
      g_free (tag_text);
      g_string_free(cert_refs_str, 1);
      g_string_free(tags_str, 1);

    }
  else
    msg = g_strdup_printf ("<nvt"
                           " oid=\"%s\">"
                           "<name>%s</name>"
                           "<user_tags>"
                           "<count>%i</count>"
                           "</user_tags>"
                           "<checksum>"
                           "<algorithm>md5</algorithm>"
                            /** @todo Implement checksum. */
                           "2397586ea5cd3a69f953836f7be9ef7b"
                           "</checksum>",
                           oid,
                           name_text,
                           resource_tag_count ("nvt",
                                                get_iterator_resource
                                                  (nvts),
                                                1));
  g_free (name_text);
  return msg;
}

/**
 * @brief GET SCAP update time, as a string.
 *
 * @return Last update time as a static string, or "" on error.
 */
const char *
manage_scap_update_time ()
{
  gchar *content;
  GError *error;
  gsize content_size;
  struct tm update_time;

  /* Read in the contents. */

  error = NULL;
  if (g_file_get_contents (SCAP_TIMESTAMP_FILENAME,
                           &content,
                           &content_size,
                           &error)
      == FALSE)
    {
      if (error)
        {
          g_debug ("%s: failed to read %s: %s",
                   __FUNCTION__, SCAP_TIMESTAMP_FILENAME, error->message);
          g_error_free (error);
        }
      return "";
    }

  memset (&update_time, 0, sizeof (struct tm));
  if (strptime (content, "%Y%m%d%H%M", &update_time))
    {
      static char time_string[100];
      strftime (time_string, 99, "%FT%T.000%z", &update_time);
      return time_string;
    }
  return "";
}

/**
 * @brief Read raw information.
 *
 * @param[in]   type    Type of the requested information.
 * @param[in]   uid     Unique identifier of the requested information
 * @param[in]   name    Name or identifier of the requested information.
 * @param[out]  result  Pointer to the read information location. Will point
 *                      to NULL on error.
 *
 * @return 1 success, -1 error.
 */
int
manage_read_info (gchar *type, gchar *uid, gchar *name, gchar **result)
{
  gchar *fname;
  gchar *pnames[2] = { "refname", NULL };
  gchar *pvalues[2] = { name, NULL };

  assert (result != NULL);
  *result = NULL;

  if (g_ascii_strcasecmp ("CPE", type) == 0)
    {
      fname = get_cpe_filename ();
      if (fname)
        {
          gchar *cpe;
          cpe = xsl_transform (CPE_GETBYNAME_XSL, fname, pnames, pvalues);
          g_free (fname);
          if (cpe)
            *result = cpe;
        }
    }
  else if (g_ascii_strcasecmp ("CVE", type) == 0)
    {
      fname = get_cve_filename (uid);
      if (fname)
        {
          gchar *cve;
          cve = xsl_transform (CVE_GETBYNAME_XSL, fname, pnames, pvalues);
          g_free (fname);
          if (cve)
            *result = cve;
        }
    }
  else if (g_ascii_strcasecmp ("NVT", type) == 0)
    {
      iterator_t nvts;
      nvt_t nvt;

      if (!find_nvt (name, &nvt) && nvt)
        {
          init_nvt_iterator (&nvts, nvt, 0, NULL, NULL, 0, NULL);

          if (next (&nvts))
            *result = get_nvti_xml (&nvts, 1, 0, NULL, 1);

          cleanup_iterator (&nvts);
        }
    }
  else if (g_ascii_strcasecmp ("OVALDEF", type) == 0)
    {
      fname = get_ovaldef_filename (uid);
      if (fname)
        {
          gchar *ovaldef;
          ovaldef = xsl_transform (OVALDEF_GETBYNAME_XSL, fname,
                                   pnames, pvalues);
          g_free (fname);
          if (ovaldef)
            *result = ovaldef;
        }
    }
  else if (g_ascii_strcasecmp ("DFN_CERT_ADV", type) == 0)
    {
      fname = get_dfn_cert_adv_filename (uid);
      if (fname)
        {
          gchar *adv;
          adv = xsl_transform (DFN_CERT_ADV_GETBYNAME_XSL, fname,
                               pnames, pvalues);
          g_free (fname);
          if (adv)
            *result = adv;
        }
    }

  if (*result == NULL)
    return -1;

  return 1;
}


/* Users. */

/**
 * @brief Produce a stripped-down xml representation of a keyfile.
 *
 * For
 * @code
 * [first group]
 * # this comment will be lost
 * weather=good
 * example=bad
 * [empty group]
 * @endcode
 * the output will look like
 * @code
 * <group name="first group">
 * <auth_conf_setting key="weather" value="good"/>
 * <auth_conf_setting key="example" value="bad"/>
 * </group>
 * <group name="empty group">
 * </group>
 * @endcode
 *
 * @param[in]  filename  Keyfile to read.
 *
 * @return NULL in case of any error, otherwise xml representation of keyfile
 *         (free with g_free).
 */
gchar *
keyfile_to_auth_conf_settings_xml (const gchar * filename)
{
  GKeyFile *key_file = g_key_file_new ();
  GString *response = NULL;
  gchar **groups = NULL;
  gchar **group = NULL;

  if (g_key_file_load_from_file (key_file, filename, G_KEY_FILE_NONE, NULL)
      == FALSE)
    {
      g_key_file_free (key_file);
      return NULL;
    }

  response = g_string_new ("");

  groups = g_key_file_get_groups (key_file, NULL);

  group = groups;
  while (*group != NULL)
    {
      gchar **keys = g_key_file_get_keys (key_file, *group, NULL, NULL);
      gchar **key = keys;
      g_string_append_printf (response, "<group name=\"%s\">\n", *group);
      while (*key != NULL)
        {
          gchar *value = g_key_file_get_value (key_file, *group, *key, NULL);
          if (value)
            g_string_append_printf (response,
                                    "<auth_conf_setting key=\"%s\" value=\"%s\"/>",
                                    *key, value);
          g_free (value);
          key++;
        }
      g_strfreev (keys);
      g_string_append (response, "</group>");
      group++;
    }

  g_strfreev (groups);
  g_key_file_free (key_file);

  return g_string_free (response, FALSE);
}

/**
 *
 * @brief Validates a username.
 *
 * @param[in]  name  The name.
 *
 * @return 0 if the username is valid, 1 if not.
 */
int
validate_username (const gchar * name)
{
  if (g_regex_match_simple ("^[[:alnum:]-_]+$", name, 0, 0))
    return 0;
  else
    return 1;
}


/* Feeds. */

/**
 * @brief Request a feed synchronization script selftest.
 *
 * Ask a feed synchronization script to perform a selftest and report
 * the results.
 *
 * @param[in]   sync_script  The file name of the synchronization script.
 * @param[out]  result       Return location for selftest errors, or NULL.
 *
 * @return TRUE if the selftest was successful, or FALSE if an error occured.
 */
gboolean
openvas_sync_script_perform_selftest (const gchar * sync_script,
                                      gchar ** result)
{
  g_assert (sync_script);
  g_assert_cmpstr (*result, ==, NULL);

  gchar *script_working_dir = g_path_get_dirname (sync_script);

  gchar **argv = (gchar **) g_malloc (3 * sizeof (gchar *));
  argv[0] = g_strdup (sync_script);
  argv[1] = g_strdup ("--selftest");
  argv[2] = NULL;

  gchar *script_out;
  gchar *script_err;
  gint script_exit;
  GError *error = NULL;

  if (!g_spawn_sync
      (script_working_dir, argv, NULL, 0, NULL, NULL, &script_out, &script_err,
       &script_exit, &error))
    {
      if (*result != NULL)
        {
          *result =
            g_strdup_printf ("Failed to execute synchronization " "script: %s",
                             error->message);
        }

      g_free (script_working_dir);
      g_strfreev (argv);
      g_free (script_out);
      g_free (script_err);
      g_error_free (error);

      return FALSE;
    }

  if (script_exit != 0)
    {
      if (script_err != NULL)
        {
          *result = g_strdup_printf ("%s", script_err);
        }

      g_free (script_working_dir);
      g_strfreev (argv);
      g_free (script_out);
      g_free (script_err);

      return FALSE;
    }

  g_free (script_working_dir);
  g_strfreev (argv);
  g_free (script_out);
  g_free (script_err);

  return TRUE;
}

/**
 * @brief Retrieves the ID string of a feed sync script, with basic validation.
 *
 * @param[in]   sync_script     The file name of the synchronization script.
 * @param[out]  identification  Return location of the identification string.
 * @param[in]   feed_type       Could be NVT_FEED, SCAP_FEED or CERT_FEED.
 *
 * @return TRUE if the identification string was retrieved, or FALSE if an
 *         error occured.
 */
gboolean
openvas_get_sync_script_identification (const gchar * sync_script,
                                        gchar ** identification,
                                        int feed_type)
{
  g_assert (sync_script);
  if (identification)
    g_assert_cmpstr (*identification, ==, NULL);

  gchar *script_working_dir = g_path_get_dirname (sync_script);

  gchar **argv = (gchar **) g_malloc (3 * sizeof (gchar *));
  argv[0] = g_strdup (sync_script);
  argv[1] = g_strdup ("--identify");
  argv[2] = NULL;

  gchar *script_out;
  gchar *script_err;
  gint script_exit;
  GError *error = NULL;

  gchar **script_identification;

  if (!g_spawn_sync
      (script_working_dir, argv, NULL, 0, NULL, NULL, &script_out, &script_err,
       &script_exit, &error))
    {
      g_warning ("Failed to execute %s: %s", sync_script, error->message);

      g_free (script_working_dir);
      g_strfreev (argv);
      g_free (script_out);
      g_free (script_err);
      g_error_free (error);

      return FALSE;
    }

  if (script_exit != 0)
    {
      g_warning ("%s returned a non-zero exit code.", sync_script);

      g_free (script_working_dir);
      g_strfreev (argv);
      g_free (script_out);
      g_free (script_err);

      return FALSE;
    }

  script_identification = g_strsplit (script_out, "|", 6);

  if ((script_identification[0] == NULL)
      || (feed_type == NVT_FEED
          && g_ascii_strncasecmp (script_identification[0],"NVTSYNC",7))
      || (feed_type == SCAP_FEED
          && g_ascii_strncasecmp (script_identification[0],"SCAPSYNC",7))
      || (feed_type == CERT_FEED
          && g_ascii_strncasecmp (script_identification[0],"CERTSYNC",7))
      || g_ascii_strncasecmp (script_identification[0], script_identification[5], 7))
    {
      g_warning ("%s is not a NVT synchronization script.", sync_script);

      g_free (script_working_dir);
      g_strfreev (argv);
      g_free (script_out);
      g_free (script_err);

      g_strfreev (script_identification);

      return FALSE;
    }

  if (identification)
    *identification = g_strdup (script_out);

  g_free (script_working_dir);
  g_strfreev (argv);
  g_free (script_out);
  g_free (script_err);

  g_strfreev (script_identification);

  return TRUE;
}

/**
 * @brief Retrieves description of a feed sync script, with basic validation.
 *
 * @param[in]   sync_script  The file name of the synchronization script.
 * @param[out]  description  Return location of the description string.
 *
 * @return TRUE if the description was retrieved, or FALSE if an error
 *         occured.
 */
gboolean
openvas_get_sync_script_description (const gchar * sync_script,
                                     gchar ** description)
{
  g_assert (sync_script);
  g_assert_cmpstr (*description, ==, NULL);

  gchar *script_working_dir = g_path_get_dirname (sync_script);

  gchar **argv = (gchar **) g_malloc (3 * sizeof (gchar *));
  argv[0] = g_strdup (sync_script);
  argv[1] = g_strdup ("--describe");
  argv[2] = NULL;

  gchar *script_out;
  gchar *script_err;
  gint script_exit;
  GError *error = NULL;

  if (!g_spawn_sync
      (script_working_dir, argv, NULL, 0, NULL, NULL, &script_out, &script_err,
       &script_exit, &error))
    {
      g_warning ("Failed to execute %s: %s", sync_script, error->message);

      g_free (script_working_dir);
      g_strfreev (argv);
      g_free (script_out);
      g_free (script_err);
      g_error_free (error);

      return FALSE;
    }

  if (script_exit != 0)
    {
      g_warning ("%s returned a non-zero exit code.", sync_script);

      g_free (script_working_dir);
      g_strfreev (argv);
      g_free (script_out);
      g_free (script_err);

      return FALSE;
    }

  *description = g_strdup (script_out);

  g_free (script_working_dir);
  g_strfreev (argv);
  g_free (script_out);
  g_free (script_err);

  return TRUE;
}

/**
 * @brief Retrieves the version of a feed handled by the sync, with basic
 * validation.
 *
 * @param[in]   sync_script  The file name of the synchronization script.
 * @param[out]  feed_version  Return location of the feed version string.
 *
 * @return TRUE if the feed version was retrieved, or FALSE if an error
 *         occured.
 */
gboolean
openvas_get_sync_script_feed_version (const gchar * sync_script,
                                      gchar ** feed_version)
{
  g_assert (sync_script);
  g_assert_cmpstr (*feed_version, ==, NULL);

  gchar *script_working_dir = g_path_get_dirname (sync_script);

  gchar **argv = (gchar **) g_malloc (3 * sizeof (gchar *));
  argv[0] = g_strdup (sync_script);
  argv[1] = g_strdup ("--feedversion");
  argv[2] = NULL;

  gchar *script_out;
  gchar *script_err;
  gint script_exit;
  GError *error = NULL;

  if (!g_spawn_sync
      (script_working_dir, argv, NULL, 0, NULL, NULL, &script_out, &script_err,
       &script_exit, &error))
    {
      g_warning ("Failed to execute %s: %s", sync_script, error->message);

      g_free (script_working_dir);
      g_strfreev (argv);
      g_free (script_out);
      g_free (script_err);
      g_error_free (error);

      return FALSE;
    }

  if (script_exit != 0)
    {
      g_warning ("%s returned a non-zero exit code.", sync_script);

      g_free (script_working_dir);
      g_strfreev (argv);
      g_free (script_out);
      g_free (script_err);

      return FALSE;
    }

  *feed_version = g_strdup (script_out);

  g_free (script_working_dir);
  g_strfreev (argv);
  g_free (script_out);
  g_free (script_err);

  return TRUE;
}

/**
 * @brief Forks a child to synchronize the local feed collection.
 *
 * The forked process calls a sync script to sync the feed.
 *
 * @param[in]  sync_script   The file name of the synchronization script.
 * @param[in]  current_user  The user currently authenticated.
 * @param[in]  feed_type     Could be NVT_FEED, SCAP_FEED or CERT_FEED.
 *
 * @return 0 sync requested (parent), 1 sync already in progress (parent),
 *         -1 error (parent), 2 sync complete (child), 11 sync in progress
 *         (child), -10 error (child), 99 permission denied.
 */
int
openvas_sync_feed (const gchar * sync_script, const gchar * current_user,
                   int feed_type)
{
  int fd, ret = 2;
  gchar *lockfile_name, *lockfile_dirname;
  gchar *script_identification_string = NULL;
  pid_t pid;
  mode_t old_mask;

  g_assert (sync_script);
  g_assert (current_user);

  if (user_may (feed_type == NVT_FEED
                 ? "sync_feed"
                 : (feed_type == SCAP_FEED)
                     ? "sync_scap"
                     : "sync_cert") == 0)
    return 99;

  if (!openvas_get_sync_script_identification
      (sync_script, &script_identification_string, feed_type))
    {
      g_warning ("No valid synchronization script supplied!");
      return -1;
    }

  /* Open the lock file. */

  lockfile_name =
    g_build_filename (g_get_tmp_dir (), "openvas-feed-sync", sync_script, NULL);
  lockfile_dirname = g_path_get_dirname (lockfile_name);
  old_mask = umask (0);
  if (g_mkdir_with_parents (lockfile_dirname,
                            /* "-rwxrwxrwx" */
                            S_IRWXU | S_IRWXG | S_IRWXO))
    {
      umask (old_mask);
      g_warning ("Failed to create lock dir '%s': %s", lockfile_dirname,
                 strerror (errno));
      g_free (lockfile_name);
      g_free (lockfile_dirname);
      return -1;
    }
  umask (old_mask);
  g_free (lockfile_dirname);

  fd =
    open (lockfile_name, O_RDWR | O_CREAT | O_EXCL,
          S_IWUSR | S_IRUSR | S_IROTH | S_IRGRP /* "-rw-r--r--" */ );
  if (fd == -1)
    {
      if (errno == EEXIST)
        return 1;
      g_warning ("Failed to open lock file '%s': %s", lockfile_name,
                 strerror (errno));
      g_free (lockfile_name);
      return -1;
    }

  /* Close and remove the lock file around the fork.  Another process may get
   * the lock here, in which case the child will simply fail to get the
   * lock. */

  if (close (fd))
    {
      g_free (lockfile_name);
      g_warning ("Failed to close lock file: %s", strerror (errno));
      return -1;
    }

  if (unlink (lockfile_name))
    {
      g_free (lockfile_name);
      g_warning ("Failed to remove lock file: %s", strerror (errno));
      return -1;
    }

  /* Setup SIGCHLD for waiting. */

  /* RATS: ignore, this is SIG_DFL damnit. */
  if (signal (SIGCHLD, SIG_DFL) == SIG_ERR)
    {
      g_warning ("Failed to set SIG_DFL");
      return -1;
    }

  /* Fork a child to run the sync while the parent responds to
   * the client. */

  pid = fork ();
  switch (pid)
    {
    case 0:
      /* Child.  Carry on to sync. */
      break;
    case -1:
      /* Parent when error. */
      g_warning ("%s: failed to fork sync child: %s\n", __FUNCTION__,
                 strerror (errno));
      return -1;
      break;
    default:
      /* Parent.  Return in order to respond to client. */
      return 0;
      break;
    }

  /* Open the lock file. */

  fd =
    open (lockfile_name, O_RDWR | O_CREAT | O_EXCL,
          S_IWUSR | S_IRUSR | S_IROTH | S_IRGRP /* "-rw-r--r--" */ );
  if (fd == -1)
    {
      if (errno == EEXIST)
        return 11;
      g_warning ("Failed to open lock file '%s' (child): %s", lockfile_name,
                 strerror (errno));
      g_free (lockfile_name);
      return -10;
    }

  /* Write the current time and user to the lock file. */

  {
    const char *output;
    int count, left;
    time_t now;

    time (&now);
    output = ctime (&now);
    left = strlen (output);
    while (1)
      {
        count = write (fd, output, left);
        if (count < 0)
          {
            if (errno == EINTR || errno == EAGAIN)
              continue;
            g_warning ("%s: write: %s", __FUNCTION__, strerror (errno));
            goto exit;
          }
        if (count == left)
          break;
        left -= count;
        output += count;
      }

    output = current_user;
    left = strlen (output);
    while (1)
      {
        count = write (fd, output, left);
        if (count < 0)
          {
            if (errno == EINTR || errno == EAGAIN)
              continue;
            g_warning ("%s: write: %s", __FUNCTION__, strerror (errno));
            goto exit;
          }
        if (count == left)
          break;
        left -= count;
        output += count;
      }

    while (1)
      {
        count = write (fd, "\n", 1);
        if (count < 0)
          {
            if (errno == EINTR || errno == EAGAIN)
              continue;
            g_warning ("%s: write: %s", __FUNCTION__, strerror (errno));
            goto exit;
          }
        if (count == 1)
          break;
      }
  }

  /* Fork a child to be the sync process. */

  pid = fork ();
  switch (pid)
    {
    case 0:
      {
        /* Child.  Become the sync process. */

        if (freopen ("/tmp/openvasad_sync_out", "w", stdout) == NULL)
          {
            g_warning ("Failed to reopen stdout: %s", strerror (errno));
            exit (EXIT_FAILURE);
          }

        if (freopen ("/tmp/openvasad_sync_err", "w", stderr) == NULL)
          {
            g_warning ("Failed to reopen stderr: %s", strerror (errno));
            exit (EXIT_FAILURE);
          }

        if (execl (sync_script, sync_script, (char *) NULL))
          {
            g_warning ("Failed to execl %s: %s", sync_script, strerror (errno));
            exit (EXIT_FAILURE);
          }
        /*@notreached@ */
        exit (EXIT_FAILURE);
        break;
      }
    case -1:
      /* Parent when error. */

      g_warning ("%s: failed to fork syncer: %s\n", __FUNCTION__,
                 strerror (errno));
      ret = -1;
      goto exit;
      break;
    default:
      {
        int status;

        /* Parent on success.  Wait for child, and handle result. */

        while (wait (&status) < 0)
          {
            if (errno == ECHILD)
              {
                g_warning ("Failed to get child exit status");
                ret = -10;
                goto exit;
              }
            if (errno == EINTR)
              continue;
            g_warning ("wait: %s", strerror (errno));
            ret = -10;
            goto exit;
          }
        if (WIFEXITED (status))
          switch (WEXITSTATUS (status))
            {
            case EXIT_SUCCESS:
              break;
            case EXIT_FAILURE:
            default:
              g_warning ("Error during synchronization.");
              ret = -10;
              break;
            }
        else
          {
            g_message ("Error during synchronization.");
            ret = -10;
          }

        break;
      }
    }

exit:

  /* Close the lock file. */

  if (close (fd))
    {
      g_free (lockfile_name);
      g_warning ("Failed to close lock file (child): %s", strerror (errno));
      return -10;
    }

  /* Remove the lock file. */

  if (unlink (lockfile_name))
    {
      g_free (lockfile_name);
      g_warning ("Failed to remove lock file (child): %s", strerror (errno));
      return -10;
    }

  g_free (lockfile_name);

  return ret;
}

/**
 * @brief Migrates SCAP or CERT database, waiting until migration terminates.
 *
 * Calls a sync script to migrate the SCAP or CERT database.
 *
 * @param[in]  sync_script   The file name of the synchronization script.
 * @param[in]  feed_type     Could be SCAP_FEED or CERT_FEED.
 *
 * @return 0 sync complete, 1 sync already in progress, -1 error
 */
int
openvas_migrate_secinfo (const gchar * sync_script, int feed_type)
{
  int fd, ret = 0;
  gchar *lockfile_name, *lockfile_dirname;
  pid_t pid;
  mode_t old_mask;

  g_assert (sync_script);

  if (feed_type != SCAP_FEED && feed_type != CERT_FEED)
    {
      g_warning ("Unsupported feed_type!");
      return -1;
    }

  if (!openvas_get_sync_script_identification
      (sync_script, NULL, feed_type))
    {
      g_warning ("No valid synchronization script supplied!");
      return -1;
    }

  /* Open the lock file. */

  lockfile_name =
    g_build_filename (g_get_tmp_dir (), "openvas-feed-sync", sync_script, NULL);
  lockfile_dirname = g_path_get_dirname (lockfile_name);
  old_mask = umask (0);
  if (g_mkdir_with_parents (lockfile_dirname,
                            /* "-rwxrwxrwx" */
                            S_IRWXU | S_IRWXG | S_IRWXO))
    {
      umask (old_mask);
      g_warning ("Failed to create lock dir '%s': %s", lockfile_dirname,
                 strerror (errno));
      g_free (lockfile_name);
      g_free (lockfile_dirname);
      return -1;
    }
  umask (old_mask);
  g_free (lockfile_dirname);

  fd =
    open (lockfile_name, O_RDWR | O_CREAT | O_EXCL,
          S_IWUSR | S_IRUSR | S_IROTH | S_IRGRP /* "-rw-r--r--" */ );
  if (fd == -1)
    {
      if (errno == EEXIST)
        return 1;
      g_warning ("Failed to open lock file '%s': %s", lockfile_name,
                 strerror (errno));
      g_free (lockfile_name);
      return -1;
    }

  /* Write the current time and user to the lock file. */
  {
    const char *output;
    int count, left;
    time_t now;

    time (&now);
    output = ctime (&now);
    left = strlen (output);
    while (1)
      {
        count = write (fd, output, left);
        if (count < 0)
          {
            if (errno == EINTR || errno == EAGAIN)
              continue;
            g_warning ("%s: write: %s", __FUNCTION__, strerror (errno));
            goto exit;
          }
        if (count == left)
          break;
        left -= count;
        output += count;
      }

    output = ""; // user name
    left = strlen (output);
    while (1)
      {
        count = write (fd, output, left);
        if (count < 0)
          {
            if (errno == EINTR || errno == EAGAIN)
              continue;
            g_warning ("%s: write: %s", __FUNCTION__, strerror (errno));
            goto exit;
          }
        if (count == left)
          break;
        left -= count;
        output += count;
      }

    while (1)
      {
        count = write (fd, "\n", 1);
        if (count < 0)
          {
            if (errno == EINTR || errno == EAGAIN)
              continue;
            g_warning ("%s: write: %s", __FUNCTION__, strerror (errno));
            goto exit;
          }
        if (count == 1)
          break;
      }
  }

  /* Fork a child to be the sync process. */

  pid = fork ();
  switch (pid)
    {
    case 0:
      {
        /* Child.  Become the sync process. */

        if (freopen ("/tmp/openvasad_sync_out", "w", stdout) == NULL)
          {
            g_warning ("Failed to reopen stdout: %s", strerror (errno));
            exit (EXIT_FAILURE);
          }

        if (freopen ("/tmp/openvasad_sync_err", "w", stderr) == NULL)
          {
            g_warning ("Failed to reopen stderr: %s", strerror (errno));
            exit (EXIT_FAILURE);
          }

        if (execl (sync_script, sync_script, "--migrate", (char *) NULL))
          {
            g_warning ("Failed to execl %s: %s", sync_script, strerror (errno));
            exit (EXIT_FAILURE);
          }
        /*@notreached@ */
        exit (EXIT_FAILURE);
        break;
      }
    case -1:
      /* Parent when error. */

      g_warning ("%s: failed to fork syncer: %s\n", __FUNCTION__,
                 strerror (errno));
      ret = -1;
      goto exit;
      break;
    default:
      {
        int status;

        /* Parent on success.  Wait for child, and handle result. */

        while (wait (&status) < 0)
          {
            if (errno == ECHILD)
              {
                g_warning ("Failed to get child exit status");
                ret = -1;
                goto exit;
              }
            if (errno == EINTR)
              continue;
            g_warning ("wait: %s", strerror (errno));
            ret = -1;
            goto exit;
          }
        if (WIFEXITED (status))
          switch (WEXITSTATUS (status))
            {
              case EXIT_SUCCESS:
                break;
              case EXIT_FAILURE:
              default:
                g_warning ("Error during SecInfo migration.");
                ret = -1;
                break;
            }
        else
          {
            g_message ("Error during SecInfo migration.");
            ret = -1;
          }

        break;
      }
    }

exit:

  /* Close the lock file. */

  if (close (fd))
    {
      g_free (lockfile_name);
      g_warning ("Failed to close lock file: %s", strerror (errno));
      return -1;
    }

  /* Remove the lock file. */

  if (unlink (lockfile_name))
    {
      g_free (lockfile_name);
      g_warning ("Failed to remove lock file: %s", strerror (errno));
      return -1;
    }

  g_free (lockfile_name);

  return ret;
}

/**
 * @brief Determine if the administrator is synchronizing with a feed.
 *
 * @param[in]   sync_script  The file name of the synchronization script.
 * @param[out]  timestamp    Newly allocated time that sync started, if syncing.
 * @param[out]  user         Newly allocated user who started sync, if syncing.
 *
 * @return 0 success, 1 success when sync in progress, -1 error.
 */
int
openvas_current_sync (const gchar * sync_script, gchar ** timestamp,
                      gchar ** user)
{
  gchar *lockfile_name, *content, **lines;
  GError *error = NULL;

  g_assert (sync_script);

  lockfile_name =
    g_build_filename (g_get_tmp_dir (), "openvas-feed-sync", sync_script, NULL);
  if (!g_file_get_contents (lockfile_name, &content, NULL, &error))
    {
      if (g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT)
          || g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_ACCES))
        {
          g_error_free (error);
          g_free (lockfile_name);
          return 0;
        }

      g_warning ("%s: %s", __FUNCTION__, error->message);
      g_error_free (error);
      g_free (lockfile_name);
      return -1;
    }

  lines = g_strsplit (content, "\n", 2);
  g_free (content);
  if (lines[0] && lines[1])
    {
      *timestamp = g_strdup (lines[0]);
      *user = g_strdup (lines[1]);

      g_free (lockfile_name);
      g_strfreev (lines);
      return 1;
    }

  g_free (lockfile_name);
  g_strfreev (lines);
  return -1;
}


/* Wizards. */

/**
 * @brief Run a wizard.
 *
 * @param[in]  name              Wizard name.
 * @param[in]  run_command       Function to run OMP command.
 * @param[in]  run_command_data  Argument for run_command.
 * @param[in]  params            Wizard params.  Array of name_value_t.
 * @param[in]  read_only         Whether to only allow wizards marked as
 *                               read only.
 * @param[in]  mode              Name of the mode to run the wizard in.
 * @param[out] command_error     Address for error message from failed command
 *                               when return is 4, or NULL.
 * @param[out] ret_response      Address for response string of last command.
 *
 * @return 0 success, 1 name error, 2 process forked to run task, -10 process
 *         forked to run task where task start failed, -2 to_scanner buffer
 *         full, 4 command in wizard failed, 5 wizard not read only,
 *         6 Parameter validation failed, -1 internal error,
 *         99 permission denied.
 */
int
manage_run_wizard (const gchar *name,
                   int (*run_command) (void*, gchar*, gchar**),
                   void *run_command_data,
                   array_t *params,
                   int read_only,
                   const char *mode,
                   gchar **command_error,
                   gchar **ret_response)
{
  gchar *file, *file_name, *response, *wizard;
  gsize wizard_len;
  GError *get_error;
  entity_t entity, mode_entity, params_entity, read_only_entity;
  entity_t param_def, step;
  entities_t modes, steps, param_defs;
  int ret, forked;
  const gchar *point;

  forked = 0;

  if (user_may ("run_wizard") == 0)
    return 99;

  if (command_error)
    *command_error = NULL;

  point = name;
  while (*point && (isalnum (*point) || *point == '_')) point++;
  if (*point)
    return 1;

  /* Read wizard from file. */

  file_name = g_strdup_printf ("%s.xml", name);
  file = g_build_filename (OPENVAS_DATA_DIR,
                           "openvasmd",
                           "wizards",
                           file_name,
                           NULL);
  g_free (file_name);

  get_error = NULL;
  g_file_get_contents (file,
                       &wizard,
                       &wizard_len,
                       &get_error);
  g_free (file);
  if (get_error)
    {
      g_warning ("%s: Failed to read wizard: %s\n",
                 __FUNCTION__,
                 get_error->message);
      g_error_free (get_error);
      return -1;
    }

  /* Parse wizard. */

  entity = NULL;
  if (parse_entity (wizard, &entity))
    {
      g_warning ("%s: Failed to parse wizard\n", __FUNCTION__);
      g_free (wizard);
      return -1;
    }
  g_free (wizard);

  /* Select mode */
  if (mode && strcmp (mode, ""))
    {
    modes = entity->entities;
    int mode_found = 0;
    while (mode_found == 0 && (mode_entity = first_entity (modes)))
      {
        if (strcasecmp (entity_name (mode_entity), "mode") == 0)
          {
            entity_t name_entity;
            name_entity = entity_child (mode_entity, "name");

            if (strcmp (entity_text (name_entity), mode) == 0)
              mode_found = 1;
          }
        modes = next_entities (modes);
      }

      if (mode_found == 0)
        {
          free_entity (entity);
          *ret_response = g_strdup ("");

          if (forked)
            return 3;
          else
            return 0;
        }
    }
  else
    {
      mode_entity = entity;
    }

  /* If needed, check if wizard is marked as read only.
   * This does not check the actual commands.
   */
  if (read_only)
    {
      read_only_entity = entity_child (mode_entity, "read_only");
      if (read_only_entity == NULL)
        {
          free_entity (entity);
          return 5;
        }
    }

  /* Check params */
  params_entity = entity_child (mode_entity, "params");
  if (params_entity)
    param_defs = params_entity->entities;

  while (params_entity && (param_def = first_entity (param_defs)))
    {
      if (strcasecmp (entity_name (param_def), "param") == 0)
        {
          entity_t name_entity, regex_entity, optional_entity;
          const char *name, *regex;
          int optional;
          int param_found = 0;

          name_entity = entity_child (param_def, "name");
          if ((name_entity == NULL)
              || (strcmp (entity_text (name_entity), "") == 0))
            {
              g_warning ("%s: Wizard PARAM missing NAME\n",
                         __FUNCTION__);
              free_entity (entity);
              return -1;
            }
          else
            name = entity_text (name_entity);

          regex_entity = entity_child (param_def, "regex");
          if ((regex_entity == NULL)
              || (strcmp (entity_text (regex_entity), "") == 0))
            {
              g_warning ("%s: Wizard PARAM missing REGEX\n",
                         __FUNCTION__);
              free_entity (entity);
              return -1;
            }
          else
            regex = entity_text (regex_entity);

          optional_entity = entity_child (param_def, "optional");
          optional = (optional_entity
                      && strcmp (entity_text (optional_entity), "")
                      && strcmp (entity_text (optional_entity), "0"));

          if (params)
            {
              guint index = params->len;
              while (index--)
                {
                  name_value_t *pair;

                  pair = (name_value_t*) g_ptr_array_index (params, index);

                  if (pair == NULL)
                    continue;

                  if ((pair->name)
                      && (pair->value)
                      && (strcmp (pair->name, name) == 0))
                    {
                      index = 0; // end loop;
                      param_found = 1;

                      if (g_regex_match_simple (regex, pair->value, 0, 0) == 0)
                        {
                          *command_error
                            = g_strdup_printf ("Value '%s' is not valid for"
                                              " parameter '%s'.",
                                              pair->value, name);
                          free_entity (entity);
                          return 6;
                        }
                    }
                }
            }

          if (optional == 0 && param_found == 0)
            {
              *command_error = g_strdup_printf ("Mandatory wizard param '%s'"
                                                " missing",
                                                name);
              free_entity (entity);
              return 6;
            }


        }
      param_defs = next_entities (param_defs);
    }

  /* Run each step of the wizard. */

  response = NULL;
  ret = 0;
  steps = mode_entity->entities;
  while ((step = first_entity (steps)))
    {
      if (strcasecmp (entity_name (step), "step") == 0)
        {
          entity_t command;
          gchar *omp;
          int xsl_fd, xml_fd;
          char xsl_file_name[] = "/tmp/openvasmd-xsl-XXXXXX";
          FILE *xsl_file, *xml_file;
          char xml_file_name[] = "/tmp/openvasmd-xml-XXXXXX";

          /* Get the command element. */

          command = entity_child (step, "command");
          if (command == NULL)
            {
              g_warning ("%s: Wizard STEP missing COMMAND\n",
                         __FUNCTION__);
              free_entity (entity);
              g_free (response);
              return -1;
            }

          /* Save the command XSL from the element to a file. */

          xsl_fd = mkstemp (xsl_file_name);
          if (xsl_fd == -1)
            {
              g_warning ("%s: Wizard XSL file create failed\n",
                         __FUNCTION__);
              free_entity (entity);
              g_free (response);
              return -1;
            }

          xsl_file = fdopen (xsl_fd, "w");
          if (xsl_file == NULL)
            {
              g_warning ("%s: Wizard XSL file open failed\n",
                         __FUNCTION__);
              close (xsl_fd);
              free_entity (entity);
              g_free (response);
              return -1;
            }

          if (first_entity (command->entities))
            print_entity (xsl_file, first_entity (command->entities));

          /* Write the params as XML to a file. */

          xml_fd = mkstemp (xml_file_name);
          if (xml_fd == -1)
            {
              g_warning ("%s: Wizard XML file create failed\n",
                         __FUNCTION__);
              fclose (xsl_file);
              unlink (xsl_file_name);
              free_entity (entity);
              g_free (response);
              return -1;
            }

          xml_file = fdopen (xml_fd, "w");
          if (xml_file == NULL)
            {
              g_warning ("%s: Wizard XML file open failed\n",
                         __FUNCTION__);
              fclose (xsl_file);
              unlink (xsl_file_name);
              close (xml_fd);
              free_entity (entity);
              g_free (response);
              return -1;
            }

          if (fprintf (xml_file, "<wizard><params>") < 0)
            {
              fclose (xsl_file);
              unlink (xsl_file_name);
              fclose (xml_file);
              free_entity (entity);
              g_warning ("%s: Wizard failed to write XML\n",
                         __FUNCTION__);
              g_free (response);
              return -1;
            }

          if (params)
            {
              guint index = params->len;
              while (index--)
                {
                  name_value_t *pair;
                  gchar *pair_name, *pair_value;

                  pair = (name_value_t*) g_ptr_array_index (params, index);

                  if (pair == NULL)
                    continue;

                  pair_name = pair->name
                               ? g_markup_escape_text
                                  (pair->name, strlen (pair->name))
                               : g_strdup ("");

                  pair_value = pair->value
                                ? g_markup_escape_text
                                   (pair->value, strlen (pair->value))
                                : g_strdup ("");

                  if (fprintf (xml_file,
                               "<param>"
                               "<name>%s</name>"
                               "<value>%s</value>"
                               "</param>",
                               pair_name,
                               pair_value)
                      < 0)
                    {
                      g_free (pair_name);
                      g_free (pair_value);
                      fclose (xsl_file);
                      unlink (xsl_file_name);
                      fclose (xml_file);
                      unlink (xml_file_name);
                      free_entity (entity);
                      g_warning ("%s: Wizard failed to write XML\n",
                                 __FUNCTION__);
                      g_free (response);
                      return -1;
                    }
                  g_free (pair_name);
                  g_free (pair_value);
                }
            }

          if (fprintf (xml_file,
                       "</params>"
                       "<previous>"
                       "<response>%s</response>"
                       "</previous>"
                       "</wizard>\n",
                       response ? response : "")
              < 0)
            {
              fclose (xsl_file);
              unlink (xsl_file_name);
              fclose (xml_file);
              unlink (xml_file_name);
              free_entity (entity);
              g_warning ("%s: Wizard failed to write XML\n",
                         __FUNCTION__);
              g_free (response);
              return -1;
            }

          fflush (xml_file);

          /* Combine XSL and XML to get the OMP command. */

          omp = xsl_transform (xsl_file_name, xml_file_name, NULL,
                               NULL);
          fclose (xsl_file);
          unlink (xsl_file_name);
          fclose (xml_file);
          unlink (xml_file_name);
          if (omp == NULL)
            {
              g_warning ("%s: Wizard XSL transform failed\n",
                         __FUNCTION__);
              free_entity (entity);
              g_free (response);
              return -1;
            }

          /* Run the OMP command. */

          g_free (response);
          response = NULL;
          ret = run_command (run_command_data, omp, &response);
          if (ret == 3)
            {
              /* Parent after a start_task fork. */
              forked = 1;
            }
          else if (ret == 0)
            {
              /* Command succeeded. */
            }
          else if (ret == 2)
            {
              /* Process forked to run a task. */
              free_entity (entity);
              g_free (response);
              return 2;
            }
          else if (ret == -10)
            {
              /* Process forked to run a task.  Task start failed. */
              free_entity (entity);
              g_free (response);
              return -10;
            }
          else if (ret == -2)
            {
              /* to_scanner buffer full. */
              free_entity (entity);
              g_free (response);
              return -2;
            }
          else
            {
              free_entity (entity);
              g_free (response);
              return -1;
            }

          /* Exit if the command failed. */

          if (response)
            {
              const char *status;
              entity_t response_entity;

              response_entity = NULL;
              if (parse_entity (response, &response_entity))
                {
                  g_warning ("%s: Wizard failed to parse response\n",
                             __FUNCTION__);
                  free_entity (entity);
                  g_free (response);
                  return -1;
                }

              status = entity_attribute (response_entity, "status");
              if ((status == NULL)
                  || (strlen (status) == 0)
                  || (status[0] != '2'))
                {
                  tracef ("response was %s\n", response);
                  if (command_error)
                    {
                      const char *text;
                      text = entity_attribute (response_entity, "status_text");
                      if (text)
                        *command_error = g_strdup (text);
                    }
                  free_entity (response_entity);
                  free_entity (entity);
                  g_free (response);
                  return 4;
                }

              free_entity (response_entity);
            }
        }
      steps = next_entities (steps);
    }
  *ret_response = g_strdup (response);
  free_entity (entity);
  g_free (response);

  /* All the steps succeeded. */

  if (forked)
    return 3;
  return 0;
}
