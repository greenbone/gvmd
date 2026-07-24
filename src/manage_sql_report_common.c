/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM SQL layer: Structured common report loading.
 */
#include "manage_sql_report_common.h"

#include "manage_sql_settings.h"
#include "manage_sql_targets.h"

#undef G_LOG_DOMAIN

/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Return the run status of the scan associated with a report.
 *
 * @param[in]   report  Report.
 * @param[out]  status  Scan run status.
 *
 * @return 0 on success, -1 on error.
 */
int
report_scan_run_status (report_t report, task_status_t *status)
{
  *status = sql_int ("SELECT scan_run_status FROM reports"
                     " WHERE reports.id = %llu;",
                     report);
  return 0;
}

/**
 * @brief Count a report's total number of vulnerabilities.
 *
 * @param[in]  report  Report.
 *
 * @return Vulnerabilities count.
 */
int
report_vuln_count (report_t report)
{
  return sql_int ("SELECT count (DISTINCT nvt) FROM results"
                  " WHERE report = %llu"
                  " AND severity != " G_STRINGIFY (SEVERITY_ERROR) ";",
                  report);
}

/**
 * @brief Get the end time of a scan.
 *
 * @param[in]  report  The report associated with the scan.
 *
 * @return End time of scan, in a newly allocated string.
 */
char *
scan_end_time (report_t report)
{
  char *time = sql_string ("SELECT iso_time (end_time)"
                           " FROM reports WHERE id = %llu;",
                           report);
  return time ? time : g_strdup ("");
}

/**
 * @brief Get the start time of a scan.
 *
 * @param[in]  report  The report associated with the scan.
 *
 * @return Start time of scan, in a newly allocated string.
 */
char *
scan_start_time (report_t report)
{
  char *time = sql_string ("SELECT iso_time (start_time)"
                           " FROM reports WHERE id = %llu;",
                           report);
  return time ? time : g_strdup ("");
}

/**
 * @brief Fill basic report metadata.
 *
 * @param[in]     report  Report to load.
 * @param[in,out] summary   Report summary to fill.
 *
 * @return 0 on success, -1 on error.
 */
int
fill_report_base (report_t report, report_summary_base_t summary)
{
  iterator_t iterator;
  gchar *id = NULL;
  gchar *comment = NULL;
  gchar *owner_name = NULL;
  user_t owner;
  time_t creation_time;
  time_t modification_time;

  if (report == 0 || summary == NULL)
    return -1;

  init_ps_iterator (
    &iterator,
    "SELECT"
    " reports.uuid,"
    " coalesce(reports.comment, ''),"
    " reports.owner,"
    " coalesce("
    "   (SELECT users.name"
    "      FROM users"
    "     WHERE users.id = reports.owner),"
    "   ''"
    " ),"
    " coalesce(reports.creation_time, 0),"
    " coalesce(reports.modification_time, 0)"
    " FROM reports"
    " WHERE reports.id = $1;",
    SQL_RESOURCE_PARAM (report),
    NULL);

  if (next (&iterator) == FALSE)
    {
      cleanup_iterator (&iterator);
      return -1;
    }

  id = g_strdup (iterator_string (&iterator, 0));
  comment = g_strdup (iterator_string (&iterator, 1));
  owner_name = g_strdup (iterator_string (&iterator, 3));

  owner = (user_t) iterator_int64 (&iterator, 2);
  creation_time = (time_t) iterator_int64 (&iterator, 4);
  modification_time = (time_t) iterator_int64 (&iterator, 5);

  cleanup_iterator (&iterator);

  /*
   * Commit the loaded values. The model takes ownership of the strings.
   */
  g_free (summary->id);
  g_free (summary->name);
  g_free (summary->comment);
  g_free (summary->owner_name);

  summary->report = report;
  summary->owner = owner;

  summary->id = id;
  summary->name = g_strdup (iso_if_time (creation_time));
  summary->comment = comment;
  summary->owner_name = owner_name;

  summary->creation_time = creation_time;
  summary->modification_time = modification_time;

  return 0;
}

/**
 * @brief Fill scan timing and run-status information.
 *
 * @param[in]     report  Report to load.
 * @param[in,out] summary   Report summary to fill.
 *
 * @return 0 on success, -1 on error.
 */
int
fill_report_scan_information (report_t report, report_summary_base_t summary)
{
  task_status_t run_status = TASK_STATUS_INTERRUPTED;
  gchar *report_uuid_value = NULL;
  gchar *timestamp_value = NULL;
  gchar *scan_start_value = NULL;
  gchar *scan_end_value = NULL;
  gchar *run_status_string = NULL;
  int ret = -1;

  if (report == 0 || summary == NULL)
    return -1;

  if (report_scan_run_status (report, &run_status))
    goto cleanup;

  run_status_string = g_strdup (
    run_status_name (
      run_status ? run_status : TASK_STATUS_INTERRUPTED));

  scan_start_value = scan_start_time (report);
  if (scan_start_value == NULL)
    goto cleanup;

  scan_end_value = scan_end_time (report);
  if (scan_end_value == NULL)
    goto cleanup;

  report_uuid_value = report_uuid (report);
  if (report_uuid_value == NULL)
    goto cleanup;

  if (report_timestamp (report_uuid_value, &timestamp_value))
    goto cleanup;

  /*
   * Commit only after all values have been loaded successfully.
   * The model takes ownership of all allocated strings.
   */
  g_free (summary->scan_run_status_str);
  g_free (summary->scan_start);
  g_free (summary->scan_end);
  g_free (summary->timestamp);

  summary->scan_run_status = run_status;

  summary->scan_run_status_str = run_status_string;
  run_status_string = NULL;

  summary->scan_start = scan_start_value;
  scan_start_value = NULL;

  summary->scan_end = scan_end_value;
  scan_end_value = NULL;

  summary->timestamp = timestamp_value;
  timestamp_value = NULL;

  ret = 0;

  cleanup:
    g_free (run_status_string);
  g_free (scan_start_value);
  g_free (scan_end_value);
  g_free (timestamp_value);
  g_free (report_uuid_value);

  return ret;
}

/**
 * @brief Calculate report task progress.
 *
 * Agent tasks are always reported as complete. Running upload tasks without
 * a network target use their upload progress. All other tasks use the report
 * progress.
 *
 * @param[in] report  Report resource.
 * @param[in] task    Task associated with the report.
 *
 * @return Report progress percentage.
 */
static int
get_report_task_progress (report_t report, task_t task)
{
  target_t target;

  if (report == 0 || task == 0)
    return 0;

#if ENABLE_AGENTS
  if (task_agent_group (task) != 0)
    return 100;
#endif

  target = task_target (task);

  if (target == 0
      && task_run_status (task) == TASK_STATUS_RUNNING)
    return task_upload_progress (task);

  return report_progress (report);
}

/**
 * @brief Fill task information associated with a report.
 *
 * @param[in]     report  Report to load.
 * @param[in,out] task_reference   Report task reference to fill.
 *
 * @return 0 on success, or -1 on error.
 */
int
fill_report_task (report_t report, report_task_reference_t task_reference)
{
  task_t task = 0;
  gchar *uuid = NULL;
  gchar *name = NULL;
  gchar *comment = NULL;
  gchar *usage_type = NULL;
  int progress = 0;
  int ret = -1;

  if (report == 0
      || task_reference == NULL)
    return -1;

  if (report_task (report, &task))
    goto cleanup;

  /*
   * A report without an associated task is valid.
   */
  if (task == 0)
    {
      ret = 0;
      goto cleanup;
    }

  if (task_uuid (task, &uuid))
    goto cleanup;

  name = task_name (task);
  comment = task_comment (task);

  if (task_usage_type (task, &usage_type))
    goto cleanup;

  progress = get_report_task_progress (report, task);

  g_free (task_reference->uuid);
  g_free (task_reference->name);
  g_free (task_reference->comment);
  g_free (task_reference->usage_type);

  task_reference->id = task;
  task_reference->uuid = uuid;
  task_reference->name = name;
  task_reference->comment = comment;
  task_reference->usage_type = usage_type;
  task_reference->progress = progress;

  uuid = NULL;
  name = NULL;
  comment = NULL;
  usage_type = NULL;

  ret = 0;

cleanup:
  g_free (uuid);
  g_free (name);
  g_free (comment);
  g_free (usage_type);

  return ret;
}

/**
 * @brief Initialize a target reference.
 *
 * @param[in,out] target    Empty target reference to initialize.
 * @param[in]     type      Target type.
 * @param[in]     id        Internal target resource.
 * @param[in]     uuid      Allocated target UUID, or NULL.
 * @param[in]     name      Allocated target name, or NULL.
 * @param[in]     comment   Allocated target comment, or NULL.
 * @param[in]     in_trash  Whether the target is in trash.
 *
 * @return 0 on success, or -1 if @p target is NULL.
 */
static int
init_report_target_reference (report_target_reference_t target,
                              report_target_type_t type,
                              resource_t id,
                              gchar *uuid,
                              gchar *name,
                              gchar *comment,
                              gboolean in_trash)
{
  if (target == NULL)
    return -1;

  g_assert (target->uuid == NULL);
  g_assert (target->name == NULL);
  g_assert (target->comment == NULL);

  target->type = type;
  target->id = id;
  target->uuid = uuid;
  target->name = name;
  target->comment = comment;
  target->in_trash = in_trash;

  return 0;
}

/**
 * @brief Fill a normal network target reference.
 *
 * @param[in]     task              Task to inspect.
 * @param[in,out] target_reference  Target reference to fill.
 *
 * @return 1 if a target was found, 0 if no target exists, or -1 on error.
 */
static int
fill_network_target_reference (
  task_t task,
  report_target_reference_t target_reference)
{
  target_t target;
  gboolean in_trash;
  gchar *uuid = NULL;
  gchar *name = NULL;
  gchar *comment = NULL;

  target = task_target (task);

  /*
   * Import tasks do not have a target.
   */
  if (target == 0)
    return 0;

  in_trash = task_target_in_trash (task);

  if (in_trash)
    {
      uuid = trash_target_uuid (target);
      name = trash_target_name (target);
      comment = trash_target_comment (target);
    }
  else
    {
      uuid = target_uuid (target);
      name = target_name (target);
      comment = target_comment (target);
    }

  if (init_report_target_reference (
    target_reference,
    REPORT_TARGET_TYPE_TARGET,
    (resource_t) target,
    uuid,
    name,
    comment,
    in_trash))
    {
      g_free (uuid);
      g_free (name);
      g_free (comment);
      return -1;
    }

  return 1;
}

#if ENABLE_CONTAINER_SCANNING

/**
 * @brief Fill an OCI image target reference.
 *
 * @param[in]     task              Task to inspect.
 * @param[in,out] target_reference  Target reference to fill.
 *
 * @return 1 if an OCI target was found, 0 if none exists, or -1 on error.
 */
static int
fill_oci_image_report_target_reference (
  task_t task,
  report_target_reference_t target_reference)
{
  oci_image_target_t target;
  gboolean in_trash;
  gchar *uuid;
  gchar *name;
  gchar *comment;

  target = task_oci_image_target (task);
  if (target == 0)
    return 0;

  in_trash = task_oci_image_target_in_trash (task);

  if (in_trash)
    {
      uuid = trash_oci_image_target_uuid (target);
      name = trash_oci_image_target_name (target);
      comment = trash_oci_image_target_comment (target);
    }
  else
    {
      uuid = oci_image_target_uuid (target);
      name = oci_image_target_name (target);
      comment = oci_image_target_comment (target);
    }

  if (init_report_target_reference (
    target_reference,
    REPORT_TARGET_TYPE_OCI_IMAGE,
    (resource_t) target,
    uuid,
    name,
    comment,
    in_trash))
    {
      g_free (uuid);
      g_free (name);
      g_free (comment);
      return -1;
    }

  /*
   * Do not free uuid, name or comment here.
   * Their ownership was transferred to target_reference.
   */

  return 1;
}

#endif /* ENABLE_CONTAINER_SCANNING */

#if ENABLE_WEB_APPLICATION_SCANNING

/**
 * @brief Fill a web application target reference.
 *
 * @param[in]     task              Task to inspect.
 * @param[in,out] target_reference  Target reference to fill.
 *
 * @return 1 if a target was found, 0 if none exists, or -1 on error.
 */
static int
fill_web_application_report_target_reference (
  task_t task,
  report_target_reference_t target_reference)
{
  web_application_target_t target;
  gboolean in_trash;
  gchar *uuid;
  gchar *name;
  gchar *comment;

  target = task_web_application_target (task);
  if (target == 0)
    return 0;

  in_trash = task_web_application_target_in_trash (task);

  if (in_trash)
    {
      uuid = trash_web_application_target_uuid (target);
      name = trash_web_application_target_name (target);
      comment = trash_web_application_target_comment (target);
    }
  else
    {
      uuid = web_application_target_uuid (target);
      name = web_application_target_name (target);
      comment = web_application_target_comment (target);
    }

  if (init_report_target_reference (
    target_reference,
    REPORT_TARGET_TYPE_WEB_APPLICATION,
    (resource_t) target,
    uuid,
    name,
    comment,
    in_trash))
    {
      g_free (uuid);
      g_free (name);
      g_free (comment);
      return -1;
    }

  return 1;
}

#endif /* ENABLE_WEB_APPLICATION_SCANNING */

#if ENABLE_AGENTS

/**
 * @brief Fill an agent group reference.
 *
 * @param[in]     task              Task to inspect.
 * @param[in,out] target_reference  Target reference to fill.
 *
 * @return 1 if an agent group was found, 0 if none exists, or -1 on error.
 */
static int
fill_agent_group_report_target_reference (
  task_t task,
  report_target_reference_t target_reference)
{
  agent_group_t agent_group;
  gboolean in_trash;
  gchar *uuid;
  gchar *name;
  gchar *comment;

  agent_group = task_agent_group (task);
  if (agent_group == 0)
    return 0;

  in_trash = task_agent_group_in_trash (task);

  if (in_trash)
    {
      uuid = trash_agent_group_uuid (agent_group);
      name = trash_agent_group_name (agent_group);
      comment = trash_agent_group_comment (agent_group);
    }
  else
    {
      uuid = agent_group_uuid (agent_group);
      name = agent_group_name (agent_group);
      comment = agent_group_comment (agent_group);
    }

  if (init_report_target_reference (
    target_reference,
    REPORT_TARGET_TYPE_AGENT_GROUP,
    (resource_t) agent_group,
    uuid,
    name,
    comment,
    in_trash))
    {
      g_free (uuid);
      g_free (name);
      g_free (comment);
      return -1;
    }

  return 1;
}

#endif /* ENABLE_AGENTS */

/**
 * @brief Fill the scan target associated with a report task.
 *
 * The first matching task resource is used. A task without any target
 * resource is represented as an import task.
 *
 * @param[in]     task   Task to inspect.
 * @param[in,out] target_reference  Report target reference to fill.
 *
 * @return 0 on success, or -1 on error.
 */
int
fill_report_target (task_t task, report_target_reference_t target_reference)
{
  int ret;

  if (target_reference == NULL)
    return -1;

  if (task == 0)
    return 0;

#if ENABLE_CONTAINER_SCANNING
  ret = fill_oci_image_report_target_reference (task, target_reference);
  if (ret < 0)
    return -1;
  if (ret > 0)
    return 0;
#endif

#if ENABLE_WEB_APPLICATION_SCANNING
  ret = fill_web_application_report_target_reference (task, target_reference);
  if (ret < 0)
    return -1;
  if (ret > 0)
    return 0;
#endif

#if ENABLE_AGENTS
  ret = fill_agent_group_report_target_reference (task, target_reference);
  if (ret < 0)
    return -1;
  if (ret > 0)
    return 0;
#endif

  ret = fill_network_target_reference (task, target_reference);
  if (ret < 0)
    return -1;

  if (ret > 0)
    return 0;

  /*
   * A task with no supported target resource is an import task.
   */
  target_reference->type = REPORT_TARGET_TYPE_IMPORT;
  target_reference->id = 0;
  target_reference->in_trash = FALSE;

  return 0;
}

/**
 * @brief Fill resource counts for a scan report.
 *
 * @param[in]     report  Report to inspect.
 * @param[in]     get     Result filter information.
 * @param[in,out] resources   Report resource summary to fill.
 *
 * @return 0 on success, -1 on invalid input.
 */
int
fill_report_resource_summary (report_t report,
                              const get_data_t *get,
                              report_resource_summary_t resources)
{

  if (report == 0
      || get == NULL
      || resources == NULL)
    return -1;

  resources->hosts = report_host_count (report);
  resources->ports = report_port_count (report);
  resources->applications = report_applications_count (report);
  resources->operating_systems = report_operating_systems_count (report);
  resources->vulnerabilities = report_vuln_count (report);
  resources->cves = report_cves_count (report, get);
  resources->closed_cves = report_closed_cve_count (report, get);
  resources->tls_certificates = report_ssl_cert_count (report);
  resources->errors = report_error_count (report);

  return 0;
}

/**
 * @brief Fill timezone information for a report.
 *
 * Uses the timezone resolved from the GET request when present. Otherwise,
 * the configured system timezone is used.
 *
 * @param[in,out] summary  Report summary base to fill.
 * @param[in]     zone   Resolved request timezone, or NULL.
 *
 * @return 0 on success, or -1 on error.
 */
int
fill_report_timezone (report_summary_base_t summary, const gchar *zone)
{
  gchar *report_zone = NULL;
  gchar *timezone = NULL;
  gchar *timezone_abbrev = NULL;
  const gchar *abbreviation = NULL;
  time_t scan_start;

  if (summary == NULL)
    return -1;

  if (zone && *zone)
    report_zone = g_strdup (zone);
  else
    report_zone = setting_timezone ();

  scan_start = scan_start_time_epoch (summary->report);

  iso_time_tz (&scan_start, report_zone, &abbreviation);

  timezone = g_strdup (
    report_zone && *report_zone
    ? report_zone
    : "Coordinated Universal Time");

  timezone_abbrev = g_strdup (
    abbreviation && *abbreviation
    ? abbreviation
    : "UTC");

  g_free (summary->timezone);
  g_free (summary->timezone_abbrev);

  summary->timezone = timezone;
  summary->timezone_abbrev = timezone_abbrev;

  g_free (report_zone);

  return 0;
}
