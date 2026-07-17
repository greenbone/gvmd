/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM SQL layer: Structured report model loading.
 *
 * SQL-backed functions for filling a structured normal report model.
 *
 * This module intentionally excludes:
 *
 * - delta report data
 * - audit and compliance data
 * - detailed results
 * - detailed hosts
 * - report export data
 */

#include "manage_sql_report.h"

#include "manage_sql_report_applications.h"
#include "manage_sql_report_operating_systems.h"
#include "manage_sql_report_ports.h"
#include "manage_sql_settings.h"
#include "manage_sql_targets.h"
#include "manage_targets.h"
#include "sql.h"

#undef G_LOG_DOMAIN

/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Fill basic report metadata.
 *
 * Strings returned by the iterator are borrowed and valid only until
 * cleanup_iterator() is called. This function duplicates those strings and
 * transfers ownership of the copies to @p model.
 *
 * @param[in]     report  Report to load.
 * @param[in,out] model   Report model to fill.
 *
 * @return 0 on success, -1 on error.
 */
static int
fill_report_metadata (report_t report, report_model_t model)
{
  iterator_t iterator;
  gchar *id = NULL;
  gchar *name = NULL;
  gchar *comment = NULL;
  gchar *owner_name = NULL;
  user_t owner;
  time_t creation_time;
  time_t modification_time;

  if (report == 0 || model == NULL)
    return -1;

  init_ps_iterator (
    &iterator,
    "SELECT"
    " reports.uuid,"
    " coalesce(reports.name, ''),"
    " coalesce(reports.comment, ''),"
    " reports.owner,"
    " coalesce("
    "   (SELECT users.name"
    "      FROM users"
    "     WHERE users.id = reports.owner),"
    "   ''"
    " ),"
    " coalesce("
    "   extract(epoch FROM reports.creation_time)::bigint,"
    "   0"
    " ),"
    " coalesce("
    "   extract(epoch FROM reports.modification_time)::bigint,"
    "   0"
    " )"
    " FROM reports"
    " WHERE reports.id = $1;",
    SQL_RESOURCE_PARAM (report),
    NULL);

  if (next (&iterator) == FALSE)
    {
      cleanup_iterator (&iterator);
      return -1;
    }

  /*
   * Duplicate borrowed iterator values before cleaning up the iterator.
   */
  id = g_strdup (iterator_string (&iterator, 0));
  name = g_strdup (iterator_string (&iterator, 1));
  comment = g_strdup (iterator_string (&iterator, 2));
  owner_name = g_strdup (iterator_string (&iterator, 4));

  owner = (user_t) iterator_int64 (&iterator, 3);
  creation_time = (time_t) iterator_int64 (&iterator, 5);
  modification_time = (time_t) iterator_int64 (&iterator, 6);

  cleanup_iterator (&iterator);

  /*
   * Commit the loaded values. The model takes ownership of the strings.
   */
  g_free (model->id);
  g_free (model->name);
  g_free (model->comment);
  g_free (model->owner_name);

  model->report = report;
  model->owner = owner;

  model->id = id;
  model->name = name;
  model->comment = comment;
  model->owner_name = owner_name;

  model->creation_time = creation_time;
  model->modification_time = modification_time;

  return 0;
}

/**
 * @brief Fill scan timing and run-status information.
 *
 * The model takes ownership of the timestamp, scan start, scan end and
 * run-status strings after all values have been loaded successfully.
 *
 * @param[in]     report  Report to load.
 * @param[in,out] model   Report model to fill.
 *
 * @return 0 on success, -1 on error.
 */
static int
fill_report_scan_information (report_t report, report_model_t model)
{
  task_status_t run_status = TASK_STATUS_INTERRUPTED;
  gchar *report_uuid_value = NULL;
  gchar *timestamp_value = NULL;
  gchar *scan_start_value = NULL;
  gchar *scan_end_value = NULL;
  gchar *run_status_string = NULL;
  int ret = -1;

  if (report == 0 || model == NULL)
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
  g_free (model->scan_run_status_str);
  g_free (model->scan_start);
  g_free (model->scan_end);
  g_free (model->timestamp);

  model->scan_run_status = run_status;

  model->scan_run_status_str = run_status_string;
  run_status_string = NULL;

  model->scan_start = scan_start_value;
  scan_start_value = NULL;

  model->scan_end = scan_end_value;
  scan_end_value = NULL;

  model->timestamp = timestamp_value;
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
 * @param[in,out] model   Report model to fill.
 *
 * @return 0 on success, or -1 on error.
 */
static int
fill_report_task (report_t report, report_model_t model)
{
  task_t task = 0;
  gchar *uuid = NULL;
  gchar *name = NULL;
  gchar *comment = NULL;
  gchar *usage_type = NULL;
  int progress = 0;
  int ret = -1;

  if (report == 0
      || model == NULL
      || model->task == NULL)
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

  g_free (model->task->uuid);
  g_free (model->task->name);
  g_free (model->task->comment);
  g_free (model->task->usage_type);

  model->task->id = task;
  model->task->uuid = uuid;
  model->task->name = name;
  model->task->comment = comment;
  model->task->usage_type = usage_type;
  model->task->progress = progress;

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
 * On success, ownership of @p uuid, @p name and @p comment is transferred
 * to @p target. On failure, ownership remains with the caller.
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
 * @param[in,out] model  Report model to fill.
 *
 * @return 0 on success, or -1 on error.
 */
static int
fill_report_target (task_t task, report_model_t model)
{
  report_target_reference_t target_reference;
  int ret;

  if (model == NULL
      || model->task == NULL
      || model->task->target == NULL)
    return -1;

  target_reference = model->task->target;

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
 * @brief Fill resource counts for a normal report.
 *
 * @param[in]     report  Report to inspect.
 * @param[in]     get     Result filter information.
 * @param[in,out] model   Report model to fill.
 *
 * @return 0 on success, -1 on invalid input.
 */
static int
fill_report_resource_summary (report_t report,
                              const get_data_t *get,
                              report_model_t model)
{
  report_resource_summary_t resources;

  if (report == 0
      || get == NULL
      || model == NULL
      || model->resources == NULL)
    return -1;

  resources = model->resources;

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
 * @brief Fill full and filtered result counts and severity.
 *
 * Legacy internal names are mapped as follows:
 *
 * - holes to high
 * - warnings to medium
 * - infos to low
 *
 * @param[in]     report  Report to inspect.
 * @param[in]     get     Result filtering information.
 * @param[in,out] model   Report model to fill.
 *
 * @return 0 on success, -1 on invalid input.
 */
static int
fill_report_result_summary (report_t report,
                            const get_data_t *get,
                            report_model_t model)
{
  int criticals;
  int holes;
  int infos;
  int logs;
  int warnings;
  int false_positives;

  int filtered_criticals;
  int filtered_holes;
  int filtered_infos;
  int filtered_logs;
  int filtered_warnings;
  int filtered_false_positives;

  double full_severity;
  double filtered_severity;

  if (report == 0 || get == NULL || model == NULL)
    return -1;

  criticals = 0;
  holes = 0;
  infos = 0;
  logs = 0;
  warnings = 0;
  false_positives = 0;

  filtered_criticals = 0;
  filtered_holes = 0;
  filtered_infos = 0;
  filtered_logs = 0;
  filtered_warnings = 0;
  filtered_false_positives = 0;

  full_severity = 0.0;
  filtered_severity = 0.0;

  /*
   * Verify the exact declaration of report_counts_id_full() in your branch.
   * This call follows the argument ordering used by print_report_xml_start().
   */
  report_counts_id_full (
    report,
    &criticals,
    &holes,
    &infos,
    &logs,
    &warnings,
    &false_positives,
    &full_severity,
    get,
    NULL,
    &filtered_criticals,
    &filtered_holes,
    &filtered_infos,
    &filtered_logs,
    &filtered_warnings,
    &filtered_false_positives,
    &filtered_severity);

  model->results.critical.full = criticals;
  model->results.critical.filtered = filtered_criticals;

  model->results.high.full = holes;
  model->results.high.filtered = filtered_holes;

  model->results.medium.full = warnings;
  model->results.medium.filtered = filtered_warnings;

  model->results.low.full = infos;
  model->results.low.filtered = filtered_infos;

  model->results.log.full = logs;
  model->results.log.filtered = filtered_logs;

  model->results.false_positive.full = false_positives;
  model->results.false_positive.filtered = filtered_false_positives;

  model->results.total.full =
    criticals
    + holes
    + warnings
    + infos
    + logs
    + false_positives;

  model->results.total.filtered =
    filtered_criticals
    + filtered_holes
    + filtered_warnings
    + filtered_infos
    + filtered_logs
    + filtered_false_positives;

  model->results.severity.full = full_severity;
  model->results.severity.filtered = filtered_severity;

  return 0;
}

/**
 * @brief Fill timezone information for a report.
 *
 * Uses the timezone resolved from the GET request when present. Otherwise,
 * the configured system timezone is used.
 *
 * @param[in,out] model  Report model to fill.
 * @param[in]     zone   Resolved request timezone, or NULL.
 *
 * @return 0 on success, or -1 on error.
 */
static int
fill_report_timezone (report_model_t model, const gchar *zone)
{
  gchar *report_zone = NULL;
  gchar *timezone = NULL;
  gchar *timezone_abbrev = NULL;
  const gchar *abbreviation = NULL;
  time_t scan_start;

  if (model == NULL)
    return -1;

  if (zone && *zone)
    report_zone = g_strdup (zone);
  else
    report_zone = setting_timezone ();

  scan_start = scan_start_time_epoch (model->report);

  iso_time_tz (&scan_start, report_zone, &abbreviation);

  timezone = g_strdup (
    report_zone && *report_zone
    ? report_zone
    : "Coordinated Universal Time");

  timezone_abbrev = g_strdup (
    abbreviation && *abbreviation
    ? abbreviation
    : "UTC");

  g_free (model->timezone);
  g_free (model->timezone_abbrev);

  model->timezone = timezone;
  model->timezone_abbrev = timezone_abbrev;

  g_free (report_zone);

  return 0;
}

/**
 * @brief Fill a structured normal report model.
 *
 * Loads report metadata, scan status, task information, target information,
 * resource counts, result counts, severity and timezone data.
 *
 * @param[in]     report  Internal report resource.
 * @param[in]     get     Result filtering controls.
 * @param[in]     zone    Resolved request timezone, or NULL.
 * @param[in,out] model   Allocated report model to populate.
 *
 * @return 0 on success, or -1 on error.
 */
int
manage_sql_fill_report_model (report_t report,
                              const get_data_t *get,
                              const gchar *zone,
                              report_model_t model)
{
  int ret;

  if (report == 0 || get == NULL || model == NULL)
    return -1;

  ret = fill_report_metadata (report, model);
  if (ret)
    return ret;

  ret = fill_report_scan_information (report, model);
  if (ret)
    return ret;

  ret = fill_report_task (report, model);
  if (ret)
    return ret;

  ret = fill_report_target (
    model->task ? model->task->id : 0,
    model);
  if (ret)
    return ret;

  ret = fill_report_resource_summary (report, get, model);
  if (ret)
    return ret;

  ret = fill_report_result_summary (report, get, model);
  if (ret)
    return ret;

  ret = fill_report_timezone (model, zone);
  if (ret)
    return ret;

  return 0;
}

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
