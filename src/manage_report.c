/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Report model and operations.
 */

#include "manage_report.h"

#include "manage_filters.h"
#include "manage_settings.h"
#include "manage_sql_report.h"

#undef G_LOG_DOMAIN

/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Controls derived from GET data for GET_REPORT.
 */
typedef struct
{
  gchar *zone;
} get_report_controls_t;

/**
 * @brief Free a GET_REPORT controls structure.
 * @param controls struct to free.
 */
static void
get_report_controls_cleanup (get_report_controls_t *controls)
{
  if (controls == NULL)
    return;

  g_free (controls->zone);
  controls->zone = NULL;
}

/**
 * @brief Allocate and initialize a report resource summary.
 *
 * @return Newly allocated resource summary.
 */
static report_resource_summary_t
report_resource_summary_new (void)
{
  return g_malloc0 (sizeof (struct report_resource_summary));
}

/**
 * @brief Free a report resource summary.
 *
 * @param[in] summary  Resource summary to free.
 */
static void
report_resource_summary_free (report_resource_summary_t summary)
{
  g_free (summary);
}

/**
 * @brief Allocate and initialize a report target reference.
 *
 * @return Newly allocated target reference.
 */
static report_target_reference_t
report_target_reference_new (void)
{
  report_target_reference_t target;

  target = g_malloc0 (sizeof (struct report_target_reference));
  target->type = REPORT_TARGET_TYPE_NONE;

  return target;
}

/**
 * @brief Free a report target reference.
 *
 * @param[in] target  Target reference to free.
 */
static void
report_target_reference_free (report_target_reference_t target)
{
  if (target == NULL)
    return;

  g_free (target->uuid);
  g_free (target->name);
  g_free (target->comment);

  g_free (target);
}

/**
 * @brief Allocate and initialize a report task reference.
 *
 * @return Newly allocated task reference.
 */
static report_task_reference_t
report_task_reference_new (void)
{
  report_task_reference_t task;

  task = g_malloc0 (sizeof (struct report_task_reference));

  task->target = report_target_reference_new ();
  if (task->target == NULL)
    {
      g_free (task);
      return NULL;
    }

  return task;
}

/**
 * @brief Free a report task reference.
 *
 * @param[in] task  Task reference to free.
 */
static void
report_task_reference_free (report_task_reference_t task)
{
  if (task == NULL)
    return;

  g_free (task->uuid);
  g_free (task->name);
  g_free (task->comment);
  g_free (task->usage_type);

  report_target_reference_free (task->target);

  g_free (task);
}

/**
 * @brief Allocate and initialize a report model.
 *
 * @return Newly allocated report model, or NULL on allocation failure.
 */
report_model_t
report_model_new (void)
{
  report_model_t model;

  model = g_malloc0 (sizeof (struct report_model));

  model->task = report_task_reference_new ();
  if (model->task == NULL)
    {
      g_free (model);
      return NULL;
    }

  model->resources = report_resource_summary_new ();
  if (model->resources == NULL)
    {
      report_task_reference_free (model->task);
      g_free (model);
      return NULL;
    }

  return model;
}

/**
 * @brief Free a report model.
 *
 * @param[in] model  Report model to free.
 */
void
report_model_free (report_model_t model)
{
  if (model == NULL)
    return;

  g_free (model->id);
  g_free (model->name);
  g_free (model->comment);
  g_free (model->owner_name);
  g_free (model->timestamp);
  g_free (model->scan_start);
  g_free (model->scan_end);

  g_free (model->scan_run_status_str);
  g_free (model->timezone);
  g_free (model->timezone_abbrev);

  report_task_reference_free (model->task);
  report_resource_summary_free (model->resources);

  g_free (model);
}

/**
 * @brief Check whether a report is supported by GET_REPORT.
 *
 * GET_REPORT currently supports vulnerability reports only.
 * Audit reports are handled by a separate command.
 *
 * @param[in] report  Report resource.
 *
 * @return 0 if supported, 1 if unsupported, or -1 on error.
 */
static int
validate_get_report_usage_type (report_t report)
{
  task_t task = 0;
  gchar *usage_type = NULL;
  int ret;

  if (report == 0)
    return -1;

  ret = report_task (report, &task);
  if (ret)
    return -1;

  /*
   * A report without an associated task has no usage type to validate.
   */
  if (task == 0)
    return 0;

  ret = task_usage_type (task, &usage_type);
  if (ret)
    return -1;

  if (usage_type && strcmp (usage_type, "audit") == 0)
    {
      g_free (usage_type);
      return 1;
    }

  g_free (usage_type);

  return 0;
}


/**
 * @brief Validate and resolve controls needed by GET_REPORT.
 *
 * @param[in]  get       GET command data.
 * @param[out] controls  Resolved controls required by the report model.
 *
 * @return 0 on success, 2 if the filter cannot be resolved, or -1 on error.
 */
static int
resolve_get_report_controls (const get_data_t *get,
                             get_report_controls_t *controls)
{
  gchar *term = NULL;
  gchar *sort_field = NULL;
  gchar *min_qod = NULL;
  gchar *levels = NULL;
  gchar *compliance_levels = NULL;
  gchar *delta_states = NULL;
  gchar *search_phrase = NULL;
  int first_result = 0;
  int max_results = 0;
  int sort_order = 0;
  int result_hosts_only = 0;
  int search_phrase_exact = 0;
  int notes = 0;
  int overrides = 0;
  int apply_overrides = 0;
  int ret;

  if (get == NULL || controls == NULL)
    return -1;

  controls->zone = NULL;

  ret = manage_report_filter_controls_from_get (
    get,
    &term,
    &first_result,
    &max_results,
    &sort_field,
    &sort_order,
    &result_hosts_only,
    NULL,
    &min_qod,
    &levels,
    &compliance_levels,
    &delta_states,
    &search_phrase,
    &search_phrase_exact,
    &notes,
    &overrides,
    &apply_overrides,
    &controls->zone);

  g_free (term);
  g_free (sort_field);
  g_free (min_qod);
  g_free (levels);
  g_free (compliance_levels);
  g_free (delta_states);
  g_free (search_phrase);

  return ret;
}

/**
 * @brief Load a structured vulnerability report model.
 *
 * @param[in]  report_id  UUID of the report.
 * @param[in]  get        GET command data.
 * @param[out] model      Loaded report model.
 *
 * @return Status describing the result of the operation.
 */
manage_get_report_response_t
manage_get_report_model (const gchar *report_id,
                         const get_data_t *get,
                         report_model_t *model)
{
  get_report_controls_t controls = {0};
  report_model_t loaded_model = NULL;
  report_t report = 0;
  int ret;

  if (report_id == NULL
      || get == NULL
      || model == NULL)
    return MANAGE_GET_REPORT_ERROR;

  *model = NULL;

  ret = find_report_with_permission (report_id,
                                    &report,
                                    "get_reports");

  if (ret)
    return MANAGE_GET_REPORT_ERROR;

  if (report == 0)
    return MANAGE_GET_REPORT_NOT_FOUND;

  ret = validate_get_report_usage_type (report);
  if (ret < 0)
    return MANAGE_GET_REPORT_ERROR;

  if (ret > 0)
    return MANAGE_GET_REPORT_UNSUPPORTED_TYPE;

  ret = resolve_get_report_controls (get, &controls);

  if (ret)
    {
      get_report_controls_cleanup (&controls);

      if (ret == 2)
        return MANAGE_GET_REPORT_FILTER_NOT_FOUND;

      return MANAGE_GET_REPORT_ERROR;
    }

  loaded_model = report_model_new ();
  if (loaded_model == NULL)
    {
      get_report_controls_cleanup (&controls);
      return MANAGE_GET_REPORT_ERROR;
    }

  ret = manage_sql_fill_report_model (report,
                                      get,
                                      controls.zone,
                                      loaded_model);

  get_report_controls_cleanup (&controls);

  if (ret)
    {
      report_model_free (loaded_model);
      return MANAGE_GET_REPORT_ERROR;
    }

  *model = loaded_model;

  return MANAGE_GET_REPORT_SUCCESS;
}
