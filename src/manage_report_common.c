/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Report common operations.
 */

#include "manage_report_common.h"

#include "manage_filters.h"

#undef G_LOG_DOMAIN

/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Free a GET_%s_REPORT controls structure.
 * @param controls struct to free.
 */
void
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
report_resource_summary_t
report_resource_summary_new (void)
{
  return g_malloc0 (sizeof (struct report_resource_summary));
}

/**
 * @brief Free a report resource summary.
 *
 * @param[in] summary  Resource summary to free.
 */
void
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
report_task_reference_t
report_task_reference_new (void)
{
  report_task_reference_t task;

  task = g_malloc0 (sizeof (struct report_task_reference));

  task->target = report_target_reference_new ();

  return task;
}

/**
 * @brief Free a report task reference.
 *
 * @param[in] task  Task reference to free.
 */
void
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
 * @brief Allocate and initialize a report summary base.
 *
 * @return Newly allocated report summary base.
 */
report_summary_base_t
report_summary_base_new (void)
{
  return g_malloc0 (sizeof (struct report_summary_base));
}

/**
 * @brief Free a report summary base.
 *
 * @param[in] base  Report summary base to free.
 */
void
report_summary_base_free (report_summary_base_t base)
{
  if (base == NULL)
    return;

  g_free (base->id);
  g_free (base->name);
  g_free (base->comment);
  g_free (base->owner_name);
  g_free (base->timestamp);
  g_free (base->scan_start);
  g_free (base->scan_end);
  g_free (base->scan_run_status_str);
  g_free (base->timezone);
  g_free (base->timezone_abbrev);

  g_free (base);
}

/**
 * @brief Get the string representation of a report target type.
 *
 * @param[in] type  Report target type.
 *
 * @return String representation of the report target type.
 */
const gchar *
report_target_type_to_string (report_target_type_t type)
{
  switch (type)
    {
    case REPORT_TARGET_TYPE_NONE:
      return "none";

    case REPORT_TARGET_TYPE_TARGET:
      return "target";

    case REPORT_TARGET_TYPE_OCI_IMAGE:
      return "oci_image";

    case REPORT_TARGET_TYPE_WEB_APPLICATION:
      return "web_application";

    case REPORT_TARGET_TYPE_AGENT_GROUP:
      return "agent_group";

    case REPORT_TARGET_TYPE_IMPORT:
      return "import";

    default:
      return "unknown";
    }
}

/**
 * @brief Check whether a report is supported by GET_%s_REPORT.
 *
 * @param[in] report  Report resource.
 * @param [in] expected_usage_type  Expected usage type of the report.
 *
 * @return 0 if supported, 1 if unsupported, or -1 on error.
 */
static int
validate_report_usage_type (report_t report,
                             const gchar *expected_usage_type)
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

  if (usage_type && !strcmp (usage_type, expected_usage_type) == 0)
    {
      g_free (usage_type);
      return 1;
    }

  g_free (usage_type);

  return 0;
}

/**
 * @brief Get the expected usage type string for a report.
 *
 * @param[in] usage_type  Expected usage type of the report.
 *
 * @return String representation of the expected usage type, or NULL if
 *         unsupported.
 */
static const gchar *
get_report_expected_usage_type (report_usage_type_t usage_type)
{
  switch (usage_type)
    {
    case REPORT_USAGE_TYPE_SCAN:
      return "scan";

    case REPORT_USAGE_TYPE_AUDIT:
      return "audit";

    default:
      return NULL;
    }
}

/**
 * @brief Check whether a report is supported by GET_%s_REPORT.
 *
 * @param[in] report      Report resource.
 * @param[in] usage_type  Expected usage type of the report.
 *
 * @return 0 if supported, 1 if unsupported, or -1 on error.
 */
int
validate_get_report_usage_type (report_t report, report_usage_type_t usage_type)
{
  const gchar *expected_usage_type = get_report_expected_usage_type (usage_type);
  if (expected_usage_type == NULL)
    return -1;

  return validate_report_usage_type (report, expected_usage_type);
}

/**
 * @brief Validate and resolve controls needed by GET_%s_REPORT.
 *
 * @param[in]  get       GET command data.
 * @param[out] controls  Resolved controls required by the report summary.
 *
 * @return 0 on success, 2 if the filter cannot be resolved, or -1 on error.
 */
int
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
