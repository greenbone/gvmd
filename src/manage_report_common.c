/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Report common operations.
 */

#include "manage_report_common.h"

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
