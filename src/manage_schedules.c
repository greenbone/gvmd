/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_schedules.h"
#include "manage_sql.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Return whether a schedule is writable.
 *
 * @param[in]  schedule  Schedule.
 *
 * @return 1 if writable, else 0.
 */
int
schedule_writable (schedule_t schedule)
{
  return 1;
}

/**
 * @brief Return whether a trashcan schedule is writable.
 *
 * @param[in]  schedule  Schedule.
 *
 * @return 1 if writable, else 0.
 */
int
trash_schedule_writable (schedule_t schedule)
{
  return trash_schedule_in_use (schedule) == 0;
}

/**
 * @brief Return whether a trashcan schedule is readable.
 *
 * @param[in]  schedule  Schedule.
 *
 * @return 1 if readable, else 0.
 */
int
trash_schedule_readable (schedule_t schedule)
{
  char *uuid;
  schedule_t found = 0;

  if (schedule == 0)
    return 0;
  uuid = schedule_uuid (schedule);
  if (find_trash ("schedule", uuid, &found))
    {
      g_free (uuid);
      return 0;
    }
  g_free (uuid);
  return found > 0;
}
