/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_targets.h"
#include "manage.h"
#include "manage_sql.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Max number of hosts per target.
 */
static int max_hosts = MANAGE_MAX_HOSTS;

/**
 * @brief Get the maximum allowed number of hosts per target.
 *
 * @return Maximum.
 */
int
manage_max_hosts ()
{
  return max_hosts;
}

/**
 * @brief Set the maximum allowed number of hosts per target.
 *
 * @param[in]   new_max   New max_hosts value.
 */
void
manage_set_max_hosts (int new_max)
{
  max_hosts = new_max;
}

/**
 * @brief Return whether a trashcan target is readable.
 *
 * @param[in]  target  Target.
 *
 * @return 1 if readable, else 0.
 */
int
trash_target_readable (target_t target)
{
  char *uuid;
  target_t found = 0;

  if (target == 0)
    return 0;
  uuid = target_uuid (target);
  if (find_trash ("target", uuid, &found))
    {
      g_free (uuid);
      return 0;
    }
  g_free (uuid);
  return found > 0;
}
