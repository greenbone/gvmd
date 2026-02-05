/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_targets.h"
#include "manage.h"

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
