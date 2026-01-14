/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_groups.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Check whether a group is writable.
 *
 * @param[in]  group  Group.
 *
 * @return 1 yes, 0 no.
 */
int
group_writable (group_t group)
{
  return 1;
}

/**
 * @brief Check whether a trashcan group is writable.
 *
 * @param[in]  group  Group.
 *
 * @return 1 yes, 0 no.
 */
int
trash_group_writable (group_t group)
{
  return 1;
}

/**
 * @brief Check whether a group is in use.
 *
 * @param[in]  group  Group.
 *
 * @return 1 yes, 0 no.
 */
int
group_in_use (group_t group)
{
  return 0;
}

/**
 * @brief Check whether a trashcan group is in use.
 *
 * @param[in]  group  Group.
 *
 * @return 1 yes, 0 no.
 */
int
trash_group_in_use (group_t group)
{
  return 0;
}
