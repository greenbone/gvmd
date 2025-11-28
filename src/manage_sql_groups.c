/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_groups.h"
#include "sql.h"

/**
 * @file
 * @brief GVM management layer: Asset SQL
 *
 * The Asset SQL for the GVM management layer.
 */

/**
 * @brief Return the UUID of a group.
 *
 * @param[in]  group  Group.
 *
 * @return Newly allocated UUID if available, else NULL.
 */
char*
group_uuid (group_t group)
{
  return sql_string ("SELECT uuid FROM groups WHERE id = %llu;",
                     group);
}
