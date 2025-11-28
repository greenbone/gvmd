/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_groups.h"
#include "manage_sql.h"
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

/**
 * @brief Create a group from an existing group.
 *
 * @param[in]  name       Name of new group.  NULL to copy from existing.
 * @param[in]  comment    Comment on new group.  NULL to copy from existing.
 * @param[in]  group_id   UUID of existing group.
 * @param[out] new_group_return  New group.
 *
 * @return 0 success, 1 group exists already, 2 failed to find existing
 *         group, 99 permission denied, -1 error.
 */
int
copy_group (const char *name, const char *comment, const char *group_id,
            group_t *new_group_return)
{
  int ret;
  group_t new, old;

  sql_begin_immediate ();

  ret = copy_resource_lock ("group", name, comment, group_id, NULL, 1, &new,
                            &old);
  if (ret)
    {
      sql_rollback ();
      return ret;
    }

  sql ("INSERT INTO group_users (\"group\", \"user\")"
       " SELECT %llu, \"user\" FROM group_users"
       " WHERE \"group\" = %llu;",
       new,
       old);

  sql_commit ();
  if (new_group_return)
    *new_group_return = new;
  return 0;
}
