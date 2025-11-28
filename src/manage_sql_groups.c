/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_groups.h"
#include "manage_acl.h"
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

/**
 * @brief Find a group for a specific permission, given a UUID.
 *
 * @param[in]   uuid        UUID of group.
 * @param[out]  group       Group return, 0 if successfully failed to find group.
 * @param[in]   permission  Permission.
 *
 * @return FALSE on success (including if failed to find group), TRUE on error.
 */
gboolean
find_group_with_permission (const char* uuid, group_t* group,
                            const char *permission)
{
  return find_resource_with_permission ("group", uuid, group, permission, 0);
}

/**
 * @brief Create a group.
 *
 * @param[in]   group_name       Group name.
 * @param[in]   comment          Comment on group.
 * @param[in]   users            Users group applies to.
 * @param[in]   special_full     Whether to give group super on itself (full
 *                               sharing between members).
 * @param[out]  group            Group return.
 *
 * @return 0 success, 1 group exists already, 2 failed to find user, 4 user
 *         name validation failed, 99 permission denied, -1 error.
 */
int
create_group (const char *group_name, const char *comment, const char *users,
              int special_full, group_t* group)
{
  int ret;
  gchar *quoted_group_name, *quoted_comment;

  assert (current_credentials.uuid);
  assert (group_name);
  assert (group);

  sql_begin_immediate ();

  if (acl_user_may ("create_group") == 0)
    {
      sql_rollback ();
      return 99;
    }

  if (resource_with_name_exists (group_name, "group", 0))
    {
      sql_rollback ();
      return 1;
    }
  quoted_group_name = sql_quote (group_name);
  quoted_comment = comment ? sql_quote (comment) : g_strdup ("");
  sql ("INSERT INTO groups"
       " (uuid, name, owner, comment, creation_time, modification_time)"
       " VALUES"
       " (make_uuid (), '%s',"
       "  (SELECT id FROM users WHERE uuid = '%s'),"
       "  '%s', m_now (), m_now ());",
       quoted_group_name,
       current_credentials.uuid,
       quoted_comment);
  g_free (quoted_comment);
  g_free (quoted_group_name);

  *group = sql_last_insert_id ();
  ret = add_users ("group", *group, users);

  if (ret)
    sql_rollback ();
  else
    {
      if (special_full)
        {
          char *group_id;

          group_id = group_uuid (*group);
          ret = create_permission_internal (1, "Super", NULL, "group", group_id,
                                            "group", group_id, NULL);
          g_free (group_id);
          if (ret)
            {
              sql_rollback ();
              return ret;
            }
        }
      sql_commit ();
    }

  return ret;
}
