/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_groups.h"
#include "manage_acl.h"
#include "manage_sql.h"
#include "manage_sql_permissions.h"
#include "manage_sql_permissions_cache.h"
#include "manage_sql_resources.h"
#include "manage_sql_users.h"
#include "sql.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @file
 * @brief GVM management layer: Group SQL
 *
 * The Group SQL for the GVM management layer.
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
 * @brief Gets users of group as a string.
 *
 * @param[in]  group  Group.
 *
 * @return Users.
 */
gchar *
group_users (group_t group)
{
  return sql_string ("SELECT group_concat (name, ', ')"
                     " FROM (SELECT users.name FROM users, group_users"
                     "       WHERE group_users.\"group\" = %llu"
                     "       AND group_users.user = users.id"
                     "       GROUP BY users.name)"
                     "      AS sub;",
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

/**
 * @brief Delete a group.
 *
 * @param[in]  group_id  UUID of group.
 * @param[in]  ultimate   Whether to remove entirely, or to trashcan.
 *
 * @return 0 success, 1 fail because a permission refers to the group, 2 failed
 *         to find group, 3 predefined group, 99 permission denied, -1 error.
 */
int
delete_group (const char *group_id, int ultimate)
{
  group_t group = 0;
  GArray *affected_users;
  iterator_t users_iter;

  sql_begin_immediate ();

  if (acl_user_may ("delete_group") == 0)
    {
      sql_rollback ();
      return 99;
    }

  if (find_group_with_permission (group_id, &group, "delete_group"))
    {
      sql_rollback ();
      return -1;
    }

  if (group == 0)
    {
      if (find_trash ("group", group_id, &group))
        {
          sql_rollback ();
          return -1;
        }
      if (group == 0)
        {
          sql_rollback ();
          return 2;
        }
      if (ultimate == 0)
        {
          /* It's already in the trashcan. */
          sql_commit ();
          return 0;
        }

      if (trash_group_in_use (group))
        {
          sql_rollback ();
          return 1;
        }

      sql ("DELETE FROM permissions"
           " WHERE resource_type = 'group'"
           " AND resource = %llu"
           " AND resource_location = " G_STRINGIFY (LOCATION_TRASH) ";",
           group);
      sql ("DELETE FROM permissions_trash"
           " WHERE resource_type = 'group'"
           " AND resource = %llu"
           " AND resource_location = " G_STRINGIFY (LOCATION_TRASH) ";",
           group);
      sql ("DELETE FROM permissions"
           " WHERE subject_type = 'group'"
           " AND subject = %llu"
           " AND subject_location = " G_STRINGIFY (LOCATION_TRASH) ";",
           group);
      sql ("DELETE FROM permissions_trash"
           " WHERE subject_type = 'group'"
           " AND subject = %llu"
           " AND subject_location = " G_STRINGIFY (LOCATION_TRASH) ";",
           group);

      tags_remove_resource ("group", group, LOCATION_TRASH);

      sql ("DELETE FROM group_users_trash WHERE \"group\" = %llu;", group);
      sql ("DELETE FROM groups_trash WHERE id = %llu;", group);
      sql_commit ();
      return 0;
    }

  if (group_in_use (group))
    {
      sql_rollback ();
      return 1;
    }

  if (ultimate == 0)
    {
      group_t trash_group;

      sql ("INSERT INTO groups_trash"
           " (uuid, owner, name, comment, creation_time, modification_time)"
           " SELECT uuid, owner, name, comment, creation_time,"
           "  modification_time"
           " FROM groups WHERE id = %llu;",
           group);

      trash_group = sql_last_insert_id ();

      sql ("INSERT INTO group_users_trash"
           " (\"group\", \"user\")"
           " SELECT %llu, \"user\""
           " FROM group_users WHERE \"group\" = %llu;",
           trash_group,
           group);

      permissions_set_locations ("group", group, trash_group, LOCATION_TRASH);
      tags_set_locations ("group", group, trash_group, LOCATION_TRASH);
      permissions_set_subjects ("group", group, trash_group, LOCATION_TRASH);
    }
  else
    {
      sql ("DELETE FROM permissions"
           " WHERE resource_type = 'group'"
           " AND resource = %llu"
           " AND resource_location = " G_STRINGIFY (LOCATION_TRASH) ";",
           group);
      sql ("DELETE FROM permissions_trash"
           " WHERE resource_type = 'group'"
           " AND resource = %llu"
           " AND resource_location = " G_STRINGIFY (LOCATION_TRASH) ";",
           group);
      sql ("DELETE FROM permissions"
           " WHERE subject_type = 'group'"
           " AND subject = %llu"
           " AND subject_location = " G_STRINGIFY (LOCATION_TABLE) ";",
           group);
      sql ("DELETE FROM permissions_trash"
           " WHERE subject_type = 'group'"
           " AND subject = %llu"
           " AND subject_location = " G_STRINGIFY (LOCATION_TABLE) ";",
           group);
    }

  tags_remove_resource ("group", group, LOCATION_TABLE);

  affected_users = g_array_new (TRUE, TRUE, sizeof (user_t));
  init_iterator (&users_iter,
                  "SELECT \"user\" FROM group_users"
                  " WHERE \"group\" = %llu",
                  group);
  while (next (&users_iter))
    {
      user_t user = iterator_int64 (&users_iter, 0);
      g_array_append_val (affected_users, user);
    }
  cleanup_iterator (&users_iter);

  sql ("DELETE FROM group_users WHERE \"group\" = %llu;", group);
  sql ("DELETE FROM groups WHERE id = %llu;", group);

  cache_all_permissions_for_users (affected_users);
  g_array_free (affected_users, TRUE);

  sql_commit ();
  return 0;
}

/**
 * @brief Modify a group.
 *
 * @param[in]   group_id       UUID of group.
 * @param[in]   name           Name of group.
 * @param[in]   comment        Comment on group.
 * @param[in]   users          Group users.
 *
 * @return 0 success, 1 failed to find group, 2 failed to find user, 3 group_id
 *         required, 4 user name validation failed, 5 group with new name
 *         exists, 99 permission denied, -1 internal error.
 */
int
modify_group (const char *group_id, const char *name, const char *comment,
              const char *users)
{
  int ret;
  gchar *quoted_name, *quoted_comment;
  group_t group;
  GArray *affected_users;
  iterator_t users_iter;

  assert (current_credentials.uuid);

  if (group_id == NULL)
    return 3;

  sql_begin_immediate ();

  if (acl_user_may ("modify_group") == 0)
    {
      sql_rollback ();
      return 99;
    }

  group = 0;

  if (find_group_with_permission (group_id, &group, "modify_group"))
    {
      sql_rollback ();
      return -1;
    }

  if (group == 0)
    {
      sql_rollback ();
      return 1;
    }

  /* Check whether a group with the same name exists already. */
  if (name)
    {
      if (resource_with_name_exists (name, "group", group))
        {
          sql_rollback ();
          return 5;
        }
    }

  quoted_name = sql_quote(name ?: "");
  quoted_comment = sql_quote (comment ? comment : "");

  sql ("UPDATE groups SET"
       " name = '%s',"
       " comment = '%s',"
       " modification_time = m_now ()"
       " WHERE id = %llu;",
       quoted_name,
       quoted_comment,
       group);

  g_free (quoted_comment);
  g_free (quoted_name);

  affected_users = g_array_new (TRUE, TRUE, sizeof (user_t));
  init_iterator (&users_iter,
                 "SELECT \"user\" FROM group_users"
                 " WHERE \"group\" = %llu",
                 group);
  while (next (&users_iter))
    {
      user_t user = iterator_int64 (&users_iter, 0);
      g_array_append_val (affected_users, user);
    }
  cleanup_iterator (&users_iter);

  sql ("DELETE FROM group_users WHERE \"group\" = %llu;", group);

  ret = add_users ("group", group, users);

  init_iterator (&users_iter,
                 "SELECT \"user\" FROM group_users"
                 " WHERE \"group\" = %llu",
                 group);

  // users not looked for in this above loop were removed
  //  -> possible permissions change
  while (next (&users_iter))
    {
      int index, found_user;
      user_t user = iterator_int64 (&users_iter, 0);

      found_user = 0;
      for (index = 0; index < affected_users->len && found_user == 0; index++)
        {
          if (g_array_index (affected_users, user_t, index) == user)
            {
              found_user = 1;
              break;
            }
        }

      if (found_user)
        {
          // users found here stay in the group -> no change in permissions
          g_array_remove_index_fast (affected_users, index);
        }
      else
        {
          // user added to group -> possible permissions change
          g_array_append_val (affected_users, user);
        }
    }

  cleanup_iterator (&users_iter);

  cache_all_permissions_for_users (affected_users);

  g_array_free (affected_users, TRUE);

  if (ret)
    sql_rollback ();
  else
    sql_commit ();

  return ret;
}

/**
 * @brief Count number of groups.
 *
 * @param[in]  get  GET params.
 *
 * @return Total number of groups in grouped set.
 */
int
group_count (const get_data_t *get)
{
  static const char *filter_columns[] = GROUP_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = GROUP_ITERATOR_COLUMNS;
  static column_t trash_columns[] = GROUP_ITERATOR_TRASH_COLUMNS;
  return count ("group", get, columns, trash_columns, filter_columns,
                0, 0, 0, TRUE);
}

/**
 * @brief Initialise a group iterator, including observed groups.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  get         GET data.
 *
 * @return 0 success, 1 failed to find group, 2 failed to find group (filt_id),
 *         -1 error.
 */
int
init_group_iterator (iterator_t* iterator, get_data_t *get)
{
  static const char *filter_columns[] = GROUP_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = GROUP_ITERATOR_COLUMNS;
  static column_t trash_columns[] = GROUP_ITERATOR_TRASH_COLUMNS;

  return init_get_iterator (iterator,
                            "group",
                            get,
                            columns,
                            trash_columns,
                            filter_columns,
                            0,
                            NULL,
                            NULL,
                            TRUE);
}
