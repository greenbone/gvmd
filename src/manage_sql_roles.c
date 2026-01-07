/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_roles.h"
#include "manage_sql_roles.h"
#include "manage_acl.h"
#include "manage_sql.h"
#include "sql.h"

/**
 * @file
 * @brief GVM management layer: Roles SQL
 *
 * The Roles SQL for the GVM management layer.
 */

/**
 * @brief List roles.
 *
 * @param[in]  log_config  Log configuration.
 * @param[in]  database    Location of manage database.
 * @param[in]  verbose     Whether to print UUID.
 *
 * @return 0 success, -1 error.
 */
int
manage_get_roles (GSList *log_config, const db_conn_info_t *database,
                  int verbose)
{
  iterator_t roles;
  int ret;

  g_info ("   Getting roles.");

  ret = manage_option_setup (log_config, database,
                             0 /* avoid_db_check_inserts */);
  if (ret)
    return ret;

  init_iterator (&roles, "SELECT name, uuid FROM roles;");
  while (next (&roles))
    if (verbose)
      printf ("%s %s\n", iterator_string (&roles, 0), iterator_string (&roles, 1));
    else
      printf ("%s\n", iterator_string (&roles, 0));

  cleanup_iterator (&roles);

  manage_option_cleanup ();

  return 0;
}

/**
 * @brief Create a role from an existing role.
 *
 * @param[in]  name       Name of new role.  NULL to copy from existing.
 * @param[in]  comment    Comment on new role.  NULL to copy from existing.
 * @param[in]  role_id    UUID of existing role.
 * @param[out] new_role_return  New role.
 *
 * @return 0 success, 1 role exists already, 2 failed to find existing
 *         role, 99 permission denied, -1 error.
 */
int
copy_role (const char *name, const char *comment, const char *role_id,
           role_t *new_role_return)
{
  int ret;
  role_t new_role, old_role;

  sql_begin_immediate ();

  if (acl_user_may ("create_role") == 0)
    return 99;

  if (acl_role_can_super_everyone (role_id))
    return 99;

  ret = copy_resource_lock ("role", name, comment, role_id, NULL, 1, &new_role,
                            &old_role);
  if (ret)
    {
      sql_rollback ();
      return ret;
    }

  sql ("INSERT INTO permissions"
       " (uuid, owner, name, comment, resource_type, resource_uuid, resource,"
       "  resource_location, subject_type, subject, subject_location,"
       "  creation_time, modification_time)"
       " SELECT make_uuid (),"
       "        (SELECT id FROM users WHERE users.uuid = '%s'),"
       "        name, comment, resource_type,"
       "        resource_uuid, resource, resource_location, subject_type, %llu,"
       "        subject_location, m_now (), m_now ()"
       " FROM permissions"
       " WHERE subject_type = 'role'"
       " AND subject = %llu"
       " AND subject_location = " G_STRINGIFY (LOCATION_TABLE)
       " AND (resource = 0 OR owner IS NULL);",
       current_credentials.uuid,
       new_role,
       old_role);

  sql_commit ();
  if (new_role_return)
    *new_role_return = new_role;
  return 0;
}

/**
 * @brief Create a role.
 *
 * @param[in]   role_name        Role name.
 * @param[in]   comment          Comment on role.
 * @param[in]   users            Users role applies to.
 * @param[in]   role             Role return.
 *
 * @return 0 success, 1 role exists already, 2 failed to find user, 4 user
 *         name validation failed, 99 permission denied, -1 error.
 */
int
create_role (const char *role_name, const char *comment, const char *users,
             role_t* role)
{
  int ret;
  gchar *quoted_role_name, *quoted_comment;

  assert (current_credentials.uuid);
  assert (role_name);
  assert (role);

  sql_begin_immediate ();

  if (acl_user_may ("create_role") == 0)
    {
      sql_rollback ();
      return 99;
    }

  if (resource_with_name_exists (role_name, "role", 0))
    {
      sql_rollback ();
      return 1;
    }

  quoted_role_name = sql_quote (role_name);
  quoted_comment = comment ? sql_quote (comment) : g_strdup ("");
  sql ("INSERT INTO roles"
       " (uuid, name, owner, comment, creation_time, modification_time)"
       " VALUES"
       " (make_uuid (), '%s',"
       "  (SELECT id FROM users WHERE users.uuid = '%s'),"
       "  '%s', m_now (), m_now ());",
       quoted_role_name,
       current_credentials.uuid,
       quoted_comment);
  g_free (quoted_comment);
  g_free (quoted_role_name);

  *role = sql_last_insert_id ();
  ret = add_users ("role", *role, users);

  if (ret)
    sql_rollback ();
  else
    sql_commit ();

  return ret;
}

/**
 * @brief Return whether a role is predefined.
 *
 * @param[in]  role  Role.
 *
 * @return 1 if predefined, else 0.
 */
int
role_is_predefined (role_t role)
{
  return sql_int ("SELECT COUNT (*) FROM roles"
                  " WHERE id = %llu"
                  " AND (uuid = '" ROLE_UUID_ADMIN "'"
                  "      OR uuid = '" ROLE_UUID_GUEST "'"
                  "      OR uuid = '" ROLE_UUID_MONITOR "'"
                  "      OR uuid = '" ROLE_UUID_INFO "'"
                  "      OR uuid = '" ROLE_UUID_USER "'"
                  "      OR uuid = '" ROLE_UUID_SUPER_ADMIN "'"
                  "      OR uuid = '" ROLE_UUID_OBSERVER "');",
                  role)
         != 0;
}

/**
 * @brief Return whether a role is predefined.
 *
 * @param[in]  uuid  UUID of role.
 *
 * @return 1 if predefined, else 0.
 */
int
role_is_predefined_id (const char *uuid)
{
  return uuid && ((strcmp (uuid, ROLE_UUID_ADMIN) == 0)
                  || (strcmp (uuid, ROLE_UUID_GUEST) == 0)
                  || (strcmp (uuid, ROLE_UUID_MONITOR) == 0)
                  || (strcmp (uuid, ROLE_UUID_INFO) == 0)
                  || (strcmp (uuid, ROLE_UUID_USER) == 0)
                  || (strcmp (uuid, ROLE_UUID_SUPER_ADMIN) == 0)
                  || (strcmp (uuid, ROLE_UUID_OBSERVER) == 0));
}

/**
 * @brief Find a role for a specific permission, given a UUID.
 *
 * @param[in]   uuid        UUID of role.
 * @param[out]  role        Role return, 0 if successfully failed to find role.
 * @param[in]   permission  Permission.
 *
 * @return FALSE on success (including if failed to find role), TRUE on error.
 */
gboolean
find_role_with_permission (const char* uuid, role_t* role,
                           const char *permission)
{
  return find_resource_with_permission ("role", uuid, role, permission, 0);
}

/**
 * @brief Find a role given a name.
 *
 * @param[in]   name  A role name.
 * @param[out]  role  Role return, 0 if successfully failed to find role.
 *
 * @return FALSE on success (including if failed to find role), TRUE on error.
 */
gboolean
find_role_by_name (const char* name, role_t *role)
{
  return find_resource_by_name ("role", name, role);
}

/**
 * @brief Delete a role.
 *
 * @param[in]  role_id   UUID of role.
 * @param[in]  ultimate  Whether to remove entirely, or to trashcan.
 *
 * @return 0 success, 1 fail because a task refers to the role, 2 failed
 *         to find role, 3 predefined role, -1 error.
 */
int
delete_role (const char *role_id, int ultimate)
{
  role_t role = 0;
  GArray *affected_users;
  iterator_t users_iter;

  sql_begin_immediate ();

  if (acl_user_may ("delete_role") == 0)
    {
      sql_rollback ();
      return 99;
    }

  if (find_role_with_permission (role_id, &role, "delete_role"))
    {
      sql_rollback ();
      return -1;
    }

  if (role == 0)
    {
      if (find_trash ("role", role_id, &role))
        {
          sql_rollback ();
          return -1;
        }
      if (role == 0)
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

      if (trash_role_in_use (role))
        {
          sql_rollback ();
          return 1;
        }

      sql ("DELETE FROM permissions"
           " WHERE resource_type = 'role'"
           " AND resource = %llu"
           " AND resource_location = " G_STRINGIFY (LOCATION_TRASH) ";",
           role);
      sql ("DELETE FROM permissions_trash"
           " WHERE resource_type = 'role'"
           " AND resource = %llu"
           " AND resource_location = " G_STRINGIFY (LOCATION_TRASH) ";",
           role);
      sql ("DELETE FROM permissions"
           " WHERE subject_type = 'role'"
           " AND subject = %llu"
           " AND subject_location = " G_STRINGIFY (LOCATION_TRASH) ";",
           role);
      sql ("DELETE FROM permissions_trash"
           " WHERE subject_type = 'role'"
           " AND subject = %llu"
           " AND subject_location = " G_STRINGIFY (LOCATION_TRASH) ";",
           role);

      tags_remove_resource ("role", role, LOCATION_TRASH);

      sql ("DELETE FROM role_users_trash WHERE role = %llu;", role);
      sql ("DELETE FROM roles_trash WHERE id = %llu;", role);
      sql_commit ();
      return 0;
    }

  if (role_is_predefined (role))
    {
      sql_rollback ();
      return 3;
    }

  if (role_in_use (role))
    {
      sql_rollback ();
      return 1;
    }

  if (ultimate == 0)
    {
      role_t trash_role;

      sql ("INSERT INTO roles_trash"
           " (uuid, owner, name, comment, creation_time, modification_time)"
           " SELECT uuid, owner, name, comment, creation_time,"
           "        modification_time"
           " FROM roles WHERE id = %llu;",
           role);

      trash_role = sql_last_insert_id ();

      sql ("INSERT INTO role_users_trash"
           " (\"role\", \"user\")"
           " SELECT %llu, \"user\""
           " FROM role_users WHERE \"role\" = %llu;",
           trash_role,
           role);

      permissions_set_locations ("role", role, trash_role, LOCATION_TRASH);
      tags_set_locations ("role", role, trash_role, LOCATION_TRASH);
      permissions_set_subjects ("role", role, trash_role, LOCATION_TRASH);
    }
  else
    {
      sql ("DELETE FROM permissions"
           " WHERE resource_type = 'role'"
           " AND resource = %llu"
           " AND resource_location = " G_STRINGIFY (LOCATION_TRASH) ";",
           role);
      sql ("DELETE FROM permissions_trash"
           " WHERE resource_type = 'role'"
           " AND resource = %llu"
           " AND resource_location = " G_STRINGIFY (LOCATION_TRASH) ";",
           role);
      sql ("DELETE FROM permissions"
           " WHERE subject_type = 'role'"
           " AND subject = %llu"
           " AND subject_location = " G_STRINGIFY (LOCATION_TABLE) ";",
           role);
      sql ("DELETE FROM permissions_trash"
           " WHERE subject_type = 'role'"
           " AND subject = %llu"
           " AND subject_location = " G_STRINGIFY (LOCATION_TABLE) ";",
           role);
      tags_remove_resource ("role", role, LOCATION_TABLE);
    }

  affected_users = g_array_new (TRUE, TRUE, sizeof (user_t));
  init_iterator (&users_iter,
                  "SELECT \"user\" FROM role_users"
                  " WHERE \"role\" = %llu",
                  role);
  while (next (&users_iter))
    {
      user_t user = iterator_int64 (&users_iter, 0);
      g_array_append_val (affected_users, user);
    }
  cleanup_iterator (&users_iter);

  sql ("DELETE FROM role_users WHERE \"role\" = %llu;", role);
  sql ("DELETE FROM roles WHERE id = %llu;", role);

  cache_all_permissions_for_users (affected_users);
  g_array_free (affected_users, TRUE);

  sql_commit ();
  return 0;
}
