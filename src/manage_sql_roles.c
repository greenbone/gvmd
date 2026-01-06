/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_roles.h"
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
