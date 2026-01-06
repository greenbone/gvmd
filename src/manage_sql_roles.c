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
