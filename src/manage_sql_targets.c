/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_targets.h"
#include "manage_acl.h"
#include "manage_sql_permissions.h"
#include "manage_sql_resources.h"
#include "sql.h"

#include <assert.h>

/**
 * @file
 * @brief GVM management layer: Targets SQL
 *
 * The Targets SQL for the GVM management layer.
 */

/**
 * @brief Find a target for a specific permission, given a UUID.
 *
 * @param[in]   uuid        UUID of target.
 * @param[out]  target      Target return, 0 if successfully failed to find target.
 * @param[in]   permission  Permission.
 *
 * @return FALSE on success (including if failed to find target), TRUE on error.
 */
gboolean
find_target_with_permission (const char* uuid, target_t* target,
                             const char *permission)
{
  return find_resource_with_permission ("target", uuid, target, permission, 0);
}

/**
 * @brief Return the UUID of a target.
 *
 * @param[in]  target  Target.
 *
 * @return Newly allocated UUID if available, else NULL.
 */
char*
target_uuid (target_t target)
{
  return sql_string ("SELECT uuid FROM targets WHERE id = %llu;",
                     target);
}

/**
 * @brief Return the UUID of a trashcan target.
 *
 * @param[in]  target  Target.
 *
 * @return Newly allocated UUID if available, else NULL.
 */
char*
trash_target_uuid (target_t target)
{
  return sql_string ("SELECT uuid FROM targets_trash WHERE id = %llu;",
                     target);
}

/**
 * @brief Return the name of a target.
 *
 * @param[in]  target  Target.
 *
 * @return Newly allocated name if available, else NULL.
 */
char*
target_name (target_t target)
{
  return sql_string ("SELECT name FROM targets WHERE id = %llu;",
                     target);
}

/**
 * @brief Return the name of a trashcan target.
 *
 * @param[in]  target  Target.
 *
 * @return Newly allocated name if available, else NULL.
 */
char*
trash_target_name (target_t target)
{
  return sql_string ("SELECT name FROM targets_trash WHERE id = %llu;",
                     target);
}

/**
 * @brief Return the comment of a target.
 *
 * @param[in]  target  Target.
 *
 * @return Newly allocated name if available, else NULL.
 */
char*
target_comment (target_t target)
{
  return sql_string ("SELECT comment FROM targets WHERE id = %llu;",
                     target);
}

/**
 * @brief Return the comment of a trashcan target.
 *
 * @param[in]  target  Target.
 *
 * @return Newly allocated name if available, else NULL.
 */
char*
trash_target_comment (target_t target)
{
  return sql_string ("SELECT comment FROM targets_trash WHERE id = %llu;",
                     target);
}

/**
 * @brief Return the hosts associated with a target.
 *
 * @param[in]  target  Target.
 *
 * @return Newly allocated comma separated list of hosts if available,
 *         else NULL.
 */
char*
target_hosts (target_t target)
{
  return sql_string ("SELECT hosts FROM targets WHERE id = %llu;",
                     target);
}

/**
 * @brief Return the excluded hosts associated with a target.
 *
 * @param[in]  target  Target.
 *
 * @return Newly allocated comma separated list of excluded hosts if available,
 *         else NULL.
 */
char*
target_exclude_hosts (target_t target)
{
  return sql_string ("SELECT exclude_hosts FROM targets WHERE id = %llu;",
                     target);
}

/**
 * @brief Return the reverse_lookup_only value of a target.
 *
 * @param[in]  target  Target.
 *
 * @return Reverse lookup only value if available, else NULL.
 */
char*
target_reverse_lookup_only (target_t target)
{
  return sql_string ("SELECT reverse_lookup_only FROM targets"
                     " WHERE id = %llu;", target);
}

/**
 * @brief Return the reverse_lookup_unify value of a target.
 *
 * @param[in]  target  Target.
 *
 * @return Reverse lookup unify value if available, else NULL.
 */
char*
target_reverse_lookup_unify (target_t target)
{
  return sql_string ("SELECT reverse_lookup_unify FROM targets"
                     " WHERE id = %llu;", target);
}

/**
 * @brief Return the allow_simultaneous_ips value of a target.
 *
 * @param[in]  target  Target.
 *
 * @return The allow_simultaneous_ips value if available, else NULL.
 */
char*
target_allow_simultaneous_ips (target_t target)
{
  return sql_string ("SELECT allow_simultaneous_ips FROM targets"
                     " WHERE id = %llu;", target);
}

/**
 * @brief Get a login port from a target.
 *
 * @param[in]  target         The target.
 * @param[in]  type           The credential type (e.g. "ssh" or "smb").
 *
 * @return  0 on success, -1 on error, 1 credential not found, 99 permission
 *          denied.
 */
static int
target_login_port (target_t target, const char* type)
{
  gchar *quoted_type;
  int port;

  if (target == 0 || type == NULL)
    return 0;

  quoted_type = sql_quote (type);

  if (sql_int ("SELECT NOT EXISTS"
               " (SELECT * FROM targets_login_data"
               "  WHERE target = %llu and type = '%s');",
               target, quoted_type))
    {
      g_free (quoted_type);
      return 0;
    }

  port = sql_int ("SELECT port FROM targets_login_data"
                  " WHERE target = %llu AND type = '%s';",
                  target, quoted_type);

  g_free (quoted_type);

  return port;
}

/**
 * @brief Return the SSH LSC port of a target.
 *
 * @param[in]  target  Target.
 *
 * @return Newly allocated port if available, else NULL.
 */
char*
target_ssh_port (target_t target)
{
  int port = target_login_port (target, "ssh");
  return port ? g_strdup_printf ("%d", port) : NULL;
}

/**
 * @brief Get a credential from a target.
 *
 * @param[in]  target         The target.
 * @param[in]  type           The credential type (e.g. "ssh" or "smb").
 *
 * @return  0 on success, -1 on error, 1 credential not found, 99 permission
 *          denied.
 */
credential_t
target_credential (target_t target, const char* type)
{
  gchar *quoted_type;
  credential_t credential;

  if (target == 0 || type == NULL)
    return 0;

  quoted_type = sql_quote (type);

  if (sql_int ("SELECT NOT EXISTS"
               " (SELECT * FROM targets_login_data"
               "  WHERE target = %llu and type = '%s');",
               target, quoted_type))
    {
      g_free (quoted_type);
      return 0;
    }

  sql_int64 (&credential,
             "SELECT credential FROM targets_login_data"
             " WHERE target = %llu AND type = '%s';",
             target, quoted_type);

  g_free (quoted_type);

  return credential;
}

/**
 * @brief Return the SSH credential associated with a target, if any.
 *
 * @param[in]  target  Target.
 *
 * @return SSH credential if any, else 0.
 */
credential_t
target_ssh_credential (target_t target)
{
  return target_credential (target, "ssh");
}

/**
 * @brief Return the SMB credential associated with a target, if any.
 *
 * @param[in]  target  Target.
 *
 * @return SMB credential if any, else 0.
 */
credential_t
target_smb_credential (target_t target)
{
  return target_credential (target, "smb");
}

/**
 * @brief Return the ESXi credential associated with a target, if any.
 *
 * @param[in]  target  Target.
 *
 * @return ESXi credential if any, else 0.
 */
credential_t
target_esxi_credential (target_t target)
{
  return target_credential (target, "esxi");
}

/**
 * @brief Return the ELEVATE credential associated with a target, if any.
 *
 * @param[in]  target  Target.
 *
 * @return ELEVATE credential if any, else 0.
 */
credential_t
target_ssh_elevate_credential (target_t target)
{
  return target_credential (target, "elevate");
}

/**
 * @brief Return the Kerberos 5 credential associated with a target, if any.
 *
 * @param[in]  target  Target.
 *
 * @return Kerberos 5 credential if any, else 0.
 */
credential_t
target_krb5_credential (target_t target)
{
  return target_credential (target, "krb5");
}

/**
 * @brief Create a target from an existing target.
 *
 * @param[in]  name        Name of new target.  NULL to copy from existing.
 * @param[in]  comment     Comment on new target.  NULL to copy from existing.
 * @param[in]  target_id   UUID of existing target.
 * @param[out] new_target  New target.
 *
 * @return 0 success, 1 target exists already, 2 failed to find existing
 *         target, 99 permission denied, -1 error.
 */
int
copy_target (const char* name, const char* comment, const char *target_id,
             target_t* new_target)
{
  int ret;
  target_t old_target;

  assert (new_target);

  ret = copy_resource ("target", name, comment, target_id,
                       "hosts, exclude_hosts, port_list, reverse_lookup_only,"
                       " reverse_lookup_unify, alive_test,"
                       " allow_simultaneous_ips",
                       1, new_target, &old_target);
  if (ret)
    return ret;

  sql ("INSERT INTO targets_login_data (target, type, credential, port)"
       " SELECT %llu, type, credential, port"
       "   FROM targets_login_data"
       "  WHERE target = %llu;",
       *new_target, old_target);

  return 0;
}

/**
 * @brief Delete a target.
 *
 * @param[in]  target_id  UUID of target.
 * @param[in]  ultimate   Whether to remove entirely, or to trashcan.
 *
 * @return 0 success, 1 fail because a task refers to the target, 2 failed
 *         to find target, 99 permission denied, -1 error.
 */
int
delete_target (const char *target_id, int ultimate)
{
  target_t target = 0;
  target_t trash_target;

  sql_begin_immediate ();

  if (acl_user_may ("delete_target") == 0)
    {
      sql_rollback ();
      return 99;
    }

  if (find_target_with_permission (target_id, &target, "delete_target"))
    {
      sql_rollback ();
      return -1;
    }

  if (target == 0)
    {
      if (find_trash ("target", target_id, &target))
        {
          sql_rollback ();
          return -1;
        }
      if (target == 0)
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

      /* Check if it's in use by a task in the trashcan. */
      if (sql_int ("SELECT count(*) FROM tasks"
                   " WHERE target = %llu"
                   " AND target_location = " G_STRINGIFY (LOCATION_TRASH) ";",
                   target))
        {
          sql_rollback ();
          return 1;
        }

      permissions_set_orphans ("target", target, LOCATION_TRASH);
      tags_remove_resource ("target", target, LOCATION_TRASH);

      sql ("DELETE FROM targets_trash_login_data WHERE target = %llu;", target);
      sql ("DELETE FROM targets_trash WHERE id = %llu;", target);
      sql_commit ();
      return 0;
    }

  if (ultimate == 0)
    {
      if (sql_int ("SELECT count(*) FROM tasks"
                   " WHERE target = %llu"
                   " AND target_location = " G_STRINGIFY (LOCATION_TABLE)
                   " AND hidden = 0;",
                   target))
        {
          sql_rollback ();
          return 1;
        }

      sql ("INSERT INTO targets_trash"
           " (uuid, owner, name, hosts, exclude_hosts, comment,"
           "  port_list, port_list_location,"
           "  reverse_lookup_only, reverse_lookup_unify, alive_test,"
           "  allow_simultaneous_ips,"
           "  creation_time, modification_time)"
           " SELECT uuid, owner, name, hosts, exclude_hosts, comment,"
           "        port_list, " G_STRINGIFY (LOCATION_TABLE) ","
           "        reverse_lookup_only, reverse_lookup_unify, alive_test,"
           "        allow_simultaneous_ips,"
           "        creation_time, modification_time"
           " FROM targets WHERE id = %llu;",
           target);

      trash_target = sql_last_insert_id ();

      /* Copy login data */
      sql ("INSERT INTO targets_trash_login_data"
           " (target, type, credential, port, credential_location)"
           " SELECT %llu, type, credential, port, "
           G_STRINGIFY (LOCATION_TABLE)
           "   FROM targets_login_data WHERE target = %llu;",
           trash_target, target);

      /* Update the location of the target in any trashcan tasks. */
      sql ("UPDATE tasks"
           " SET target = %llu,"
           "     target_location = " G_STRINGIFY (LOCATION_TRASH)
           " WHERE target = %llu"
           " AND target_location = " G_STRINGIFY (LOCATION_TABLE) ";",
           sql_last_insert_id (),
           target);

      permissions_set_locations ("target", target,
                                 sql_last_insert_id (),
                                 LOCATION_TRASH);
      tags_set_locations ("target", target,
                          sql_last_insert_id (),
                          LOCATION_TRASH);
    }
  else if (sql_int ("SELECT count(*) FROM tasks"
                    " WHERE target = %llu"
                    " AND target_location = " G_STRINGIFY (LOCATION_TABLE),
                    target))
    {
      sql_rollback ();
      return 1;
    }
  else
    {
      permissions_set_orphans ("target", target, LOCATION_TABLE);
      tags_remove_resource ("target", target, LOCATION_TABLE);
    }

  sql ("DELETE FROM targets_login_data WHERE target = %llu;", target);
  sql ("DELETE FROM targets WHERE id = %llu;", target);

  sql_commit ();
  return 0;
}
