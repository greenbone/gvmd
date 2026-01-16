/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_users.h"
#include "manage_acl.h"
#include "manage_authentication.h"
#include "manage_filters.h"
#include "manage_port_lists.h"
#include "manage_report_formats.h"
#include "manage_sql.h"
#include "manage_sql_groups.h"
#include "manage_sql_port_lists.h"
#include "manage_sql_report_configs.h"
#include "manage_sql_report_formats.h"
#include "manage_sql_roles.h"
#include "manage_sql_tickets.h"
#include "manage_sql_tls_certificates.h"
#include "sql.h"

#include <gvm/base/pwpolicy.h>
#include <gvm/util/uuidutils.h>

/**
 * @file
 * @brief GVM management layer: Users SQL
 *
 * The Users SQL for the GVM management layer.
 */

/**
 * @brief Return the name of a user.
 *
 * @param[in]  uuid  UUID of user.
 *
 * @return Newly allocated name if available, else NULL.
 */
gchar *
user_name (const char *uuid)
{
  gchar *name, *quoted_uuid;

  quoted_uuid = sql_quote (uuid);
  name = sql_string ("SELECT name FROM users WHERE uuid = '%s';",
                     quoted_uuid);
  g_free (quoted_uuid);
  return name;
}

/**
 * @brief Return the UUID of a user.
 *
 * Warning: this is only safe for users that are known to be in the db.
 *
 * @param[in]  user  User.
 *
 * @return Newly allocated UUID if available, else NULL.
 */
char*
user_uuid (user_t user)
{
  return sql_string ("SELECT uuid FROM users WHERE id = %llu;",
                     user);
}

/**
 * @brief Return the hosts of a user.
 *
 * @param[in]  uuid  UUID of user.
 *
 * @return Newly allocated hosts value if available, else NULL.
 */
gchar *
user_hosts (const char *uuid)
{
  gchar *name, *quoted_uuid;

  quoted_uuid = sql_quote (uuid);
  name = sql_string ("SELECT hosts FROM users WHERE uuid = '%s';",
                     quoted_uuid);
  g_free (quoted_uuid);
  return name;
}

/**
 * @brief Return whether hosts value of a user denotes allowed.
 *
 * @param[in]  uuid  UUID of user.
 *
 * @return 1 if allow, else 0.
 */
int
user_hosts_allow (const char *uuid)
{
  gchar *quoted_uuid;
  int allow;

  quoted_uuid = sql_quote (uuid);
  allow = sql_int ("SELECT hosts_allow FROM users WHERE uuid = '%s';",
                   quoted_uuid);
  g_free (quoted_uuid);
  return allow;
}

/**
 * @brief Count number of users.
 *
 * @param[in]  get  GET params.
 *
 * @return Total number of users in usered set.
 */
int
user_count (const get_data_t *get)
{
  static const char *filter_columns[] = USER_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = USER_ITERATOR_COLUMNS;
  return count ("user", get, columns, NULL, filter_columns,
                  0, 0, 0, TRUE);
}

/**
 * @brief Initialise a user iterator, including observed users.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  get         GET data.
 *
 * @return 0 success, 1 failed to find user, 2 failed to find user (filt_id),
 *         -1 error.
 */
int
init_user_iterator (iterator_t* iterator, get_data_t *get)
{
  static const char *filter_columns[] = USER_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = USER_ITERATOR_COLUMNS;
  static column_t trash_columns[] = USER_ITERATOR_TRASH_COLUMNS;

  return init_get_iterator (iterator,
                            "user",
                            get,
                            columns,
                            trash_columns,
                            filter_columns,
                            0,
                            NULL,
                            NULL,
                            TRUE);
}

/**
 * @brief Get the method of the user from a user iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Method of the user or NULL if iteration is complete.
 */
DEF_ACCESS (user_iterator_method, GET_ITERATOR_COLUMN_COUNT);

/**
 * @brief Get the hosts from a user iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Hosts or NULL if iteration is complete.
 */
DEF_ACCESS (user_iterator_hosts, GET_ITERATOR_COLUMN_COUNT + 1);

/**
 * @brief Get the hosts allow value from a user iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Hosts allow.
 */
int
user_iterator_hosts_allow (iterator_t* iterator)
{
  if (iterator->done) return -1;
  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 2);
}

/**
 * @brief Initialise an info iterator.
 *
 * @param[in]  iterator        Iterator.
 * @param[in]  user            User.
 */
void
init_user_group_iterator (iterator_t *iterator, user_t user)
{
  gchar *available, *with_clause;
  get_data_t get;
  array_t *permissions;

  assert (user);

  get.trash = 0;
  permissions = make_array ();
  array_add (permissions, g_strdup ("get_groups"));
  available = acl_where_owned ("group", &get, 1, "any", 0, permissions, 0,
                               &with_clause);
  array_free (permissions);

  init_iterator (iterator,
                 "%s"
                 " SELECT DISTINCT id, uuid, name, %s FROM groups"
                 " WHERE id IN (SELECT \"group\" FROM group_users"
                 "              WHERE \"user\" = %llu)"
                 " ORDER by name;",
                 with_clause ? with_clause : "",
                 available,
                 user);

  g_free (with_clause);
  g_free (available);
}

/**
 * @brief Get the UUID from a user group iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return UUID or NULL if iteration is complete.  Freed by cleanup_iterator.
 */
DEF_ACCESS (user_group_iterator_uuid, 1);

/**
 * @brief Get the NAME from a user group iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return NAME or NULL if iteration is complete.  Freed by cleanup_iterator.
 */
DEF_ACCESS (user_group_iterator_name, 2);

/**
 * @brief Get the read permission status from a GET iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return 1 if may read, else 0.
 */
int
user_group_iterator_readable (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return iterator_int (iterator, 3);
}

/**
 * @brief Initialise an info iterator.
 *
 * @param[in]  iterator        Iterator.
 * @param[in]  user            User.
 */
void
init_user_role_iterator (iterator_t *iterator, user_t user)
{
  gchar *available, *with_clause;
  get_data_t get;
  array_t *permissions;

  assert (user);

  get.trash = 0;
  permissions = make_array ();
  array_add (permissions, g_strdup ("get_roles"));
  available = acl_where_owned ("role", &get, 1, "any", 0, permissions, 0,
                               &with_clause);
  array_free (permissions);

  init_iterator (iterator,
                 "%s"
                 " SELECT DISTINCT id, uuid, name, order_role (name), %s"
                 " FROM roles"
                 " WHERE id IN (SELECT role FROM role_users"
                 "              WHERE \"user\" = %llu)"
                 " ORDER by order_role (name);",
                 with_clause ? with_clause : "",
                 available,
                 user);

  g_free (with_clause);
  g_free (available);
}

/**
 * @brief Get the UUID from a user role iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return UUID or NULL if iteration is complete.  Freed by cleanup_iterator.
 */
DEF_ACCESS (user_role_iterator_uuid, 1);

/**
 * @brief Get the NAME from a user role iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return NAME or NULL if iteration is complete.  Freed by cleanup_iterator.
 */
DEF_ACCESS (user_role_iterator_name, 2);

/**
 * @brief Get the read permission status from a GET iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return 1 if may read, else 0.
 */
int
user_role_iterator_readable (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return iterator_int (iterator, 4);
}

/**
 * @brief Find a user for a specific permission, given a UUID.
 *
 * @param[in]   uuid        UUID of user.
 * @param[out]  user        User return, 0 if successfully failed to find user.
 * @param[in]   permission  Permission.
 *
 * @return FALSE on success (including if failed to find user), TRUE on error.
 */
gboolean
find_user_with_permission (const char* uuid, user_t* user,
                           const char *permission)
{
  return find_resource_with_permission ("user", uuid, user, permission, 0);
}

/**
 * @brief Find a user given a name.
 *
 * @param[in]   name  A user name.
 * @param[out]  user  User return, 0 if successfully failed to find user.
 * @param[in]   permission  Permission.
 *
 * @return FALSE on success (including if failed to find user), TRUE on error.
 */
gboolean
find_user_by_name_with_permission (const char* name, user_t *user,
                                   const char *permission)
{
  return find_resource_by_name_with_permission ("user", name, user, permission);
}

/**
 * @brief Find a user given a name.
 *
 * @param[in]   name  A user name.
 * @param[out]  user  User return, 0 if successfully failed to find user.
 *
 * @return FALSE on success (including if failed to find user), TRUE on error.
 */
gboolean
find_user_by_name (const char* name, user_t *user)
{
  return find_resource_by_name ("user", name, user);
}

/**
 * @brief Check if user exists.
 *
 * @param[in]  name    User name.
 * @param[in]  method  Auth method.
 *
 * @return 1 yes, 0 no.
 */
int
user_exists_method (const gchar *name, auth_method_t method)
{
  gchar *quoted_name, *quoted_method;
  int ret;

  quoted_name = sql_quote (name);
  quoted_method = sql_quote (auth_method_name (method));
  ret = sql_int ("SELECT count (*) FROM users"
                 " WHERE name = '%s' AND method = '%s';",
                 quoted_name,
                 quoted_method);
  g_free (quoted_name);
  g_free (quoted_method);

  return ret;
}

/**
 * @brief Check if user exists.
 *
 * @param[in]  name    User name.
 *
 * @return 1 yes, 0 no.
 */
int
user_exists (const gchar *name)
{
  if (ldap_auth_enabled ()
      && user_exists_method (name, AUTHENTICATION_METHOD_LDAP_CONNECT))
    return 1;
  if (radius_auth_enabled ()
      && user_exists_method (name, AUTHENTICATION_METHOD_RADIUS_CONNECT))
    return 1;
  return user_exists_method (name, AUTHENTICATION_METHOD_FILE);
}

/**
 * @brief Get user uuid.
 *
 * @param[in]  username  User name.
 * @param[in]  method    Authentication method.
 *
 * @return UUID.
 */
static gchar *
user_uuid_method (const gchar *username, auth_method_t method)
{
  gchar *uuid, *quoted_username, *quoted_method;
  quoted_username = sql_quote (username);
  quoted_method = sql_quote (auth_method_name (method));
  uuid = sql_string ("SELECT uuid FROM users"
                     " WHERE name = '%s' AND method = '%s';",
                     quoted_username,
                     quoted_method);
  g_free (quoted_username);
  g_free (quoted_method);
  return uuid;
}

/**
 * @brief Get user uuid, trying all authentication methods.
 *
 * @param[in]  name    User name.
 *
 * @return UUID.
 */
gchar *
user_uuid_any_method (const gchar *name)
{
  if (ldap_auth_enabled ()
      && user_exists_method (name, AUTHENTICATION_METHOD_LDAP_CONNECT))
    return user_uuid_method (name, AUTHENTICATION_METHOD_LDAP_CONNECT);
  if (radius_auth_enabled ()
      && user_exists_method (name, AUTHENTICATION_METHOD_RADIUS_CONNECT))
    return user_uuid_method (name, AUTHENTICATION_METHOD_RADIUS_CONNECT);
  if (user_exists_method (name, AUTHENTICATION_METHOD_FILE))
    return user_uuid_method (name, AUTHENTICATION_METHOD_FILE);
  return NULL;
}

/**
 * @brief Add users to a group or role.
 *
 * Caller must take care of transaction.
 *
 * @param[in]  type      Type.
 * @param[in]  resource  Group or role.
 * @param[in]  users     List of users.
 *
 * @return 0 success, 2 failed to find user, 4 user name validation failed,
 *         99 permission denied, -1 error.
 */
int
add_users (const gchar *type, resource_t resource, const char *users)
{
  if (users)
    {
      gchar **split, **point;
      GList *added;

      /* Add each user. */

      added = NULL;
      split = g_strsplit_set (users, " ,", 0);
      point = split;

      while (*point)
        {
          user_t user;
          gchar *name;

          name = *point;

          g_strstrip (name);

          if (strcmp (name, "") == 0)
            {
              point++;
              continue;
            }

          if (g_list_find_custom (added, name, (GCompareFunc) strcmp))
            {
              point++;
              continue;
            }

          added = g_list_prepend (added, name);

          if (user_exists (name) == 0)
            {
              g_list_free (added);
              g_strfreev (split);
              return 2;
            }

          if (find_user_by_name (name, &user))
            {
              g_list_free (added);
              g_strfreev (split);
              return -1;
            }

          if (user == 0)
            {
              gchar *uuid;

              if (validate_username (name))
                {
                  g_list_free (added);
                  g_strfreev (split);
                  return 4;
                }

              uuid = user_uuid_any_method (name);

              if (uuid == NULL)
                {
                  g_list_free (added);
                  g_strfreev (split);
                  return -1;
                }

              if (sql_int ("SELECT count(*) FROM users WHERE uuid = '%s';",
                           uuid)
                  == 0)
                {
                  gchar *quoted_name;
                  quoted_name = sql_quote (name);
                  sql ("INSERT INTO users"
                       " (uuid, name, creation_time, modification_time)"
                       " VALUES"
                       " ('%s', '%s', m_now (), m_now ());",
                       uuid,
                       quoted_name);
                  g_free (quoted_name);

                  user = sql_last_insert_id ();
                }
              else
                {
                  /* find_user_by_name should have found it. */
                  assert (0);
                  g_free (uuid);
                  g_list_free (added);
                  g_strfreev (split);
                  return -1;
                }

              g_free (uuid);
            }

          if (find_user_by_name_with_permission (name, &user, "get_users"))
            {
              g_list_free (added);
              g_strfreev (split);
              return -1;
            }

          if (user == 0)
            {
              g_list_free (added);
              g_strfreev (split);
              return 99;
            }

          sql ("INSERT INTO %s_users (\"%s\", \"user\") VALUES (%llu, %llu);",
               type,
               type,
               resource,
               user);

          point++;
        }

      g_list_free (added);
      g_strfreev (split);
    }

  return 0;
}

/**
 * @brief Adds a new user to the GVM installation.
 *
 * @todo Adding users authenticating with certificates is not yet implemented.
 *
 * @param[in]  name         The name of the new user.
 * @param[in]  password     The password of the new user.
 * @param[in]  comment      Comment for the new user or NULL.
 * @param[in]  hosts        The host the user is allowed/forbidden to scan.
 * @param[in]  hosts_allow  Whether hosts is allow or forbid.
 * @param[in]  allowed_methods  Allowed login methods.
 * @param[in]  groups       Groups.
 * @param[out] group_id_return  ID of group on "failed to find" error.
 * @param[in]  roles        Roles.
 * @param[out] role_id_return  ID of role on "failed to find" error.
 * @param[out] r_errdesc    If not NULL the address of a variable to receive
 *                          a malloced string with the error description.  Will
 *                          always be set to NULL on success.
 * @param[out] new_user     Created user.
 * @param[in]  forbid_super_admin  Whether to forbid creation of Super Admin.
 *
 * @return 0 if the user has been added successfully, 1 failed to find group,
 *         2 failed to find role, 3 syntax error in hosts, 99 permission denied,
 *         -1 on error, -2 if user exists already, -3 if wrong number of methods,
 *         -4 error in method.
 */
int
create_user (const gchar * name, const gchar * password, const gchar *comment,
             const gchar * hosts, int hosts_allow,
             const array_t * allowed_methods, array_t *groups,
             gchar **group_id_return, array_t *roles, gchar **role_id_return,
             gchar **r_errdesc, user_t *new_user, int forbid_super_admin)
{
  char *errstr, *uuid;
  gchar *quoted_hosts, *quoted_method, *quoted_name, *hash;
  gchar *quoted_comment, *clean, *generated;
  int index, max, ret;
  user_t user;
  GArray *cache_users;

  assert (name);
  assert (password);

  if (r_errdesc)
    *r_errdesc = NULL;

  /* allowed_methods is a NULL terminated array. */
  if (allowed_methods && (allowed_methods->len > 2))
    return -3;

  if (allowed_methods && (allowed_methods->len <= 1))
    allowed_methods = NULL;

  if (allowed_methods
      && (auth_method_name_valid (g_ptr_array_index (allowed_methods, 0))
          == 0))
    return -4;

  if (validate_username (name) != 0)
    {
      g_warning ("Invalid characters in user name!");
      if (r_errdesc)
        *r_errdesc = g_strdup ("Invalid characters in user name");
      return -1;
    }

  if (allowed_methods &&
      (!strcmp (g_ptr_array_index (allowed_methods, 0), "ldap_connect")
       || !strcmp (g_ptr_array_index (allowed_methods, 0), "radius_connect")))
    password = generated = gvm_uuid_make ();
  else
    generated = NULL;

  if ((errstr = gvm_validate_password (password, name)))
    {
      g_warning ("new password for '%s' rejected: %s", name, errstr);
      if (r_errdesc)
        *r_errdesc = errstr;
      else
        g_free (errstr);
      g_free (generated);
      return -1;
    }

  sql_begin_immediate ();

  if (acl_user_may ("create_user") == 0)
    {
      sql_rollback ();
      g_free (generated);
      return 99;
    }

  /* Check if user exists already. */

  if (resource_with_name_exists_global (name, "user", 0))
    {
      sql_rollback ();
      g_free (generated);
      return -2;
    }
  quoted_name = sql_quote (name);

  /* Check hosts. */

  max = manage_max_hosts ();
  manage_set_max_hosts (MANAGE_USER_MAX_HOSTS);
  if (hosts && (manage_count_hosts (hosts, NULL) < 0))
    {
      manage_set_max_hosts (max);
      sql_rollback ();
      g_free (generated);
      return 3;
    }
  manage_set_max_hosts (max);

  /* Get the password hashes. */

  hash = manage_authentication_hash (password);

  /* Get the quoted comment */

  if (comment)
    quoted_comment = sql_quote (comment);
  else
    quoted_comment = g_strdup ("");

  /* Add the user to the database. */

  clean = clean_hosts (hosts ? hosts : "", &max);
  quoted_hosts = sql_quote (clean);
  g_free (clean);
  quoted_method = sql_quote (allowed_methods
                              ? g_ptr_array_index (allowed_methods, 0)
                              : "file");

  ret
    = sql_error ("INSERT INTO users"
                 " (uuid, owner, name, password, comment, hosts, hosts_allow,"
                 "  method, creation_time, modification_time)"
                 " VALUES"
                 " (make_uuid (),"
                 "  (SELECT id FROM users WHERE uuid = '%s'),"
                 "  '%s', '%s', '%s', '%s', %i,"
                 "  '%s', m_now (), m_now ());",
                 current_credentials.uuid,
                 quoted_name,
                 hash,
                 quoted_comment,
                 quoted_hosts,
                 hosts_allow,
                 quoted_method);
  g_free (generated);
  g_free (hash);
  g_free (quoted_comment);
  g_free (quoted_hosts);
  g_free (quoted_method);
  g_free (quoted_name);

  if (ret == 3)
    {
      sql_rollback ();
      return -2;
    }
  else if (ret)
    {
      sql_rollback ();
      return -1;
    }

  user = sql_last_insert_id ();

  /* Add the user to any given groups. */

  index = 0;
  while (groups && (index < groups->len))
    {
      gchar *group_id;
      group_t group;

      group_id = (gchar*) g_ptr_array_index (groups, index);
      if (strcmp (group_id, "0") == 0)
        {
          index++;
          continue;
        }

      if (find_group_with_permission (group_id, &group, "modify_group"))
        {
          sql_rollback ();
          return -1;
        }

      if (group == 0)
        {
          sql_rollback ();
          if (group_id_return) *group_id_return = group_id;
          return 1;
        }

      sql ("INSERT INTO group_users (\"group\", \"user\") VALUES (%llu, %llu);",
           group,
           user);

      index++;
    }

  /* Add the user to any given roles. */

  index = 0;
  while (roles && (index < roles->len))
    {
      gchar *role_id;
      role_t role;

      role_id = (gchar*) g_ptr_array_index (roles, index);
      if (strcmp (role_id, "0") == 0)
        {
          index++;
          continue;
        }

      if (forbid_super_admin && acl_role_can_super_everyone (role_id))
        {
          sql_rollback ();
          return 99;
        }

      if (find_role_with_permission (role_id, &role, "get_roles"))
        {
          sql_rollback ();
          return -1;
        }

      if (role == 0)
        {
          sql_rollback ();
          if (role_id_return) *role_id_return = role_id;
          return 2;
        }

      sql ("INSERT INTO role_users (role, \"user\") VALUES (%llu, %llu);",
           role,
           user);

      index++;
    }

  if (new_user)
    *new_user = user;

  /* Ensure the user can see themself. */

  uuid = user_uuid (user);
  if (uuid == NULL)
    {
      g_warning ("%s: Failed to allocate UUID", __func__);
      sql_rollback ();
      return -1;
    }

  create_permission_internal (1,
                              "GET_USERS",
                              "Automatically created when adding user",
                              NULL,
                              uuid,
                              "user",
                              uuid,
                              NULL);

  free (uuid);

  /* Cache permissions. */

  cache_users = g_array_new (TRUE, TRUE, sizeof (user_t));
  g_array_append_val (cache_users, user);
  cache_all_permissions_for_users (cache_users);
  g_free (g_array_free (cache_users, TRUE));

  sql_commit ();
  return 0;
}

/**
 * @brief Check if a user still has resources that are in use.
 *
 * @param[in] user          The user to check.
 * @param[in] table         The table to check for resources in use.
 * @param[in] in_use        Function to check if a resource is in use.
 * @param[in] trash_table   The trash table to check for resources in use.
 * @param[in] trash_in_use  Function to check if a trash resource is in use.
 *
 * @return 0 no resources in use, 1 found resources used by user.
 */
static int
user_resources_in_use (user_t user,
                       const char *table, int(*in_use)(resource_t),
                       const char *trash_table, int(*trash_in_use)(resource_t))
{
  iterator_t iter;
  int has_resource_in_use = 0;

  init_iterator (&iter, "SELECT id FROM %s WHERE owner = %llu",
                 table, user);
  while (next (&iter) && has_resource_in_use == 0)
    {
      resource_t resource = iterator_int64 (&iter, 0);
      has_resource_in_use = in_use (resource);
    }
  cleanup_iterator (&iter);
  if (has_resource_in_use)
    return 1;

  if (trash_table == NULL || trash_in_use == NULL)
    return 0;

  init_iterator (&iter, "SELECT id FROM %s WHERE owner = %llu",
                 trash_table, user);
  while (next (&iter) && has_resource_in_use == 0)
    {
      resource_t resource = iterator_int64 (&iter, 0);
      has_resource_in_use = trash_in_use (resource);
    }
  cleanup_iterator (&iter);
  if (has_resource_in_use)
    return 2;

  return 0;
}

/**
 * @brief Delete a user.
 *
 * @param[in]  user_id_arg  UUID of user.
 * @param[in]  name_arg     Name of user.  Overridden by user_id.
 * @param[in]  forbid_super_admin  Whether to forbid removal of Super Admin.
 * @param[in]  inheritor_id   UUID of user who will inherit owned objects.
 * @param[in]  inheritor_name Name of user who will inherit owned objects.
 *
 * @return 0 success, 2 failed to find user, 4 user has active tasks,
 *         5 attempted suicide, 6 inheritor not found, 7 inheritor same as
 *         deleted user, 8 invalid inheritor, 9 resources still in use,
 *         10 user is 'Feed Import Owner' 99 permission denied, -1 error.
 */
int
delete_user (const char *user_id_arg, const char *name_arg,
             int forbid_super_admin,
             const char* inheritor_id, const char *inheritor_name)
{
  iterator_t tasks;
  user_t user, inheritor;
  get_data_t get;
  char *current_uuid, *feed_owner_id;
  gboolean has_rows;
  iterator_t rows;
  gchar *deleted_user_id;

  assert (user_id_arg || name_arg);

  if (current_credentials.username && current_credentials.uuid)
    {
      if (user_id_arg)
        {
          if (strcmp (user_id_arg, current_credentials.uuid) == 0)
            return 5;
        }
      else if (name_arg
               && (strcmp (name_arg, current_credentials.username) == 0))
        return 5;
    }

  sql_begin_immediate ();

  if (acl_user_may ("delete_user") == 0)
    {
      sql_rollback ();
      return 99;
    }

  user = 0;
  if (user_id_arg)
    {
      if (forbid_super_admin
          && (strcmp (user_id_arg, ROLE_UUID_SUPER_ADMIN) == 0))
        {
          sql_rollback ();
          return 99;
        }

      if (find_user_with_permission (user_id_arg, &user, "delete_user"))
        {
          sql_rollback ();
          return -1;
        }
    }
  else if (find_user_by_name_with_permission (name_arg, &user, "delete_user"))
    {
      sql_rollback ();
      return -1;
    }

  if (user == 0)
    return 2;

  setting_value (SETTING_UUID_FEED_IMPORT_OWNER, &feed_owner_id);
  if (feed_owner_id)
    {
      char *uuid;

      uuid = user_uuid (user);
      if (strcmp (uuid, feed_owner_id) == 0)
        {
          free (uuid);
          free (feed_owner_id);
          sql_rollback ();
          return 10;
        }
      free (feed_owner_id);
      free (uuid);
    }

  if (forbid_super_admin)
    {
      char *uuid;

      uuid = user_uuid (user);
      if (acl_user_is_super_admin (uuid))
        {
          free (uuid);
          sql_rollback ();
          return 99;
        }
      free (uuid);
    }

  /* Fail if there are any active tasks. */

  memset (&get, '\0', sizeof (get));
  current_uuid = current_credentials.uuid;
  current_credentials.uuid = sql_string ("SELECT uuid FROM users"
                                         " WHERE id = %llu;",
                                         user);
  init_user_task_iterator (&tasks, 0, 1);
  while (next (&tasks))
    switch (task_iterator_run_status (&tasks))
      {
        case TASK_STATUS_DELETE_REQUESTED:
        case TASK_STATUS_DELETE_ULTIMATE_REQUESTED:
        case TASK_STATUS_DELETE_ULTIMATE_WAITING:
        case TASK_STATUS_DELETE_WAITING:
        case TASK_STATUS_REQUESTED:
        case TASK_STATUS_RUNNING:
        case TASK_STATUS_QUEUED:
        case TASK_STATUS_STOP_REQUESTED:
        case TASK_STATUS_STOP_WAITING:
        case TASK_STATUS_PROCESSING:
          {
            cleanup_iterator (&tasks);
            free (current_credentials.uuid);
            current_credentials.uuid = current_uuid;
            sql_rollback ();
            return 4;
          }
        default:
          break;
      }
  cleanup_iterator (&tasks);
  free (current_credentials.uuid);
  current_credentials.uuid = current_uuid;

  /* Check if there's an inheritor. */

  if (inheritor_id && strcmp (inheritor_id, ""))
    {
      if (strcmp (inheritor_id, "self") == 0)
        {
          sql_int64 (&inheritor, "SELECT id FROM users WHERE uuid = '%s'",
                     current_credentials.uuid);

          if (inheritor == 0)
            {
              sql_rollback ();
              return -1;
            }
        }
      else
        {
          if (find_user_with_permission (inheritor_id, &inheritor, "get_users"))
            {
              sql_rollback ();
              return -1;
            }

          if (inheritor == 0)
            {
              sql_rollback ();
              return 6;
            }
        }
    }
  else if (inheritor_name && strcmp (inheritor_name, ""))
    {
      if (find_user_by_name_with_permission (inheritor_name, &inheritor,
                                             "get_users"))
        {
          sql_rollback ();
          return -1;
        }

      if (inheritor == 0)
        {
          sql_rollback ();
          return 6;
        }
    }
  else
    inheritor = 0;

  if (inheritor)
    {
      gchar *deleted_user_name;
      gchar *real_inheritor_id, *real_inheritor_name;

      /* Transfer ownership of objects to the inheritor. */

      if (inheritor == user)
        {
          sql_rollback ();
          return 7;
        }

      real_inheritor_id = user_uuid (inheritor);

      /* Only the current user, owned users or global users may inherit. */
      if (current_credentials.uuid
          && strcmp (current_credentials.uuid, "")
          && strcmp (real_inheritor_id, current_credentials.uuid)
          && sql_int ("SELECT NOT (" ACL_IS_GLOBAL () ")"
                      " FROM users WHERE id = %llu",
                      inheritor)
          && ! acl_user_owns ("user", inheritor, 0)
          && sql_int ("SELECT owner != 0 FROM users WHERE id = %llu",
                      inheritor))
        {
          g_free (real_inheritor_id);
          sql_rollback ();
          return 8;
        }

      deleted_user_id = user_uuid (user);
      deleted_user_name = user_name (deleted_user_id);
      real_inheritor_name = user_name (real_inheritor_id);

      g_log ("event user", G_LOG_LEVEL_MESSAGE,
             "User %s (%s) is inheriting from %s (%s)",
             real_inheritor_name, real_inheritor_id,
             deleted_user_name, deleted_user_id);

      g_free (deleted_user_name);
      g_free (real_inheritor_id);
      g_free (real_inheritor_name);

      /* Transfer owned resources. */

      sql ("UPDATE alerts SET owner = %llu WHERE owner = %llu;",
           inheritor, user);
      sql ("UPDATE alerts_trash SET owner = %llu WHERE owner = %llu;",
           inheritor, user);
      sql ("UPDATE configs SET owner = %llu WHERE owner = %llu;",
           inheritor, user);
      sql ("UPDATE configs_trash SET owner = %llu WHERE owner = %llu;",
           inheritor, user);
      sql ("UPDATE credentials SET owner = %llu WHERE owner = %llu;",
           inheritor, user);
      sql ("UPDATE credentials_trash SET owner = %llu WHERE owner = %llu;",
           inheritor, user);
      sql ("UPDATE host_identifiers SET owner = %llu WHERE owner = %llu;",
           inheritor, user);
      sql ("UPDATE host_oss SET owner = %llu WHERE owner = %llu;",
           inheritor, user);
      sql ("UPDATE hosts SET owner = %llu WHERE owner = %llu;",
           inheritor, user);
      sql ("UPDATE filters SET owner = %llu WHERE owner = %llu;",
           inheritor, user);
      sql ("UPDATE filters_trash SET owner = %llu WHERE owner = %llu;",
           inheritor, user);
      sql ("UPDATE notes SET owner = %llu WHERE owner = %llu;",
           inheritor, user);
      sql ("UPDATE notes_trash SET owner = %llu WHERE owner = %llu;",
           inheritor, user);
      sql ("UPDATE oss SET owner = %llu WHERE owner = %llu;",
           inheritor, user);
      sql ("UPDATE permissions SET owner = %llu WHERE owner = %llu",
           inheritor, user);

      inherit_port_lists (user, inheritor);

      sql ("UPDATE reports SET owner = %llu WHERE owner = %llu;",
           inheritor, user);
      sql ("UPDATE report_counts SET \"user\" = %llu WHERE \"user\" = %llu",
           inheritor, user);
      sql ("UPDATE reports SET owner = %llu WHERE owner = %llu;",
           inheritor, user);
      sql ("UPDATE results SET owner = %llu WHERE owner = %llu;",
           inheritor, user);
      sql ("UPDATE results_trash SET owner = %llu WHERE owner = %llu;",
           inheritor, user);

      sql ("UPDATE overrides SET owner = %llu WHERE owner = %llu;",
           inheritor, user);
      sql ("UPDATE overrides_trash SET owner = %llu WHERE owner = %llu;",
           inheritor, user);
      sql ("UPDATE permissions SET owner = %llu WHERE owner = %llu;",
           inheritor, user);
      sql ("UPDATE permissions_trash SET owner = %llu WHERE owner = %llu;",
           inheritor, user);
      sql ("UPDATE scanners SET owner = %llu WHERE owner = %llu;",
           inheritor, user);
      sql ("UPDATE scanners_trash SET owner = %llu WHERE owner = %llu;",
           inheritor, user);
      sql ("UPDATE schedules SET owner = %llu WHERE owner = %llu;",
           inheritor, user);
      sql ("UPDATE schedules_trash SET owner = %llu WHERE owner = %llu;",
           inheritor, user);
      sql ("DELETE FROM tag_resources"
           " WHERE resource_type = 'user' AND resource = %llu;",
           user);
      sql ("UPDATE tags SET owner = %llu WHERE owner = %llu;",
           inheritor, user);
      sql ("DELETE FROM tag_resources_trash"
           " WHERE resource_type = 'user' AND resource = %llu;",
           user);
      sql ("UPDATE tags_trash SET owner = %llu WHERE owner = %llu;",
           inheritor, user);
      sql ("UPDATE targets SET owner = %llu WHERE owner = %llu;",
           inheritor, user);
      sql ("UPDATE targets_trash SET owner = %llu WHERE owner = %llu;",
           inheritor, user);

      sql ("UPDATE tasks SET owner = %llu WHERE owner = %llu;",
           inheritor, user);

      inherit_tickets (user, inheritor);
      inherit_tls_certificates (user, inheritor);

      sql ("UPDATE groups SET owner = %llu WHERE owner = %llu;",
           inheritor, user);
      sql ("UPDATE roles SET owner = %llu WHERE owner = %llu;",
           inheritor, user);
      sql ("UPDATE users SET owner = %llu WHERE owner = %llu;",
           inheritor, user);
      sql ("UPDATE groups_trash SET owner = %llu WHERE owner = %llu;",
           inheritor, user);
      sql ("UPDATE roles_trash SET owner = %llu WHERE owner = %llu;",
           inheritor, user);

      sql ("UPDATE report_configs SET owner = %llu WHERE owner = %llu;",
           inheritor, user);
      sql ("UPDATE report_configs_trash SET owner = %llu WHERE owner = %llu;",
           inheritor, user);

      /* Report Formats. */

      has_rows = inherit_report_formats (user, inheritor, &rows);

      /* Delete user. */

      sql ("DELETE FROM group_users WHERE \"user\" = %llu;", user);
      sql ("DELETE FROM group_users_trash WHERE \"user\" = %llu;", user);
      sql ("DELETE FROM role_users WHERE \"user\" = %llu;", user);
      sql ("DELETE FROM role_users_trash WHERE \"user\" = %llu;", user);

      delete_permissions_cache_for_user (user);

      sql ("DELETE FROM settings WHERE owner = %llu;", user);
      sql ("DELETE FROM users WHERE id = %llu;", user);

      /* Very last: report formats dirs. */

      if (deleted_user_id == NULL)
        g_warning ("%s: deleted_user_id NULL, skipping dirs", __func__);
      else if (has_rows)
        do
        {
          inherit_report_format_dir (iterator_string (&rows, 0),
                                     deleted_user_id,
                                     inheritor);
        } while (next (&rows));

      g_free (deleted_user_id);
      cleanup_iterator (&rows);

      sql_commit ();

      return 0;
    }

  /* Delete settings and miscellaneous resources not referenced directly. */

  /* Settings. */
  sql ("DELETE FROM settings WHERE owner = %llu;", user);

  /* Delete data modifiers (not directly referenced) */

  /* Notes. */
  sql ("DELETE FROM notes WHERE owner = %llu;", user);
  sql ("DELETE FROM notes_trash WHERE owner = %llu;", user);

  /* Overrides. */
  sql ("DELETE FROM overrides WHERE owner = %llu;", user);
  sql ("DELETE FROM overrides_trash WHERE owner = %llu;", user);

  /* Tags. */
  sql ("DELETE FROM tag_resources"
       " WHERE resource_type = 'user' AND resource = %llu;",
       user);
  sql ("DELETE FROM tag_resources"
       " WHERE tag IN (SELECT id FROM tags WHERE owner = %llu);",
       user);
  sql ("DELETE FROM tags WHERE owner = %llu;", user);
  sql ("DELETE FROM tag_resources_trash"
       " WHERE resource_type = 'user' AND resource = %llu;",
       user);
  sql ("DELETE FROM tag_resources_trash"
       " WHERE tag IN (SELECT id FROM tags_trash WHERE owner = %llu);",
       user);
  sql ("DELETE FROM tags_trash WHERE owner = %llu;", user);

  delete_tickets_user (user);

  delete_tls_certificates_user (user);

  /* Delete assets (not directly referenced). */

  /* Hosts. */
  sql ("DELETE FROM host_details WHERE host IN"
       " (SELECT id FROM hosts WHERE owner = %llu);", user);
  sql ("DELETE FROM host_max_severities WHERE host IN"
       " (SELECT id FROM hosts WHERE owner = %llu);", user);
  sql ("DELETE FROM host_identifiers WHERE owner = %llu;", user);
  sql ("DELETE FROM host_oss WHERE owner = %llu;", user);
  sql ("DELETE FROM hosts WHERE owner = %llu;", user);

  /* OSs. */
  sql ("DELETE FROM oss WHERE owner = %llu;", user);

  /* Delete report data and tasks (not directly referenced). */

  /* Counts. */
  sql ("DELETE FROM report_counts WHERE \"user\" = %llu", user);
  sql ("DELETE FROM report_counts"
       " WHERE report IN (SELECT id FROM reports WHERE owner = %llu);",
       user);

  /* Hosts. */
  sql ("DELETE FROM report_host_details"
       " WHERE report_host IN (SELECT id FROM report_hosts"
       "                       WHERE report IN (SELECT id FROM reports"
       "                                        WHERE owner = %llu));",
       user);
  sql ("DELETE FROM report_hosts"
       " WHERE report IN (SELECT id FROM reports WHERE owner = %llu);",
       user);

  /* Results. */
  sql ("DELETE FROM results"
       " WHERE report IN (SELECT id FROM reports WHERE owner = %llu);",
       user);
  sql ("DELETE FROM results_trash"
       " WHERE report IN (SELECT id FROM reports WHERE owner = %llu);",
       user);

  /* Reports. */
  sql ("DELETE FROM result_nvt_reports"
       " WHERE report IN (SELECT id FROM reports WHERE owner = %llu);",
       user);
  sql ("DELETE FROM reports WHERE owner = %llu;", user);

  /* Delete tasks (not directly referenced). */

  if (user_resources_in_use (user,
                             "tasks", target_in_use,
                             NULL, NULL))
    {
      sql_rollback ();
      return 9;
    }
  tickets_remove_tasks_user (user);
  sql ("DELETE FROM task_alerts"
       " WHERE task IN (SELECT id FROM tasks WHERE owner = %llu);",
       user);
  sql ("DELETE FROM task_files"
       " WHERE task IN (SELECT id FROM tasks WHERE owner = %llu);",
       user);
  sql ("DELETE FROM task_preferences"
       " WHERE task IN (SELECT id FROM tasks WHERE owner = %llu);",
       user);
  sql ("DELETE FROM tasks WHERE owner = %llu;", user);

  /* Delete resources directly used by tasks. */

  /* Alerts. */
  if (user_resources_in_use (user,
                             "alerts", alert_in_use,
                             "alerts_trash", trash_alert_in_use))
    {
      sql_rollback ();
      return 9;
    }
  sql ("DELETE FROM alert_condition_data"
       " WHERE alert IN (SELECT id FROM alerts WHERE owner = %llu);",
       user);
  sql ("DELETE FROM alert_condition_data_trash"
       " WHERE alert IN (SELECT id FROM alerts_trash WHERE owner = %llu);",
       user);
  sql ("DELETE FROM alert_event_data"
       " WHERE alert IN (SELECT id FROM alerts WHERE owner = %llu);",
       user);
  sql ("DELETE FROM alert_event_data_trash"
       " WHERE alert IN (SELECT id FROM alerts_trash WHERE owner = %llu);",
       user);
  sql ("DELETE FROM alert_method_data"
       " WHERE alert IN (SELECT id FROM alerts WHERE owner = %llu);",
       user);
  sql ("DELETE FROM alert_method_data_trash"
       " WHERE alert IN (SELECT id FROM alerts_trash WHERE owner = %llu);",
       user);
  sql ("DELETE FROM alerts WHERE owner = %llu;", user);
  sql ("DELETE FROM alerts_trash WHERE owner = %llu;", user);

  /* Configs. */
  if (user_resources_in_use (user,
                             "configs", config_in_use,
                             "configs_trash", trash_config_in_use))
    {
      sql_rollback ();
      return 9;
    }
  sql ("DELETE FROM nvt_selectors"
       " WHERE name IN (SELECT nvt_selector FROM configs WHERE owner = %llu)"
       " AND name != '" MANAGE_NVT_SELECTOR_UUID_ALL "';",
       user);
  sql ("DELETE FROM config_preferences"
       " WHERE config IN (SELECT id FROM configs WHERE owner = %llu);",
       user);
  sql ("DELETE FROM config_preferences_trash"
       " WHERE config IN (SELECT id FROM configs_trash WHERE owner = %llu);",
       user);
  sql ("DELETE FROM configs WHERE owner = %llu;", user);
  sql ("DELETE FROM configs_trash WHERE owner = %llu;", user);

  /* Scanners. */
  if (user_resources_in_use (user,
                             "scanners", scanner_in_use,
                             "scanners_trash", trash_scanner_in_use))
    {
      sql_rollback ();
      return 9;
    }
  sql ("DELETE FROM scanners WHERE owner = %llu;", user);
  sql ("DELETE FROM scanners_trash WHERE owner = %llu;", user);

  /* Schedules. */
  if (user_resources_in_use (user,
                             "schedules", schedule_in_use,
                             "schedules_trash", trash_schedule_in_use))
    {
      sql_rollback ();
      return 9;
    }
  sql ("DELETE FROM schedules WHERE owner = %llu;", user);
  sql ("DELETE FROM schedules_trash WHERE owner = %llu;", user);

  /* Targets. */
  if (user_resources_in_use (user,
                             "targets", target_in_use,
                             "targets_trash", trash_target_in_use))
    {
      sql_rollback ();
      return 9;
    }
  sql ("DELETE FROM targets_login_data WHERE target IN"
       " (SELECT id FROM targets WHERE owner = %llu);", user);
  sql ("DELETE FROM targets_trash_login_data WHERE target IN"
       " (SELECT id FROM targets_trash WHERE owner = %llu);", user);
  sql ("DELETE FROM targets WHERE owner = %llu;", user);
  sql ("DELETE FROM targets_trash WHERE owner = %llu;", user);

#if ENABLE_CONTAINER_SCANNING
  /* OCI Image Targets. */
  if (user_resources_in_use (user,
                             "oci_image_targets",
                             oci_image_target_in_use,
                             "oci_image_targets_trash",
                             trash_oci_image_target_in_use))
    {
      sql_rollback ();
      return 9;
    }
  sql ("DELETE FROM oci_image_targets WHERE owner = %llu;", user);
  sql ("DELETE FROM oci_image_targets_trash WHERE owner = %llu;", user);
#endif /* ENABLE_CONTAINER_SCANNING */

  /* Delete resources used indirectly by tasks */

  /* Filters (used by alerts and settings). */
  if (user_resources_in_use (user,
                             "filters", filter_in_use,
                             "filters_trash", trash_filter_in_use))
    {
      sql_rollback ();
      return 9;
    }
  sql ("DELETE FROM filters WHERE owner = %llu;", user);
  sql ("DELETE FROM filters_trash WHERE owner = %llu;", user);

  /* Port lists (used by targets). */
  if (user_resources_in_use (user,
                             "port_lists", port_list_in_use,
                             "port_lists_trash", trash_port_list_in_use))
    {
      sql_rollback ();
      return 9;
    }
  delete_port_lists_user (user);

  /* Check credentials before deleting report formats, because we can't
   * rollback the deletion of the report format dirs. */
  if (user_resources_in_use (user,
                             "credentials", credential_in_use,
                             "credentials_trash", trash_credential_in_use))
    {
      sql_rollback ();
      return 9;
    }

  /* Check report formats (used by alerts). */
  if (user_resources_in_use (user,
                             "report_formats",
                             report_format_in_use,
                             "report_formats_trash",
                             trash_report_format_in_use))
    {
      sql_rollback ();
      return 9;
    }

  /* Delete credentials last because they can be used in various places */

  sql ("DELETE FROM credentials_data WHERE credential IN"
       " (SELECT id FROM credentials WHERE owner = %llu);",
       user);
  sql ("DELETE FROM credentials_trash_data WHERE credential IN"
       " (SELECT id FROM credentials_trash WHERE owner = %llu);",
       user);

  sql ("DELETE FROM credentials WHERE owner = %llu;", user);
  sql ("DELETE FROM credentials_trash WHERE owner = %llu;", user);

  /* Make permissions global if they are owned by the user and are related
   * to users/groups/roles that are owned by the user. */

  sql ("UPDATE permissions SET owner = NULL"
       " WHERE owner = %llu"
       " AND ((subject_type = 'user' AND subject IN (SELECT id FROM users WHERE owner = %llu))"
       "      OR (subject_type = 'group' AND subject IN (SELECT id FROM groups WHERE owner = %llu))"
       "      OR (subject_type = 'role' AND subject IN (SELECT id FROM roles WHERE owner = %llu))"
       "      OR (resource_type = 'user' AND resource IN (SELECT id FROM users WHERE owner = %llu))"
       "      OR (resource_type = 'group' AND resource IN (SELECT id FROM groups WHERE owner = %llu))"
       "      OR (resource_type = 'role' AND resource IN (SELECT id FROM roles WHERE owner = %llu)));",
       user,
       user,
       user,
       user,
       user,
       user,
       user);

  /* Make users, roles and groups global if they are owned by the user. */

  sql ("UPDATE users SET owner = NULL WHERE owner = %llu;", user);
  sql ("UPDATE roles SET owner = NULL WHERE owner = %llu;", user);
  sql ("UPDATE groups SET owner = NULL WHERE owner = %llu;", user);
  sql ("UPDATE roles_trash SET owner = NULL WHERE owner = %llu;", user);
  sql ("UPDATE groups_trash SET owner = NULL WHERE owner = %llu;", user);

  /* Remove all other permissions owned by the user or given on the user. */

  sql ("DELETE FROM permissions"
       " WHERE owner = %llu"
       " OR subject_type = 'user' AND subject = %llu"
       " OR (resource_type = 'user' AND resource = %llu);",  /* For Super. */
       user,
       user,
       user);
  sql ("DELETE FROM permissions_get_tasks WHERE \"user\" = %llu;", user);

  /* Delete permissions granted by the user. */

  sql ("DELETE FROM permissions WHERE owner = %llu;", user);
  sql ("DELETE FROM permissions_trash WHERE owner = %llu;", user);

  /* Remove user from groups and roles. */

  sql ("DELETE FROM group_users WHERE \"user\" = %llu;", user);
  sql ("DELETE FROM group_users_trash WHERE \"user\" = %llu;", user);
  sql ("DELETE FROM role_users WHERE \"user\" = %llu;", user);
  sql ("DELETE FROM role_users_trash WHERE \"user\" = %llu;", user);

  /* Delete report configs */

  delete_report_configs_user (user);

  /* Delete report formats. */

  has_rows = delete_report_formats_user (user, &rows);

  /* Delete user. */

  deleted_user_id = user_uuid (user);

  sql ("DELETE FROM users WHERE id = %llu;", user);

  /* Delete report format dirs. */

  if (deleted_user_id)
    delete_report_format_dirs_user (deleted_user_id, has_rows ? &rows : NULL);
  else
    g_warning ("%s: deleted_user_id NULL, skipping removal of report formats dir",
               __func__);

  sql_commit ();
  return 0;
}
