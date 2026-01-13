/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_users.h"
#include "manage_sql_users.h"
#include "manage_acl.h"
#include "manage_authentication.h"
#include "manage_sql.h"
#include "manage_sql_groups.h"
#include "manage_sql_roles.h"
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
