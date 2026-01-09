/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_users.h"
#include "manage_sql_users.h"
#include "manage_acl.h"
#include "manage_sql.h"
#include "sql.h"

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
