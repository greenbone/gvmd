/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_permissions_cache.h"
#include "manage_sql_users.h"
#include "manage.h" // for current_credentials
#include "manage_sql.h"
#include "sql.h"

/**
 * @file
 * @brief GVM management layer: Permissions cache SQL
 *
 * The permissions cache SQL for the GVM management layer.
 */

/**
 * @brief Update permissions cache for a resource.
 *
 * @param[in]  type         Resource type.
 * @param[in]  resource     The resource to update the cache for.
 * @param[in]  cache_users  GArray of users to create cache for or NULL for all.
 */
void
cache_permissions_for_resource (const char *type, resource_t resource,
                                GArray *cache_users)
{
  int free_users;

  if (type == NULL || resource == 0 || resource == -1)
    return;

  if (cache_users == NULL)
    {
      g_debug ("%s: Getting all users", __func__);
      free_users = 1;
      cache_users = all_users_array ();
    }
  else
    free_users = 0;

  if (strcmp (type, "task") == 0)
    {
      char* old_current_user_id;
      gchar *resource_id;
      int user_index;

      old_current_user_id = current_credentials.uuid;
      resource_id = resource_uuid (type, resource);

      g_debug ("%s: Caching permissions on %s \"%s\" for %d user(s)",
               __func__, type, resource_id, cache_users->len);

      for (user_index = 0; user_index < cache_users->len; user_index++)
        {
          user_t user;
          gchar *user_id;

          user = g_array_index (cache_users, user_t, user_index);
          user_id = user_uuid (user);

          current_credentials.uuid = user_id;
          manage_session_init (user_id);

          if (sql_int ("SELECT count(*) FROM permissions_get_%ss"
                       " WHERE \"user\" = %llu"
                       "   AND %s = %llu;",
                       type,
                       user,
                       type,
                       resource))
            {
              sql ("UPDATE permissions_get_%ss"
                   "  SET has_permission"
                   "       = user_has_access_uuid (cast ('%s' as text),"
                   "                               cast ('%s' as text),"
                   "                               cast ('get_%ss' as text),"
                   "                               0)"
                   " WHERE \"user\" = %llu"
                   "   AND %s = %llu;",
                   type,
                   type,
                   resource_id,
                   type,
                   user,
                   type,
                   resource);
            }
          else
            {
              sql ("INSERT INTO permissions_get_%ss"
                   "              (\"user\", %s, has_permission)"
                   "  SELECT %llu, %llu,"
                   "         user_has_access_uuid (cast ('%s' as text),"
                   "                               cast ('%s' as text),"
                   "                               cast ('get_%ss' as text),"
                   "                               0);",
                   type,
                   type,
                   user,
                   resource,
                   type,
                   resource_id,
                   type);
            }

          g_free (user_id);
          current_credentials.uuid = NULL;
        }

      current_credentials.uuid = old_current_user_id;
      manage_session_init (old_current_user_id);

      g_free (resource_id);
    }

  if (free_users)
    g_array_free (cache_users, TRUE);
}

/**
 * @brief Update permissions cache for a given type and selection of users.
 *
 * @param[in]  type         Type.
 * @param[in]  cache_users  GArray of users to create cache for.
 */
static void
cache_permissions_for_users (const char *type, GArray *cache_users)
{
  int free_users;

  if (type == NULL)
    return;

  if (cache_users == NULL)
    {
      g_debug ("%s: Getting all users", __func__);
      free_users = 1;
      cache_users = all_users_array ();
    }
  else
    free_users = 0;

  if (strcmp (type, "task") == 0)
    {
      iterator_t resources;

      init_iterator (&resources, "SELECT id FROM %ss;", type);

      while (next (&resources))
        {
          resource_t resource = iterator_int64 (&resources, 0);
          cache_permissions_for_resource (type, resource, cache_users);
        }

      cleanup_iterator (&resources);
    }

  if (free_users)
    g_array_free (cache_users, TRUE);
}

/**
 * @brief Update entire permission cache the given users.
 *
 * @param[in]  cache_users  GArray of users to create cache for.  NULL means
 *                          all users.
 */
void
cache_all_permissions_for_users (GArray *cache_users)
{
  int free_users;

  if (cache_users == NULL)
    {
      g_debug ("%s: Getting all users", __func__);
      free_users = 1;
      cache_users = all_users_array ();
    }
  else
    free_users = 0;

  cache_permissions_for_users ("task", cache_users);

  if (free_users)
    g_array_free (cache_users, TRUE);
}

/**
 * @brief Delete permission cache a resource.
 *
 * @param[in]  type      Resource type.
 * @param[in]  resource  Resource.
 */
void
delete_permissions_cache_for_resource (const char* type, resource_t resource)
{
  if (type == NULL || resource == 0)
    return;

  if (strcmp (type, "task") == 0)
    {
      sql ("DELETE FROM permissions_get_%ss WHERE \"%s\" = %llu",
           type, type, resource);
    }
}

/**
 * @brief Delete permission cache the given user.
 *
 * @param[in]  user  User.
 */
void
delete_permissions_cache_for_user (user_t user)
{
  sql ("DELETE FROM permissions_get_tasks WHERE \"user\" = %llu;", user);
}
