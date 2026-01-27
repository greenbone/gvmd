/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_permissions.h"
#include "manage_acl.h"
#include "manage_sql_users.h"
#include "sql.h"

/**
 * @file
 * @brief GVM management layer: Permissions SQL
 *
 * The Permissions SQL for the GVM management layer.
 */

/**
 * @brief Adjust location of resource in permissions.
 *
 * @param[in]   type  Type.
 * @param[in]   old   Resource ID in old table.
 * @param[in]   new   Resource ID in new table.
 * @param[in]   to    Destination, trash or table.
 */
void
permissions_set_locations (const char *type, resource_t old, resource_t new,
                           int to)
{
  sql ("UPDATE permissions SET resource_location = %i, resource = %llu"
       " WHERE resource_type = '%s' AND resource = %llu"
       " AND resource_location = %i;",
       to,
       new,
       type,
       old,
       to == LOCATION_TABLE ? LOCATION_TRASH : LOCATION_TABLE);
  sql ("UPDATE permissions_trash SET resource_location = %i, resource = %llu"
       " WHERE resource_type = '%s' AND resource = %llu"
       " AND resource_location = %i;",
       to,
       new,
       type,
       old,
       to == LOCATION_TABLE ? LOCATION_TRASH : LOCATION_TABLE);
}

/**
 * @brief Set permissions to orphan.
 *
 * @param[in]  type      Type.
 * @param[in]  resource  Resource ID.
 * @param[in]  location  Location: table or trash.
 */
void
permissions_set_orphans (const char *type, resource_t resource, int location)
{
  sql ("UPDATE permissions SET resource = -1"
       " WHERE resource_type = '%s' AND resource = %llu"
       " AND resource_location = %i;",
       type,
       resource,
       location);
  sql ("UPDATE permissions_trash SET resource = -1"
       " WHERE resource_type = '%s' AND resource = %llu"
       " AND resource_location = %i;",
       type,
       resource,
       location);
}

/**
 * @brief Adjust subject in permissions.
 *
 * @param[in]   type  Subject type.
 * @param[in]   old   Resource ID in old table.
 * @param[in]   new   Resource ID in new table.
 * @param[in]   to    Destination, trash or table.
 */
void
permissions_set_subjects (const char *type, resource_t old, resource_t new,
                          int to)
{
  assert (type && (strcmp (type, "group") == 0 || strcmp (type, "role") == 0));

  sql ("UPDATE permissions"
       " SET subject_location = %i, subject = %llu"
       " WHERE subject_location = %i"
       " AND subject_type = '%s'"
       " AND subject = %llu;",
       to,
       new,
       to == LOCATION_TRASH ? LOCATION_TABLE : LOCATION_TRASH,
       type,
       old);

  sql ("UPDATE permissions_trash"
       " SET subject_location = %i, subject = %llu"
       " WHERE subject_location = %i"
       " AND subject_type = '%s'"
       " AND subject = %llu;",
       to,
       new,
       to == LOCATION_TRASH ? LOCATION_TABLE : LOCATION_TRASH,
       type,
       old);
}

/**
 * @brief Add role permissions to feed objects according to the
 *        'Feed Import Roles' setting.
 *
 * @param[in]  type             The object type, e.g. report_format.
 * @param[in]  type_cap         Capitalized type, e.g. "Report Format"
 * @param[out] permission_count Number of permissions added.
 * @param[out] object_count     Number of data objects affected.
 */
void
add_feed_role_permissions (const char *type,
                           const char *type_cap,
                           int *permission_count,
                           int *object_count)
{
  char *roles_str;
  gchar **roles;
  iterator_t resources;

  roles_str = NULL;
  setting_value (SETTING_UUID_FEED_IMPORT_ROLES, &roles_str);

  if (roles_str == NULL || strlen (roles_str) == 0)
    {
      g_message ("%s: No feed import roles defined", __func__);
      g_free (roles_str);
      return;
    }

  roles = g_strsplit (roles_str, ",", 0);
  free (roles_str);

  init_iterator (&resources,
                 "SELECT id, uuid, name, owner FROM %ss"
                 " WHERE predefined = 1",
                 type);
  while (next (&resources))
    {
      gboolean added_permission = FALSE;
      resource_t permission_resource = iterator_int64 (&resources, 0);
      const char *permission_resource_id = iterator_string (&resources, 1);
      const char *permission_resource_name = iterator_string (&resources, 2);
      user_t owner = iterator_int64 (&resources, 3);
      gchar **role = roles;

      while (*role)
        {
          char *role_name = NULL;
          manage_resource_name ("role", *role, &role_name);

          if (sql_int ("SELECT count(*) FROM permissions"
                       " WHERE name = 'get_%ss'"
                       "   AND subject_type = 'role'"
                       "   AND subject"
                       "         = (SELECT id FROM roles WHERE uuid='%s')"
                       "   AND resource = %llu",
                       type,
                       *role,
                       permission_resource))
            {
              g_debug ("Role %s (%s) already has read permission"
                       " for %s %s (%s).",
                       role_name,
                       *role,
                       type_cap,
                       permission_resource_name,
                       permission_resource_id);
            }
          else
            {
              gchar *permission_name;

              g_info ("Creating read permission for role %s (%s)"
                      " on %s %s (%s).",
                      role_name,
                      *role,
                      type_cap,
                      permission_resource_name,
                      permission_resource_id);

              added_permission = TRUE;
              if (permission_count)
                *permission_count = *permission_count + 1;

              permission_name = g_strdup_printf ("get_%ss", type);

              current_credentials.uuid = user_uuid (owner);
              switch (create_permission_internal
                       (0,
                        permission_name,
                        "Automatically created by"
                        " --optimize",
                        type,
                        permission_resource_id,
                        "role",
                        *role,
                        NULL))
                {
                  case 0:
                    // success
                    break;
                  case 2:
                    g_warning ("%s: failed to find role %s for permission",
                               __func__, *role);
                    break;
                  case 3:
                    g_warning ("%s: failed to find %s %s for permission",
                               __func__, type_cap, permission_resource_id);
                    break;
                  case 5:
                    g_warning ("%s: error in resource when creating permission"
                               " for %s %s",
                               __func__, type_cap, permission_resource_id);
                    break;
                  case 6:
                    g_warning ("%s: error in subject (Role %s)",
                               __func__, *role);
                    break;
                  case 7:
                    g_warning ("%s: error in name %s",
                               __func__, permission_name);
                    break;
                  case 8:
                    g_warning ("%s: permission on permission", __func__);
                    break;
                  case 9:
                    g_warning ("%s: permission %s does not accept resource",
                               __func__, permission_name);
                    break;
                  case 99:
                    g_warning ("%s: permission denied to create %s permission"
                               " for role %s on %s %s",
                               __func__, permission_name, *role, type_cap,
                               permission_resource_id);
                    break;
                  default:
                    g_warning ("%s: internal error creating %s permission"
                               " for role %s on %s %s",
                               __func__, permission_name, *role, type_cap,
                               permission_resource_id);
                    break;
                }

              free (current_credentials.uuid);
              current_credentials.uuid = NULL;
            }

          free (role_name);
          role ++;
        }
      if (object_count && added_permission)
        *object_count = *object_count + 1;
    }

  cleanup_iterator (&resources);
  g_strfreev (roles);

  return;
}

/**
 * @brief Delete permissions to feed objects for roles that are not set
 *        in the 'Feed Import Roles' setting.
 *
 * @param[in]  type  The object type, e.g. report_format.
 * @param[in]  type_cap         Capitalized type, e.g. "Report Format"
 * @param[out] permission_count Number of permissions added.
 * @param[out] object_count     Number of data objects affected.
 */
void
clean_feed_role_permissions (const char *type,
                             const char *type_cap,
                             int *permission_count,
                             int *object_count)
{
  char *roles_str;
  gchar **roles, **role;
  GString *sql_roles;
  iterator_t resources;

  roles_str = NULL;
  setting_value (SETTING_UUID_FEED_IMPORT_ROLES, &roles_str);

  if (roles_str == NULL || strlen (roles_str) == 0)
    {
      g_message ("%s: No feed import roles defined", __func__);
      g_free (roles_str);
      return;
    }

  sql_roles = g_string_new ("(");

  roles = g_strsplit (roles_str, ",", 0);
  role = roles;
  while (*role)
    {
      gchar *quoted_role = sql_insert (*role);
      g_string_append (sql_roles, quoted_role);

      role ++;
      if (*role)
        g_string_append (sql_roles, ", ");
    }

  g_string_append (sql_roles, ")");
  g_debug ("%s: Keeping permissions for roles %s\n", __func__, sql_roles->str);

  init_iterator (&resources,
                 "SELECT id, uuid, name FROM %ss"
                 " WHERE predefined = 1",
                 type);

  while (next (&resources))
    {
      gboolean removed_permission = FALSE;
      resource_t permission_resource = iterator_int64 (&resources, 0);
      const char *permission_resource_id = iterator_string (&resources, 1);
      const char *permission_resource_name = iterator_string (&resources, 2);
      iterator_t permissions;
      roles = NULL;

      init_iterator (&permissions,
                     "DELETE FROM permissions"
                     " WHERE name = 'get_%ss'"
                     "   AND resource = %llu"
                     "   AND subject_type = 'role'"
                     "   AND subject NOT IN"
                     "     (SELECT id FROM roles WHERE uuid IN %s)"
                     " RETURNING"
                     "   (SELECT uuid FROM roles WHERE id = subject),"
                     "   (SELECT name FROM roles WHERE id = subject)",
                     type,
                     permission_resource,
                     sql_roles->str);

      while (next (&permissions))
        {
          const char *role_id = iterator_string (&permissions, 0);
          const char *role_name = iterator_string (&permissions, 1);
          g_info ("Removed permission on %s %s (%s) for role %s (%s)",
                  type_cap,
                  permission_resource_name,
                  permission_resource_id,
                  role_name,
                  role_id);

          if (permission_count)
            *permission_count = *permission_count + 1;
          removed_permission = TRUE;
        }

      if (object_count && removed_permission)
        *object_count = *object_count + 1;
    }

  cleanup_iterator (&resources);
  g_strfreev (roles);

  return;
}
