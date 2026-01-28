/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_permissions.h"
#include "manage_acl.h"
#include "manage_sql_roles.h"
#include "manage_sql_users.h"
#include "sql.h"

/**
 * @file
 * @brief GVM management layer: Permissions SQL
 *
 * The Permissions SQL for the GVM management layer.
 */

/**
 * @brief Return the UUID of a permission.
 *
 * @param[in]  permission  Permission.
 *
 * @return Newly allocated UUID if available, else NULL.
 */
char*
permission_uuid (permission_t permission)
{
  return sql_string ("SELECT uuid FROM permissions WHERE id = %llu;",
                     permission);
}

/**
 * @brief Return the resource of a permission.
 *
 * @param[in]  permission  Permission.
 *
 * @return Resource if there is one, else 0.
 */
resource_t
permission_resource (permission_t permission)
{
  resource_t resource;
  sql_int64 (&resource,
             "SELECT resource FROM permissions WHERE id = %llu;",
             permission);
  return resource;
}

/**
 * @brief Return the name of a permission.
 *
 * @param[in]  permission  Permission.
 *
 * @return Newly allocated name if available, else NULL.
 */
char *
permission_name (permission_t permission)
{
  return sql_string ("SELECT name FROM permissions WHERE id = %llu;",
                     permission);
}

/**
 * @brief Return the subject type of a permission.
 *
 * @param[in]  permission  Permission.
 *
 * @return Newly allocated subject type if available, else NULL.
 */
char *
permission_subject_type (permission_t permission)
{
  return sql_string ("SELECT subject_type FROM permissions WHERE id = %llu;",
                     permission);
}

/**
 * @brief Return the subject of a permission.
 *
 * @param[in]  permission  Permission.
 *
 * @return Subject if there is one, else 0.
 */
resource_t
permission_subject (permission_t permission)
{
  resource_t subject;
  sql_int64 (&subject,
             "SELECT subject FROM permissions WHERE id = %llu;",
             permission);
  return subject;
}

/**
 * @brief Return the UUID of the subject of a permission.
 *
 * @param[in]  permission  Permission.
 *
 * @return Newly allocated subject ID if available, else NULL.
 */
char *
permission_subject_id (permission_t permission)
{
  return sql_string ("SELECT subject_id FROM permissions WHERE id = %llu;",
                     permission);
}

/**
 * @brief Return the resource type of a permission.
 *
 * @param[in]  permission  Permission.
 *
 * @return Newly allocated resource type if available, else NULL.
 */
char *
permission_resource_type (permission_t permission)
{
  return sql_string ("SELECT resource_type FROM permissions WHERE id = %llu;",
                     permission);
}

/**
 * @brief Return the UUID of the resource of a permission.
 *
 * @param[in]  permission  Permission.
 *
 * @return Newly allocated resource ID if available, else NULL.
 */
char *
permission_resource_id (permission_t permission)
{
  return sql_string ("SELECT resource_id FROM permissions WHERE id = %llu;",
                     permission);
}

/**
 * @brief Return whether a permission is predefined.
 *
 * @param[in]  permission  Permission.
 *
 * @return 1 if predefined, else 0.
 */
int
permission_is_predefined (permission_t permission)
{
  return !!sql_int ("SELECT COUNT (*) FROM permissions"
                    " WHERE id = %llu"
                    " AND (uuid = '" PERMISSION_UUID_ADMIN_EVERYTHING "'"
                    "      OR (subject_type = 'role'"
                    "          AND resource = 0"
                    "          AND subject"
                    "              IN (SELECT id FROM roles"
                    "                  WHERE uuid = '" ROLE_UUID_ADMIN "'"
                    "                  OR uuid = '" ROLE_UUID_GUEST "'"
                    "                  OR uuid = '" ROLE_UUID_INFO "'"
                    "                  OR uuid = '" ROLE_UUID_MONITOR "'"
                    "                  OR uuid = '" ROLE_UUID_USER "'"
                    "                  OR uuid = '" ROLE_UUID_SUPER_ADMIN "'"
                    "                  OR uuid = '" ROLE_UUID_OBSERVER "')))",
                    permission);
}

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

/**
 * @brief Count number of permissions.
 *
 * @param[in]  get  GET params.
 *
 * @return Total number of permissions in filtered set.
 */
int
permission_count (const get_data_t *get)
{
  static const char *filter_columns[] = PERMISSION_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = PERMISSION_ITERATOR_COLUMNS;
  static column_t trash_columns[] = PERMISSION_ITERATOR_TRASH_COLUMNS;

  return count ("permission", get, columns, trash_columns, filter_columns,
                0, 0, 0, TRUE);
}

/**
 * @brief Initialise a permission iterator.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  get         GET data.
 *
 * @return 0 success, 1 failed to find target, 2 failed to find filter,
 *         -1 error.
 */
int
init_permission_iterator (iterator_t* iterator, get_data_t *get)
{
  static const char *filter_columns[] = PERMISSION_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = PERMISSION_ITERATOR_COLUMNS;
  static column_t trash_columns[] = PERMISSION_ITERATOR_TRASH_COLUMNS;

  return init_get_iterator (iterator,
                            "permission",
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
 * @brief Get the type of resource from a permission iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Type, or NULL if iteration is complete.
 */
DEF_ACCESS (permission_iterator_resource_type, GET_ITERATOR_COLUMN_COUNT);

/**
 * @brief Get the UUID of the resource from a permission iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return UUID, or NULL if iteration is complete.
 */
DEF_ACCESS (permission_iterator_resource_uuid, GET_ITERATOR_COLUMN_COUNT + 1);

/**
 * @brief Get the name of the resource from a permission iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name, or NULL if iteration is complete.
 */
DEF_ACCESS (permission_iterator_resource_name, GET_ITERATOR_COLUMN_COUNT + 2);

/**
 * @brief Return the permission resource location.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Whether the resource is in the trashcan
 */
int
permission_iterator_resource_in_trash (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return iterator_int64 (iterator, GET_ITERATOR_COLUMN_COUNT + 3);
}

/**
 * @brief Check if the permission resource has been deleted.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Whether the resource has been deleted.
 */
int
permission_iterator_resource_orphan (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return iterator_int64 (iterator, GET_ITERATOR_COLUMN_COUNT + 4);
}

/**
 * @brief Get the readable status of a resource from a permission iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return 1 if readable, otherwise 0.
 */
int
permission_iterator_resource_readable (iterator_t* iterator)
{
  resource_t found;
  const char *type, *uuid;
  gchar *permission;

  if (iterator->done) return 0;

  type = permission_iterator_resource_type (iterator);
  uuid = permission_iterator_resource_uuid (iterator);

  if (type == NULL || uuid == NULL)
    return 0;

  if (type_is_info_subtype (type))
    permission = g_strdup ("get_info");
  else if (type_is_asset_subtype (type))
    permission = g_strdup ("get_assets");
  else
    permission = g_strdup_printf ("get_%ss", type);

  found = 0;
  find_resource_with_permission (type,
                                 uuid,
                                 &found,
                                 permission,
                                 permission_iterator_resource_in_trash
                                  (iterator));
  g_free (permission);
  return found > 0;
}

/**
 * @brief Get the type of subject from a permission iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Type, or NULL if iteration is complete.
 */
DEF_ACCESS (permission_iterator_subject_type, GET_ITERATOR_COLUMN_COUNT + 5);

/**
 * @brief Get the subject UUID from a permission iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return UUID, or NULL if iteration is complete.
 */
DEF_ACCESS (permission_iterator_subject_uuid, GET_ITERATOR_COLUMN_COUNT + 6);

/**
 * @brief Get the subject name from a permission iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name, or NULL if iteration is complete.
 */
DEF_ACCESS (permission_iterator_subject_name, GET_ITERATOR_COLUMN_COUNT + 7);

/**
 * @brief Return the permission subject location.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Whether the subject is in the trashcan
 */
int
permission_iterator_subject_in_trash (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return iterator_int64 (iterator, GET_ITERATOR_COLUMN_COUNT + 8);
}

/**
 * @brief Get the readable status of a subject from a permission iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return 1 if readable, otherwise 0.
 */
int
permission_iterator_subject_readable (iterator_t* iterator)
{
  resource_t found;
  const char *type, *uuid;
  gchar *permission;

  if (iterator->done) return 0;

  type = permission_iterator_subject_type (iterator);
  uuid = permission_iterator_subject_uuid (iterator);

  if (type == NULL || uuid == NULL)
    return 0;

  if ((strcmp (type, "user") == 0)
      || (strcmp (type, "role") == 0)
      || (strcmp (type, "group") == 0))
    permission = g_strdup_printf ("get_%ss", type);
  else
    return 0;

  found = 0;
  find_resource_with_permission (type,
                                 uuid,
                                 &found,
                                 permission,
                                 permission_iterator_subject_in_trash
                                  (iterator));
  g_free (permission);
  return found > 0;
}

/**
 * @brief Create a SQL clause to select the subject users.
 *
 * @param[in]  subject_type  Subject type.
 * @param[in]  subject       The subject.
 *
 * @return Newly allocated string containing the SQL clause.
 */
gchar *
subject_where_clause (const char* subject_type, resource_t subject)
{
  gchar *subject_where = NULL;
  if (subject && subject_type)
    {
      if (strcmp (subject_type, "user") == 0)
        {
          subject_where
            = g_strdup_printf ("id = %llu", subject);
        }
      else if (strcmp (subject_type, "group") == 0)
        {
          subject_where
            = g_strdup_printf ("id IN (SELECT \"user\" FROM group_users"
                               "        WHERE \"group\" = %llu)",
                               subject);
        }
      else if (strcmp (subject_type, "role") == 0)
        {
          subject_where
            = g_strdup_printf ("id IN (SELECT \"user\" FROM role_users"
                               "        WHERE \"role\" = %llu)",
                               subject);
        }
      else
        {
          subject_where = strdup ("t()");
          g_warning ("%s: unknown subject_type %s",
                     __func__, subject_type);
        }
    }
  return subject_where;
}

/**
 * @brief Find a permission given a UUID.
 *
 * @param[in]   uuid        UUID of permission.
 * @param[out]  permission  Permission return, 0 if successfully failed to find
 *                          permission.
 *
 * @return FALSE on success (including if failed to find permission), TRUE on
 *         error.
 */
gboolean
find_permission (const char* uuid, permission_t* permission)
{
  return find_resource ("permission", uuid, permission);
}

/**
 * @brief Check args for create_permission or modify_permission.
 *
 * @param[in]   check_access    Whether to check if user may get resource and
 *                              subject.
 * @param[in]   name_arg        Name of permission.
 * @param[in]   resource_type_arg  Type of resource, for special permissions.
 * @param[in]   resource_id_arg    UUID of resource.
 * @param[in]   subject_type    Type of subject.
 * @param[in]   subject_id      UUID of subject.
 * @param[out]  name            Name return.
 * @param[out]  resource        Resource return.
 * @param[out]  resource_type   Resource type return.
 * @param[out]  resource_id     Resource ID return.
 * @param[out]  subject         Subject return.
 *
 * @return 0 success, 2 failed to find subject, 3 failed to find resource,
 *         5 error in resource, 6 error in subject, 7 error in name,
 *         8 permission on permission, 9 permission does not accept resource,
 *         99 permission denied, -1 error.
 */
int
check_permission_args (gboolean check_access, const char *name_arg,
                       const char *resource_type_arg,
                       const char *resource_id_arg, const char *subject_type,
                       const char *subject_id, gchar **name,
                       resource_t *resource, char **resource_type,
                       const char **resource_id, resource_t *subject)
{
  if ((name_arg == NULL)
      || ((valid_gmp_command (name_arg) == 0)
          && strcasecmp (name_arg, "super"))
      || (strcasecmp (name_arg, "get_version") == 0))
    return 7;

  if (resource_id_arg
      && strcmp (resource_id_arg, "")
      && strcmp (resource_id_arg, "0")
      && (((gmp_command_takes_resource (name_arg) == 0)
           && strcasecmp (name_arg, "super"))))
    return 9;

  if (resource_type_arg
      && strcasecmp (name_arg, "super") == 0
      && strcmp (resource_type_arg, "group")
      && strcmp (resource_type_arg, "role")
      && strcmp (resource_type_arg, "user"))
    return 5;

  if (resource_type_arg
      && strcasecmp (name_arg, "super")
      && (valid_db_resource_type (resource_type_arg) == 0
          || gmp_command_takes_resource (name_arg) == 0))
    return 5;

  if (subject_type
      && strcmp (subject_type, "group")
      && strcmp (subject_type, "role")
      && strcmp (subject_type, "user"))
    return 6;

  if (subject_id == NULL)
    /* For now a permission must have a subject. */
    return 6;

  if (subject_id && (subject_type == NULL))
    return 6;

  assert (subject_type);

  *name = strcasecmp (name_arg, "super")
           ? g_ascii_strdown (name_arg, -1)
           : g_strdup ("Super");
  *resource = 0;
  if (resource_id_arg
      && strcmp (resource_id_arg, "")
      && strcmp (resource_id_arg, "0"))
    {
      *resource_type = strcasecmp (*name, "super")
                        ? gmp_command_type (*name)
                        : g_strdup (resource_type_arg);

      if (*resource_type == NULL)
        {
          g_free (*name);
          return 3;
        }

      if (strcasecmp (*resource_type, "asset") == 0)
        {
          g_free (*resource_type);
          *resource_type = g_strdup ("host");
          if (check_access == FALSE)
            {
              if (find_resource_no_acl (*resource_type, resource_id_arg, resource))
                {
                  g_free (*name);
                  g_free (*resource_type);
                  return -1;
                }
            }
          else
            {
              if (find_resource (*resource_type, resource_id_arg, resource))
                {
                  g_free (*name);
                  g_free (*resource_type);
                  return -1;
                }
            }

          if (*resource == 0)
            {
              g_free (*resource_type);
              *resource_type = g_strdup ("os");
              if (check_access == FALSE)
                {
                  if (find_resource_no_acl (*resource_type, resource_id_arg, resource))
                    {
                      g_free (*name);
                      g_free (*resource_type);
                      return -1;
                    }
                }
              else
                {
                  if (find_resource (*resource_type, resource_id_arg, resource))
                    {
                      g_free (*name);
                      g_free (*resource_type);
                      return -1;
                    }
                }
            }
        }
      else if (check_access == FALSE)
        {
          if (find_resource_no_acl (*resource_type, resource_id_arg, resource))
            {
              g_free (*name);
              g_free (*resource_type);
              return -1;
            }
        }
      else
        {
          gchar *get_permission;
          get_permission = g_strdup_printf ("get_%ss", *resource_type);
          if (find_resource_with_permission (*resource_type, resource_id_arg,
                                             resource, get_permission, 0))
            {
              g_free (*name);
              g_free (*resource_type);
              g_free (get_permission);
              return -1;
            }
          g_free (get_permission);
        }

      if (*resource == 0)
        {
          g_free (*name);
          g_free (*resource_type);
          return 3;
        }

      *resource_id = resource_id_arg;
    }
  else
    {
      *resource_id = NULL;
      *resource_type = NULL;
    }

  if (strcasecmp (*name, "super") == 0)
    {
      if (*resource == 0)
        {
          g_free (*name);
          g_free (*resource_type);
          return 3;
        }

      if ((acl_user_is_owner (*resource_type, *resource_id) == 0)
          && (acl_user_can_super_everyone (current_credentials.uuid) == 0))
        {
          g_free (*name);
          g_free (*resource_type);
          return 99;
        }
    }

  /* For simplicity refuse to make permissions on permissions. */
  if (*resource && strcasestr (*name, "permission"))
    {
      g_free (*name);
      g_free (*resource_type);
      return 8;
    }

  /* Ensure the user may grant this permission. */

  if (((*resource == 0) || strcasecmp (*name, "super") == 0)
      && (acl_user_can_everything (current_credentials.uuid) == 0))
    {
      g_free (*name);
      g_free (*resource_type);
      return 99;
    }

  *subject = 0;
  assert (subject_id);
  if (*resource)
    {
      /* Permission on a particular resource.  Only need read access to the
       * subject. */
      if (check_access)
        {
          if (find_resource_with_permission (subject_type,
                                             subject_id,
                                             subject,
                                             NULL, /* GET permission. */
                                             0))   /* Trash. */
            {
              g_free (*name);
              g_free (*resource_type);
              return -1;
            }
        }
       else
        {
          if (find_resource_no_acl (subject_type, subject_id, subject))
            {
              g_free (*name);
              g_free (*resource_type);
              return -1;
            }
        }
    }
  else
    {
      gchar *permission;

      /* Command level permission.  Must have write access to the subject. */

      /* However, modification of the predefined roles is forbidden. */
      if (subject_id
          && strcmp (subject_type, "role") == 0
          && role_is_predefined_id (subject_id))
        return 99;

      permission = g_strdup_printf ("modify_%s", subject_type);
      if (find_resource_with_permission (subject_type,
                                         subject_id,
                                         subject,
                                         permission,
                                         0)) /* Trash. */
        {
          g_free (*name);
          g_free (*resource_type);
          g_free (permission);
          return -1;
        }
      g_free (permission);
    }

  if (*subject == 0)
    {
      g_free (*name);
      g_free (*resource_type);
      return 2;
    }

  return 0;
}

/**
 * @brief Create a permission.
 *
 * Caller must organise the transaction.
 *
 * @param[in]   check_access    Whether to check if user may CREATE_PERMISSION.
 * @param[in]   name_arg        Name of permission.
 * @param[in]   comment         Comment on permission.
 * @param[in]   resource_type_arg  Type of resource, for special permissions.
 * @param[in]   resource_id_arg    UUID of resource.
 * @param[in]   subject_type    Type of subject.
 * @param[in]   subject_id      UUID of subject.
 * @param[out]  permission      Permission.
 *
 * @return 0 success, 2 failed to find subject, 3 failed to find resource,
 *         5 error in resource, 6 error in subject, 7 error in name,
 *         8 permission on permission, 9 permission does not accept resource,
 *         99 permission denied, -1 internal error.
 */
int
create_permission_internal (int check_access, const char *name_arg,
                            const char *comment, const char *resource_type_arg,
                            const char *resource_id_arg,
                            const char *subject_type, const char *subject_id,
                            permission_t *permission)
{
  int ret;
  gchar *name, *quoted_name, *quoted_comment, *resource_type;
  resource_t resource, subject;
  const char *resource_id;
  GHashTable *reports = NULL;
  int clear_original = 0;
  gchar *subject_where;

  assert (current_credentials.uuid);

  if (check_access && (acl_user_may ("create_permission") == 0))
    return 99;

  ret = check_permission_args (check_access, name_arg, resource_type_arg,
                               resource_id_arg, subject_type, subject_id, &name,
                               &resource, &resource_type, &resource_id,
                               &subject);

  if (ret)
    return ret;

  assert (subject);
  assert ((resource_id == resource_id_arg) || (resource_id == NULL));

  quoted_name = sql_quote (name);
  g_free (name);
  quoted_comment = sql_quote (comment ? comment : "");

  sql ("INSERT INTO permissions"
       " (uuid, owner, name, comment, resource_type, resource_uuid, resource,"
       "  resource_location, subject_type, subject, subject_location,"
       "  creation_time, modification_time)"
       " VALUES"
       " (make_uuid (),"
       "  (SELECT id FROM users WHERE users.uuid = '%s'),"
       "  '%s', '%s', '%s', '%s', %llu, " G_STRINGIFY (LOCATION_TABLE) ","
       "  %s%s%s, %llu, " G_STRINGIFY (LOCATION_TABLE) ", m_now (), m_now ());",
       current_credentials.uuid,
       quoted_name,
       quoted_comment,
       resource_id ? resource_type : "",
       resource_id ? resource_id : "",
       resource,
       subject_id ? "'" : "",
       subject_id ? subject_type : "NULL",
       subject_id ? "'" : "",
       subject);

  subject_where = subject_where_clause (subject_type, subject);

  if (permission)
    *permission = sql_last_insert_id ();

  /* Update Permissions cache */
  if (strcasecmp (quoted_name, "super") == 0)
    cache_all_permissions_for_users (NULL);
  else if (resource_type && resource)
    cache_permissions_for_resource (resource_type, resource, NULL);

  /* Update Reports cache */
  if (resource_type && resource_id && strcmp (resource_type, "override") == 0)
    {
      reports = reports_for_override (resource);
    }
  else if (strcasecmp (quoted_name, "super") == 0)
    {
      reports = reports_hashtable ();
      clear_original = 1;
    }

  if (reports && g_hash_table_size (reports))
    {
      GHashTableIter reports_iter;
      report_t *reports_ptr;
      int auto_cache_rebuild;

      reports_ptr = NULL;
      g_hash_table_iter_init (&reports_iter, reports);
      auto_cache_rebuild = setting_auto_cache_rebuild_int ();
      while (g_hash_table_iter_next (&reports_iter,
                                    ((gpointer*)&reports_ptr), NULL))
        {
          if (auto_cache_rebuild)
            report_cache_counts (*reports_ptr, clear_original, 1,
                                 subject_where);
          else
            report_clear_count_cache (*reports_ptr, clear_original, 1,
                                      subject_where);
        }
    }

  if (reports)
    g_hash_table_destroy (reports);

  g_free (quoted_comment);
  g_free (quoted_name);
  g_free (resource_type);
  g_free (subject_where);

  return 0;
}

/**
 * @brief Create a permission.
 *
 * @param[in]   name_arg        Name of permission.
 * @param[in]   comment         Comment on permission.
 * @param[in]   resource_type_arg  Type of resource, for special permissions.
 * @param[in]   resource_id_arg    UUID of resource.
 * @param[in]   subject_type    Type of subject.
 * @param[in]   subject_id      UUID of subject.
 * @param[out]  permission      Permission.
 *
 * @return 0 success, 2 failed to find subject, 3 failed to find resource,
 *         5 error in resource, 6 error in subject, 7 error in name,
 *         8 permission on permission, 9 permission does not accept resource,
 *         99 permission denied, -1 internal error.
 */
int
create_permission (const char *name_arg, const char *comment,
                   const char *resource_type_arg, const char *resource_id_arg,
                   const char *subject_type, const char *subject_id,
                   permission_t *permission)
{
  int ret;

  sql_begin_immediate ();

  ret = create_permission_internal (1, name_arg, comment, resource_type_arg,
                                    resource_id_arg, subject_type, subject_id,
                                    permission);
  if (ret)
    sql_rollback ();
  else
    sql_commit ();

  return ret;
}

/**
 * @brief Create a permission.
 *
 * Does not require current user to have CREATE_PERMISSION access.
 *
 * @param[in]   name_arg        Name of permission.
 * @param[in]   comment         Comment on permission.
 * @param[in]   resource_type_arg  Type of resource, for special permissions.
 * @param[in]   resource_id_arg    UUID of resource.
 * @param[in]   subject_type    Type of subject.
 * @param[in]   subject_id      UUID of subject.
 * @param[out]  permission      Permission.
 *
 * @return 0 success, 2 failed to find subject, 3 failed to find resource,
 *         5 error in resource, 6 error in subject, 7 error in name,
 *         8 permission on permission, 9 permission does not accept resource,
 *         99 permission denied, -1 internal error.
 */
int
create_permission_no_acl (const char *name_arg, const char *comment,
                          const char *resource_type_arg,
                          const char *resource_id_arg,
                          const char *subject_type, const char *subject_id,
                          permission_t *permission)
{
  return create_permission_internal (0, name_arg, comment, resource_type_arg,
                                     resource_id_arg, subject_type, subject_id,
                                     permission);
}

/**
 * @brief Create a permission from an existing permission.
 *
 * @param[in]  comment     Comment on new permission.  NULL to copy from existing.
 * @param[in]  permission_id   UUID of existing permission.
 * @param[out] new_permission  New permission.
 *
 * @return 0 success, 1 permission exists already, 2 failed to find existing
 *         permission, 99 permission denied, -1 error.
 */
int
copy_permission (const char* comment, const char *permission_id,
                 permission_t* new_permission)
{
  int ret;
  permission_t permission, new, old;
  char *subject_type, *name;
  resource_t subject;

  sql_begin_immediate ();

  permission = 0;
  /* There are no permissions on permissions, so no need for the
   * "_with_permission" version. */
  if (find_permission (permission_id, &permission))
    {
      sql_rollback ();
      return -1;
    }

  if (permission == 0)
    {
      sql_rollback ();
      return 2;
    }

  /* Prevent copying of command level permissions for predefined roles. */
  subject_type = permission_subject_type (permission);
  subject = permission_subject (permission);
  if (permission_resource (permission) == 0
      && subject_type
      && strcmp (subject_type, "role") == 0
      && subject
      && role_is_predefined (subject))
    {
      free (subject_type);
      sql_rollback ();
      return 99;
    }
  free (subject_type);

  /* Refuse to copy Super On Everyone. */
  name = permission_name (permission);
  if ((strcmp (name, "Super") == 0)
      && (permission_resource (permission) == 0))
    {
      free (name);
      sql_rollback ();
      return 99;
    }
  free (name);

  ret = copy_resource_lock ("permission", NULL, comment, permission_id,
                            "resource_type, resource, resource_uuid,"
                            " resource_location, subject_type, subject,"
                            " subject_location",
                            0, &new, &old);
  if (ret)
    {
      sql_rollback ();
      return ret;
    }

  sql_commit ();
  if (new_permission) *new_permission = new;
  return 0;

}
