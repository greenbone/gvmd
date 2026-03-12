/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_tags.h"
#include "manage_acl.h"
#include "manage_sql.h"
#include "manage_sql_filters.h"
#include "manage_sql_permissions.h"
#include "manage_sql_resources.h"
#include "manage_sql_tickets.h"
#include "sql.h"

/**
 * @file
 * @brief GVM management layer: Tags SQL
 *
 * The Tags SQL for the GVM management layer.
 */

/**
 * @brief Return the UUID of a tag.
 *
 * @param[in]  tag  Tag.
 *
 * @return Newly allocated UUID if available, else NULL.
 */
char*
tag_uuid (tag_t tag)
{
  return sql_string ("SELECT uuid FROM tags WHERE id = %llu;",
                     tag);
}

/**
 * @brief Remove a resource from tags.
 *
 * @param[in]  type      Type.
 * @param[in]  resource  Resource.
 * @param[in]  location  Location: table or trash.
 */
void
tags_remove_resource (const char *type, resource_t resource, int location)
{
  sql ("DELETE FROM tag_resources"
       " WHERE resource_type = '%s' AND resource = %llu"
       " AND resource_location = %i;",
       type,
       resource,
       location);
}

/**
 * @brief Adjust location of resource in tags.
 *
 * @param[in]   type  Type.
 * @param[in]   old   Resource ID in old table.
 * @param[in]   new   Resource ID in new table.
 * @param[in]   to    Destination, trash or table.
 */
void
tags_set_locations (const char *type, resource_t old, resource_t new,
                    int to)
{
  sql ("UPDATE tag_resources SET resource_location = %i, resource = %llu"
       " WHERE resource_type = '%s' AND resource = %llu"
       " AND resource_location = %i;",
       to,
       new,
       type,
       old,
       to == LOCATION_TABLE ? LOCATION_TRASH : LOCATION_TABLE);
  sql ("UPDATE tag_resources_trash SET resource_location = %i, resource = %llu"
       " WHERE resource_type = '%s' AND resource = %llu"
       " AND resource_location = %i;",
       to,
       new,
       type,
       old,
       to == LOCATION_TABLE ? LOCATION_TRASH : LOCATION_TABLE);
}

/**
 * @brief Find a tag for a specific permission, given a UUID.
 *
 * @param[in]   uuid        UUID of tag.
 * @param[out]  tag         Tag return, 0 if successfully failed to find tag.
 * @param[in]   permission  Permission.
 *
 * @return FALSE on success (including if failed to find tag), TRUE on error.
 */
static gboolean
find_tag_with_permission (const char* uuid, tag_t* tag,
                          const char *permission)
{
  return find_resource_with_permission ("tag", uuid, tag, permission, 0);
}

/**
 * @brief Create a tag from an existing tag.
 *
 * @param[in]  name        Name of new tag.  NULL to copy from existing.
 * @param[in]  comment     Comment on new tag.  NULL to copy from existing.
 * @param[in]  tag_id      UUID of existing tag.
 * @param[out] new_tag_return  New tag.
 *
 * @return 0 success, 2 failed to find existing tag,
 *         99 permission denied, -1 error.
 */
int
copy_tag (const char* name, const char* comment, const char *tag_id,
          tag_t* new_tag_return)
{
  int ret = 0;
  tag_t new_tag, old_tag;

  ret = copy_resource ("tag", name, comment, tag_id,
                       "value, resource_type, active",
                       1, &new_tag, &old_tag);

  if (ret)
    return ret;

  if (new_tag_return)
    *new_tag_return = new_tag;

  sql ("INSERT INTO tag_resources"
       " (tag, resource_type, resource, resource_uuid, resource_location)"
       " SELECT"
       "  %llu, resource_type, resource, resource_uuid, resource_location"
       "   FROM tag_resources"
       "  WHERE tag = %llu",
       new_tag, old_tag);

  return 0;
}

/**
 * @brief Delete a tag.
 *
 * @param[in]  tag_id     UUID of tag.
 * @param[in]  ultimate   Whether to remove entirely, or to trashcan.
 *
 * @return 0 success, 2 failed to find tag, 99 permission denied, -1 error.
 */
int
delete_tag (const char *tag_id, int ultimate)
{
  tag_t tag = 0;

  sql_begin_immediate ();

  if (acl_user_may ("delete_tag") == 0)
    {
      sql_rollback ();
      return 99;
    }

  if (find_tag_with_permission (tag_id, &tag, "delete_tag"))
    {
      sql_rollback ();
      return -1;
    }

  if (tag == 0)
    {
      if (find_trash ("tag", tag_id, &tag))
        {
          sql_rollback ();
          return -1;
        }
      if (tag == 0)
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

      permissions_set_orphans ("tag", tag, LOCATION_TRASH);

      sql ("DELETE FROM tag_resources_trash WHERE tag = %llu", tag);
      sql ("DELETE FROM tags_trash WHERE id = %llu;", tag);
      sql_commit ();
      return 0;
    }

  if (ultimate == 0)
    {
      tag_t trash_tag;

      sql ("INSERT INTO tags_trash"
           " (uuid, owner, name, comment, creation_time,"
           "  modification_time, resource_type, active, value)"
           " SELECT uuid, owner, name, comment, creation_time,"
           "        modification_time, resource_type, active, value"
           " FROM tags WHERE id = %llu;",
           tag);

      trash_tag = sql_last_insert_id ();

      sql ("INSERT INTO tag_resources_trash"
           "  (tag, resource_type, resource, resource_uuid, resource_location)"
           " SELECT"
           "   %llu, resource_type, resource, resource_uuid, resource_location"
           " FROM tag_resources WHERE tag = %llu;",
           trash_tag, tag);

      permissions_set_locations ("tag", tag, trash_tag, LOCATION_TRASH);
    }
  else
    {
      permissions_set_orphans ("tag", tag, LOCATION_TABLE);
      tags_remove_resource ("tag", tag, LOCATION_TABLE);
    }

  sql ("DELETE FROM tag_resources WHERE tag = %llu", tag);
  sql ("DELETE FROM tags WHERE id = %llu;", tag);
  sql_commit ();

  return 0;
}

/**
 * @brief Add a resource to a tag.
 *
 * @param[in]  tag         Tag to attach to the resource.
 * @param[in]  type        The resource Type.
 * @param[in]  uuid        The resource UUID.
 * @param[in]  resource    The resource row id.
 * @param[in]  location    Whether the resource is in the trashcan.
 *
 * @return  0 success, -1 error
 */
static int
tag_add_resource (tag_t tag, const char *type, const char *uuid,
                  resource_t resource, int location)
{
  int already_added, ret;
  gchar *quoted_resource_uuid;

  ret = 0;

  quoted_resource_uuid = uuid ? sql_insert (uuid) : g_strdup ("''");

  if (type_is_info_subtype (type))
    already_added = sql_int ("SELECT count(*) FROM tag_resources"
                             " WHERE resource_type = '%s'"
                             " AND resource_uuid = %s"
                             " AND tag = %llu",
                             type, quoted_resource_uuid, tag);
  else
    already_added = sql_int ("SELECT count(*) FROM tag_resources"
                             " WHERE resource_type = '%s'"
                             " AND resource = %llu"
                             " AND resource_location = %d"
                             " AND tag = %llu",
                             type, resource, location, tag);

  if (already_added == 0)
    {
      g_debug ("%s - adding %s %s", __func__, type, uuid);
      sql ("INSERT INTO tag_resources"
           " (tag, resource_type, resource, resource_uuid, resource_location)"
           " VALUES (%llu, '%s', %llu, %s, %d)",
           tag, type, resource, quoted_resource_uuid, location);
    }
  else
    {
      g_debug ("%s - skipping %s %s", __func__, type, uuid);
    }

  g_free (quoted_resource_uuid);

  return ret;
}

/**
 * @brief Find a resource by UUID and add it as a tag resource.
 *
 * @param[in]  tag         Tag to attach to the resource.
 * @param[in]  type        The resource type.
 * @param[in]  tag_type    The tag type. Could be a sub-type.
 * @param[in]  uuid        The resource UUID.
 * @param[in]  permission  The permission required to get the resource.
 *
 * @return 0 success, -1 error, 1 resource not found.
 */
static int
tag_add_resource_uuid (tag_t tag,
                       const char *type,
                       const char *tag_type,
                       const char *uuid,
                       const char *permission)
{
  int resource_location = LOCATION_TABLE;
  resource_t resource;

  if (find_resource_with_permission (type, uuid,
                                     &resource, permission, 0))
    {
      g_warning ("%s: Failed to find %s %s",
                 __func__, type, uuid);
      return -1;
    }
  else if (resource == 0
           && type_has_trash (type))
    {
      if (find_resource_with_permission (type, uuid,
                                         &resource, permission,
                                         1))
        {
          g_warning ("%s: Failed to find trash %s %s",
                     __func__, type, uuid);
          return -1;
        }
      else if (resource != 0)
        resource_location = LOCATION_TRASH;
    }

  if (resource == 0)
    return 1;

  if ((strcmp (type, "task") == 0)
      || (strcmp (type, "config") == 0)
      || (strcmp (type, "report") == 0))
    {
      gchar *usage_type;
      if (strcmp (type, "report"))
        usage_type = sql_string ("SELECT usage_type FROM %ss WHERE id = %llu",
                                 type, resource);
      else
        {
          task_t task;
          if (report_task (resource, &task))
            return -1;

          usage_type = sql_string ("SELECT usage_type FROM tasks WHERE id = %llu",
                                   task);
        }

      if (usage_type == NULL)
        return -1;

      int same_type = (strcmp (tag_type, type) == 0);

      if (same_type && ((strcmp (usage_type, "audit") == 0)
                        || (strcmp (usage_type, "policy") == 0)))
        {
          g_free (usage_type);
          return 1;
        }
      if (!same_type && (strcmp (usage_type, "scan") == 0))
        {
          g_free (usage_type);
          return 1;
        }
      g_free (usage_type);
    }

  return tag_add_resource (tag, type, uuid, resource, resource_location);
}

/**
 * @brief Find resources from an array by UUID and insert as a tag resource.
 *
 * @param[in]  tag         Tag to attach to the resource.
 * @param[in]  type        The resource type.
 * @param[in]  uuids       The array of resource UUIDs.
 * @param[out] error_extra Extra error output. Contains UUID if not found.
 *
 * @return 0 success, -1 error, 1 resource not found.
 */
static int
tag_add_resources_list (tag_t tag, const char *type, array_t *uuids,
                        gchar **error_extra)
{
  gchar *resource_permission, *current_uuid;
  int index;

  gchar *resource_type = g_strdup (type);

  if (type_is_info_subtype (type))
    resource_permission = g_strdup ("get_info");
  else if (type_is_asset_subtype (type))
    resource_permission = g_strdup ("get_assets");
  else if (type_is_report_subtype (type))
    {
      resource_permission = g_strdup ("get_reports");
      g_free (resource_type);
      resource_type = g_strdup ("report");
    }
  else if (type_is_task_subtype (type))
    {
      resource_permission = g_strdup ("get_tasks");
      g_free (resource_type);
      resource_type = g_strdup ("task");
    }
  else if (type_is_config_subtype (type))
    {
      resource_permission = g_strdup ("get_configs");
      g_free (resource_type);
      resource_type = g_strdup ("config");
    }
  else
    resource_permission = g_strdup_printf ("get_%ss", type);

  index = 0;
  while ((current_uuid = g_ptr_array_index (uuids, index++)))
    {
      int ret;

      ret = tag_add_resource_uuid (tag, resource_type, type, current_uuid,
                                   resource_permission);
      if (ret)
        {
          g_free (resource_permission);
          g_free (resource_type);
          if (error_extra)
            *error_extra = g_strdup (current_uuid);
          return ret;
        }
    }
  g_free (resource_permission);
  g_free (resource_type);

  return 0;
}

/**
 * @brief Find resources using a filter and insert as tag resources.
 *
 * @param[in]  tag         Tag to attach to the resource.
 * @param[in]  type        The resource type.
 * @param[in]  filter      The filter to select resources with.
 *
 * @return 0 success, -1 error, 1 resource not found, 2 no resources returned.
 */
static int
tag_add_resources_filter (tag_t tag, const char *type, const char *filter)
{
  iterator_t resources;
  gchar *filtered_select;
  get_data_t resources_get;
  int ret;

  memset (&resources_get, '\0', sizeof (resources_get));
  resources_get.filter = g_strdup (filter);
  resources_get.filt_id = FILT_ID_NONE;
  resources_get.trash = LOCATION_TABLE;
  resources_get.type = g_strdup (type);
  resources_get.ignore_max_rows_per_page = 1;
  filtered_select = NULL;

  if (strcasecmp (type, "TICKET") == 0)
    {
      /* TODO This is how it should be done for all types, in order
       * to contain each per-resource implementation in its own file. */
      if (init_ticket_iterator (&resources, &resources_get))
        {
          g_warning ("%s: Failed to build filter SELECT", __func__);
          sql_rollback ();
          g_free (resources_get.filter);
          g_free (resources_get.type);
          return -1;
        }
    }
  else
    {
      if (strcasecmp (type, "task") == 0)
        {
          get_data_set_extra (&resources_get, "usage_type", g_strdup ("scan"));
        }
      else if (strcasecmp (type, "audit") == 0)
        {
          type = g_strdup ("task");
          resources_get.type = g_strdup (type);
          get_data_set_extra (&resources_get, "usage_type", g_strdup ("audit"));
        }
      else if (strcasecmp (type, "policy") == 0)
        {
          type = g_strdup ("config");
          resources_get.type = g_strdup (type);
          get_data_set_extra (&resources_get, "usage_type", g_strdup ("policy"));
        }
      else if (strcasecmp (type, "config") == 0)
        {
          get_data_set_extra (&resources_get, "usage_type", g_strdup ("scan"));
        }
      else if (strcasecmp (type, "audit_report") == 0)
        {
          type = g_strdup ("report");
          resources_get.type = g_strdup (type);
          get_data_set_extra (&resources_get, "usage_type", g_strdup ("audit"));
        }
      else if (strcasecmp (type, "report") == 0)
        {
          get_data_set_extra (&resources_get, "usage_type", g_strdup ("scan"));
        }

      gchar *columns;

      columns = g_strdup_printf ("%ss.id, %ss.uuid", type, type);
      switch (type_build_select (type,
                                 columns,
                                 &resources_get, 0, 1, NULL, NULL, NULL,
                                 &filtered_select))
        {
          case 0:
            g_free (columns);
            if (sql_int ("SELECT count(*) FROM (%s) AS filter_selection",
                         filtered_select) == 0)
              {
                g_free (filtered_select);
                return 2;
              }

            init_iterator (&resources,
                           "%s",
                           filtered_select);

            break;
          default:
            g_free (columns);
            g_warning ("%s: Failed to build filter SELECT", __func__);
            sql_rollback ();
            g_free (resources_get.filter);
            g_free (resources_get.type);
            if (resources_get.extra_params)
              g_hash_table_destroy (resources_get.extra_params);
            return -1;
        }
    }

  g_free (resources_get.filter);
  g_free (resources_get.type);
  if (resources_get.extra_params)
    g_hash_table_destroy (resources_get.extra_params);

  ret = 2;
  while (next (&resources))
    {
      resource_t resource;
      const char *current_uuid;
      int add_ret;

      resource = iterator_int64 (&resources, 0);
      current_uuid = iterator_string (&resources, 1);

      add_ret = tag_add_resource (tag, type, current_uuid, resource,
                                  LOCATION_TABLE);
      if (add_ret)
        {
          ret = add_ret;
          break;
        }
      ret = 0;
    }
  cleanup_iterator (&resources);

  g_free (filtered_select);

  return ret;
}

/**
 * @brief Remove resources from a tag using a UUIDs array.
 *
 * @param[in]  tag         Tag to attach to the resource.
 * @param[in]  type        The resource type.
 * @param[in]  uuids       The array of resource UUIDs.
 * @param[out] error_extra Extra error output. Contains UUID if not found.
 *
 * @return 0 success, -1 error, 1 resource not found.
 */
static int
tag_remove_resources_list (tag_t tag, const char *type, array_t *uuids,
                           gchar **error_extra)
{
  gchar *current_uuid;
  int index;

  index = 0;
  while ((current_uuid = g_ptr_array_index (uuids, index++)))
    {
      gchar *uuid_escaped = g_markup_escape_text (current_uuid, -1);

      if (sql_int ("SELECT count(*) FROM tag_resources"
                   " WHERE tag = %llu AND resource_uuid = '%s'",
                   tag, uuid_escaped) == 0)
        {
          if (error_extra)
            *error_extra = g_strdup (current_uuid);
          g_free (uuid_escaped);
          return 1;
        }

      sql ("DELETE FROM tag_resources"
           " WHERE tag = %llu AND resource_uuid = '%s'",
           tag, uuid_escaped);
      g_free (uuid_escaped);
    }

  return 0;
}

/**
 * @brief Remove resources from a tag using a filter.
 *
 * @param[in]  tag         Tag to attach to the resource.
 * @param[in]  type        The resource type.
 * @param[in]  filter      The filter to select resources with.
 *
 * @return 0 success, -1 error, 1 resource not found, 2 no resources returned.
 */
static int
tag_remove_resources_filter (tag_t tag, const char *type, const char *filter)
{
  iterator_t resources;
  gchar *iterator_select;
  get_data_t resources_get;
  int ret;

  memset (&resources_get, '\0', sizeof (resources_get));
  resources_get.filter = g_strdup (filter);
  resources_get.filt_id = FILT_ID_NONE;
  resources_get.trash = LOCATION_TABLE;
  resources_get.type = g_strdup (type);
  resources_get.ignore_max_rows_per_page = 1;

  iterator_select = NULL;

  if (strcasecmp (type, "TICKET") == 0)
    {
      /* TODO This is how it should be done for all types, in order
       * to contain each per-resource implementation in its own file. */
      if (init_ticket_iterator (&resources, &resources_get))
        {
          g_warning ("%s: Failed to init ticket iterator", __func__);
          sql_rollback ();
          g_free (resources_get.filter);
          g_free (resources_get.type);
          return -1;
        }
    }
  else
    {
      if (strcasecmp (type, "task") == 0)
        {
          get_data_set_extra (&resources_get, "usage_type", g_strdup ("scan"));
        }
      else if (strcasecmp (type, "audit") == 0)
        {
          type = g_strdup ("task");
          resources_get.type = g_strdup (type);
          get_data_set_extra (&resources_get, "usage_type", g_strdup ("audit"));
        }
      else if (strcasecmp (type, "policy") == 0)
        {
          type = g_strdup ("config");
          resources_get.type = g_strdup (type);
          get_data_set_extra (&resources_get, "usage_type", g_strdup ("policy"));
        }
      else if (strcasecmp (type, "config") == 0)
        {
          get_data_set_extra (&resources_get, "usage_type", g_strdup ("scan"));
        }
      else if (strcasecmp (type, "audit_report") == 0)
        {
          type = g_strdup ("report");
          resources_get.type = g_strdup (type);
          get_data_set_extra (&resources_get,
                              "usage_type",
                              g_strdup ("audit"));
        }
      else if (strcasecmp (type, "report") == 0)
        {
          get_data_set_extra (&resources_get, "usage_type", g_strdup ("scan"));
        }

      gchar *columns;

      columns = g_strdup_printf ("%ss.id", type);
      switch (type_build_select (type,
                                 columns,
                                 &resources_get, 0, 1, NULL, NULL, NULL,
                                 &iterator_select))
        {
          case 0:
            g_free (columns);
            init_iterator (&resources, "%s", iterator_select);
            break;
          default:
            g_free (columns);
            g_warning ("%s: Failed to build filter SELECT", __func__);
            sql_rollback ();
            g_free (resources_get.filter);
            g_free (resources_get.type);
            if (resources_get.extra_params)
              g_hash_table_destroy (resources_get.extra_params);
            return -1;
        }
    }

  g_free (resources_get.filter);
  g_free (resources_get.type);
  if (resources_get.extra_params)
      g_hash_table_destroy (resources_get.extra_params);

  ret = 2;
  while (next (&resources))
    {
      resource_t resource;

      resource = iterator_int64 (&resources, 0);

      ret = 0;
      sql ("DELETE FROM tag_resources"
           " WHERE tag = %llu"
           " AND resource = %llu"
           " AND resource_location = %d",
           tag, resource, resources_get.trash);
    }
  cleanup_iterator (&resources);

  g_free (iterator_select);

  return ret;
}

/**
 * @brief Create a tag.
 *
 * @param[in]  name          Name of the tag.
 * @param[in]  comment       Comment for the tag.
 * @param[in]  value         Value of the tag.
 * @param[in]  resource_type    Resource type to attach the tag to.
 * @param[in]  resource_uuids   Unique IDs of the resource to attach the tag to.
 * @param[in]  resources_filter Filter to select resources to attach tag to.
 * @param[in]  active        0 for inactive, NULL or any other value for active.
 * @param[out] tag          Created tag.
 * @param[out] error_extra  Extra string for error (e.g. missing resource ID)
 *
 * @return 0 success, 1 resource ID not found (sets error_extra to UUID),
 *   2 filter returned no results, 3 too many resources selected,
 *   99 permission denied, -1 error.
 */
int
create_tag (const char * name, const char * comment, const char * value,
            const char * resource_type, array_t * resource_uuids,
            const char * resources_filter, const char * active, tag_t * tag,
            gchar **error_extra)
{
  gchar *quoted_name, *quoted_comment, *quoted_value;
  gchar *lc_resource_type, *quoted_resource_type;
  tag_t new_tag;

  sql_begin_immediate ();

  if (acl_user_may ("create_tag") == 0)
    {
      sql_rollback ();
      return 99;
    }

  lc_resource_type = g_ascii_strdown (resource_type, -1);
  if (strcmp (lc_resource_type, "")
      && valid_db_resource_type (lc_resource_type) == 0)
    {
      if (!valid_subtype (lc_resource_type))
        {
          g_free (lc_resource_type);
          sql_rollback ();
          return -1;
        }
    }

  quoted_name = sql_insert (name);
  quoted_resource_type = sql_insert (lc_resource_type);

  quoted_comment = sql_insert (comment ? comment : "");
  quoted_value = sql_insert (value ? value : "");
  sql ("INSERT INTO tags"
      " (uuid, owner, creation_time, modification_time, name, comment,"
      "  value, resource_type, active)"
      " VALUES"
      " (make_uuid (), (SELECT id FROM users WHERE users.uuid = '%s'),"
      "  %i, %i, %s, %s, %s, %s, %i);",
      current_credentials.uuid,
      time (NULL),
      time (NULL),
      quoted_name,
      quoted_comment,
      quoted_value,
      quoted_resource_type,
      active
       ? (strcmp (active, "0") == 0
           ? 0
           : 1)
       : 1);

  new_tag = sql_last_insert_id ();

  g_free (quoted_name);
  g_free (quoted_comment);
  g_free (quoted_value);
  g_free (quoted_resource_type);

  /* Handle resource IDs */
  if (resource_uuids)
    {
      int ret;
      ret = tag_add_resources_list (new_tag, lc_resource_type, resource_uuids,
                                    error_extra);

      if (ret)
        {
          // Assume tag_add_resources_list return codes match
          sql_rollback ();
          g_free (lc_resource_type);
          return ret;
        }
    }

  /* Handle filter */
  if (resources_filter && strcmp (resources_filter, ""))
    {
      int ret;
      ret = tag_add_resources_filter (new_tag, lc_resource_type,
                                      resources_filter);

      if (ret)
        {
          // Assume tag_add_resources_list return codes match
          sql_rollback ();
          g_free (lc_resource_type);
          return ret;
        }
    }

  g_free (lc_resource_type);

  if (tag)
    *tag = new_tag;

  sql_commit ();

  return 0;
}

/**
 * @brief Modify a tag.
 *
 * @param[in]  tag_id            UUID of tag.
 * @param[in]  name              New name of the tag or NULL.
 * @param[in]  comment           New comment for the tag or NULL.
 * @param[in]  value             New value of the tag or NULL.
 * @param[in]  resource_type     New resource type to attach the tag to or NULL.
 * @param[in]  resource_uuids    New Unique IDs of the resources to attach.
 * @param[in]  resources_filter  Filter to select resources to attach tag to.
 * @param[in]  resources_action  Resources action, e.g. "add" or "remove".
 * @param[in]  active            0 for inactive, any other for active or NULL.
 * @param[out] error_extra  Extra string for error (e.g. missing resource ID)
 *
 * @return 0 success, 1 failed to find tag, 2 tag_id required,
 *         3 unexpected resource action,
 *         4 resource ID not found (sets error_extra to UUID),
 *         5 filter returned no results, 6 too many resources selected,
 *         99 permission denied, -1 internal error.
 */
int
modify_tag (const char *tag_id, const char *name, const char *comment,
            const char *value, const char *resource_type,
            array_t *resource_uuids, const char *resources_filter,
            const char *resources_action, const char *active,
            gchar **error_extra)
{
  gchar *quoted_name, *quoted_comment, *quoted_value;
  gchar *lc_resource_type, *quoted_resource_type;
  tag_t tag;
  gchar *current_resource_type;

  if (tag_id == NULL)
    return 2;

  sql_begin_immediate ();

  assert (current_credentials.uuid);

  if (acl_user_may ("modify_tag") == 0)
    {
      sql_rollback ();
      return 99;
    }

  tag = 0;
  if (find_tag_with_permission (tag_id, &tag, "modify_tag"))
    {
      sql_rollback ();
      return -1;
    }

  if (tag == 0)
    {
      sql_rollback ();
      return 1;
    }

  lc_resource_type = (resource_type
                      ? g_ascii_strdown (resource_type, -1)
                      : g_strdup (""));
  if (strcmp (lc_resource_type, "")
      && valid_db_resource_type (lc_resource_type) == 0)
    {
      if (!valid_subtype (lc_resource_type))
        {
          sql_rollback ();
          return -1;
        }
    }

  quoted_resource_type = sql_insert (lc_resource_type);
  quoted_name = sql_insert (name ? name : "");
  quoted_comment = sql_insert (comment ? comment : "");
  quoted_value = sql_insert (value ? value : "");

  if (name)
    {
      sql ("UPDATE tags SET"
           " name = %s"
           " WHERE id = %llu;",
           quoted_name,
           tag);
    }

  if (resource_type)
    {
      sql ("UPDATE tags SET"
           " resource_type = %s"
           " WHERE id = %llu;",
           quoted_resource_type,
           tag);
    }

  if (comment)
    {
      sql ("UPDATE tags SET"
           " comment = %s"
           " WHERE id = %llu;",
           quoted_comment,
           tag);
    }

  if (value)
    {
      sql ("UPDATE tags SET"
           " value = %s"
           " WHERE id = %llu;",
           quoted_value,
           tag);
    }

  if (active)
    {
      sql ("UPDATE tags SET"
           " active = %i"
           " WHERE id = %llu;",
           strcmp (active, "0") ? 1 : 0,
           tag);
    }

  sql ("UPDATE tags SET"
       " modification_time = %i"
       " WHERE id = %llu;",
       time (NULL),
       tag);

  g_free (quoted_name);
  g_free (quoted_resource_type);
  g_free (quoted_comment);
  g_free (quoted_value);

  current_resource_type = sql_string ("SELECT resource_type"
                                      " FROM tags"
                                      " WHERE id = %llu",
                                      tag);

  /* Clear old resources */
  if (resources_action == NULL
      || strcmp (resources_action, "") == 0
      || strcmp (resources_action, "set") == 0)
    {
      if (resource_uuids
          || (resources_filter && strcmp (resources_filter, "")))
        {
          sql ("DELETE FROM tag_resources WHERE tag = %llu", tag);
        }
    }
  else if (strcmp (resources_action, "add")
           && strcmp (resources_action, "remove"))
    {
      sql_rollback ();
      g_free (current_resource_type);
      g_free (lc_resource_type);
      return 3;
    }

  /* Handle resource IDs */
  if (resource_uuids)
    {
      int ret;

      if (resources_action && strcmp (resources_action, "remove") == 0)
        ret = tag_remove_resources_list (tag, current_resource_type,
                                         resource_uuids, error_extra);
      else
        ret = tag_add_resources_list (tag, current_resource_type,
                                      resource_uuids, error_extra);

      if (ret)
        {
          sql_rollback ();
          g_free (current_resource_type);
          g_free (lc_resource_type);
          // Assume return codes besides -1 are offset from create_tag
          if (ret > 0)
            return ret + 3;
          else
            return ret;
        }
    }

  /* Handle filter */
  if (resources_filter && strcmp (resources_filter, ""))
    {
      int ret;

      if (resources_action && strcmp (resources_action, "remove") == 0)
        ret = tag_remove_resources_filter (tag, current_resource_type,
                                           resources_filter);
      else
        ret = tag_add_resources_filter (tag, current_resource_type,
                                        resources_filter);

      if (ret)
        {
          // Assume tag_add_resources_list return codes match
          sql_rollback ();
          g_free (current_resource_type);
          g_free (lc_resource_type);
          // Assume return codes besides -1 are offset from create_tag
          if (ret > 0)
            return ret + 3;
          else
            return ret;
        }
    }

  g_free (current_resource_type);
  g_free (lc_resource_type);

  sql_commit ();

  return 0;
}
